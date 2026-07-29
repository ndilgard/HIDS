import { readlinkSync } from "node:fs";
import { upsertScanStatus } from "../state/history-db.ts";
import { readJson, writeJsonAtomic } from "../state/json-store.ts";
import type { Module, ModuleContext } from "./types.ts";

// Linux default ephemeral port range (net.ipv4.ip_local_port_range). This is where WebRTC/QUIC
// and other transient app sockets get assigned from — not configurable-detection here, just the
// common default, documented as an assumption rather than silently hardcoded.
const EPHEMERAL_PORT_MIN = 32768;
const EPHEMERAL_PORT_MAX = 65535;

// A process gets to open this many distinct ephemeral UDP ports (each one alerting normally)
// before the pattern is treated as established repeated churn and further ones are suppressed.
// Deliberately NOT tied to the process module's own known-binary allowlist — that allowlist gets
// populated by an independent 10s poll, so any process (malicious or not) that happens to survive
// one poll before opening its listener would already read as "known," which would make "an
// unrecognized process still alerts" untrustworthy. This counter is self-contained instead: it
// only trusts a process once *this exact behavior* — repeatedly binding new ephemeral UDP ports —
// has actually been observed a few times from it.
const EPHEMERAL_UDP_TRUST_THRESHOLD = 3;

interface Listener {
	proto: string;
	localAddress: string;
	process: string;
}

function extractPort(localAddress: string): number | null {
	const parts = localAddress.split(":");
	const port = Number(parts[parts.length - 1]);
	return Number.isFinite(port) ? port : null;
}

function extractPid(processField: string): number | null {
	const match = processField.match(/pid=(\d+)/);
	return match ? Number(match[1]) : null;
}

function resolveExePath(pid: number): string | null {
	try {
		return readlinkSync(`/proc/${pid}/exe`);
	} catch {
		return null; // process exited between listing and resolving, or not our user
	}
}

function parseListeners(output: string): Listener[] {
	const lines = output.split("\n").slice(1); // drop header
	const listeners: Listener[] = [];
	for (const line of lines) {
		if (!line.trim()) continue;
		const fields = line.trim().split(/\s+/);
		const [proto, , , , localAddress] = fields;
		if (!proto || !localAddress) continue;
		const process = fields.slice(6).join(" ");
		listeners.push({ proto, localAddress, process });
	}
	return listeners;
}

function listenerKey(l: Listener): string {
	return `${l.proto}:${l.localAddress}`;
}

function countEstablished(output: string): number {
	return output.split("\n").filter((l) => l.trim() && !l.startsWith("State"))
		.length;
}

export function createNetworkModule(ctx: ModuleContext): Module {
	const { config, db, recorder } = ctx;
	const baselinePath = `${config.dataDir}/baseline-network.json`;
	let timer: ReturnType<typeof setInterval> | null = null;

	async function scanNow(): Promise<void> {
		const known = new Set(readJson<string[]>(baselinePath, []));
		const isFirstRun = known.size === 0;
		const ephemeralUdpCountsPath = `${config.dataDir}/ephemeral-udp-counts.json`;
		const ephemeralUdpCounts = readJson<Record<string, number>>(
			ephemeralUdpCountsPath,
			{},
		);

		const listenResult = Bun.spawnSync(["ss", "-tulnp"]);
		const listeners = parseListeners(listenResult.stdout.toString());
		let newListeners = 0;

		for (const listener of listeners) {
			const key = listenerKey(listener);
			if (!known.has(key)) {
				known.add(key);
				newListeners++;

				// UDP "listeners" from `ss` include ephemeral bind()-only sockets ordinary apps open
				// constantly (WebRTC/QUIC/DNS on high ports) — those look identical to a genuine new
				// listener by port number alone. Rather than ignore all UDP (which would blind us to
				// a real UDP-based backdoor), only suppress once a SPECIFIC process has demonstrated
				// this exact pattern — repeatedly binding new ephemeral ports — a few times. The
				// first few ephemeral-UDP binds from any process (known or not) still alert; only
				// after EPHEMERAL_UDP_TRUST_THRESHOLD distinct ports from the same exe path do
				// further ones quiet down. This does NOT depend on the process module's own
				// allowlist (which populates from an independent 10s poll and could make an
				// unrecognized process look "known" before its first UDP bind is even evaluated) —
				// the trust here is earned by this behavior specifically, not borrowed from elsewhere.
				let suppressAsEphemeralNoise = false;
				if (listener.proto === "udp" && !config.network.alertOnUdp) {
					const port = extractPort(listener.localAddress);
					const isEphemeralPort =
						port !== null &&
						port >= EPHEMERAL_PORT_MIN &&
						port <= EPHEMERAL_PORT_MAX;
					if (isEphemeralPort) {
						const pid = extractPid(listener.process);
						const exePath = pid !== null ? resolveExePath(pid) : null;
						if (exePath) {
							const priorCount = ephemeralUdpCounts[exePath] ?? 0;
							ephemeralUdpCounts[exePath] = priorCount + 1;
							suppressAsEphemeralNoise =
								priorCount >= EPHEMERAL_UDP_TRUST_THRESHOLD;
						}
						// exePath unresolved (process already exited, or permissions) — can't establish
						// a trust history, so it stays alert-worthy rather than silently passing through.
					}
				}

				if (
					!isFirstRun &&
					config.network.alertOnNewListener &&
					!suppressAsEphemeralNoise
				) {
					recorder.record({
						module: "network",
						severity: "warning",
						summary: `New listening port: ${listener.proto} ${listener.localAddress} (${listener.process || "unknown process"})`,
						detail: listener,
					});
				}
			}
		}

		writeJsonAtomic(baselinePath, [...known]);
		writeJsonAtomic(ephemeralUdpCountsPath, ephemeralUdpCounts);

		// Outbound connections: checked for visibility, deliberately not persisted or alert-diffed —
		// normal desktop use opens/closes connections constantly, too noisy to be alert-worthy.
		let establishedCount = 0;
		if (config.network.alertOnOutbound) {
			const estResult = Bun.spawnSync(["ss", "-tnp", "state", "established"]);
			establishedCount = countEstablished(estResult.stdout.toString());
		}

		upsertScanStatus(
			db,
			"network",
			isFirstRun
				? `baseline created (${listeners.length} listeners)`
				: `ok (${listeners.length} listeners, +${newListeners} new${config.network.alertOnOutbound ? `, ${establishedCount} established` : ""})`,
		);
	}

	function start(): void {
		timer = setInterval(() => void scanNow(), config.network.pollIntervalMs);
	}

	function stop(): void {
		if (timer) clearInterval(timer);
	}

	return { scanNow, start, stop };
}
