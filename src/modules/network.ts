import { upsertScanStatus } from "../state/history-db.ts";
import { readJson, writeJsonAtomic } from "../state/json-store.ts";
import type { Module, ModuleContext } from "./types.ts";

interface Listener {
	proto: string;
	localAddress: string;
	process: string;
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

		const listenResult = Bun.spawnSync(["ss", "-tulnp"]);
		const listeners = parseListeners(listenResult.stdout.toString());
		let newListeners = 0;

		for (const listener of listeners) {
			const key = listenerKey(listener);
			if (!known.has(key)) {
				known.add(key);
				newListeners++;
				if (!isFirstRun && config.network.alertOnNewListener) {
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
