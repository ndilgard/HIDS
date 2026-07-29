import { createHash } from "node:crypto";
import {
	existsSync,
	type FSWatcher,
	readdirSync,
	readFileSync,
	statSync,
	watch,
} from "node:fs";
import { join } from "node:path";
import { upsertScanStatus } from "../state/history-db.ts";
import { readJson, writeJsonAtomic } from "../state/json-store.ts";
import type { Module, ModuleContext } from "./types.ts";

interface FileRecord {
	hash: string;
	size: number;
	mtime: string;
	mode: string;
}

type Baseline = Record<string, FileRecord>;

function hashFile(path: string): FileRecord | null {
	try {
		const buf = readFileSync(path);
		const stat = statSync(path);
		return {
			hash: createHash("sha256").update(buf).digest("hex"),
			size: stat.size,
			mtime: stat.mtime.toISOString(),
			mode: stat.mode.toString(8),
		};
	} catch {
		return null; // unreadable/gone between listing and reading — skip, don't crash
	}
}

function listFiles(root: string): string[] {
	if (!existsSync(root)) return [];
	const stat = statSync(root);
	if (stat.isFile()) return [root];
	if (!stat.isDirectory()) return [];
	const entries = readdirSync(root, { recursive: true }) as string[];
	return entries
		.map((e) => join(root, e))
		.filter((p) => {
			try {
				return statSync(p).isFile();
			} catch {
				return false;
			}
		});
}

function buildBaseline(watchPaths: string[]): Baseline {
	const baseline: Baseline = {};
	for (const root of watchPaths) {
		for (const file of listFiles(root)) {
			const record = hashFile(file);
			if (record) baseline[file] = record;
		}
	}
	return baseline;
}

/**
 * Every binary the network module has ever trusted (outbound-first-seen.json's top-level keys) —
 * closes the "trust once forever" gap's tampering half: even after the network layer has gone
 * permanently quiet on a binary, FIM keeps hashing it and alerts if its content ever changes.
 * Only reads the key set, not the (now nested, per-destination) values, so this stays unaffected
 * by how network.ts structures its own trust data internally.
 */
function getTrustedProcessPaths(dataDir: string): string[] {
	const firstSeen = readJson<Record<string, unknown>>(
		`${dataDir}/outbound-first-seen.json`,
		{},
	);
	return Object.keys(firstSeen).filter((p) => {
		try {
			return statSync(p).isFile();
		} catch {
			return false; // app since uninstalled — nothing to hash, not an error
		}
	});
}

export function createFimModule(ctx: ModuleContext): Module {
	const { config, db, recorder } = ctx;
	const baselinePath = `${config.dataDir}/baseline-fim.json`;
	const watchers: FSWatcher[] = [];
	const debounceTimers = new Map<string, ReturnType<typeof setTimeout>>();
	const watchedTrustedPaths = new Set<string>();
	let reconcileTimer: ReturnType<typeof setInterval> | null = null;

	/**
	 * Trusted-process paths accumulate over time as the network module discovers new binaries —
	 * called from scanNow() (so it naturally re-runs on every debounced/periodic scan) to pick up
	 * real-time fs.watch coverage for anything newly trusted since the daemon started, rather than
	 * waiting for the next 15-minute reconcile to notice a change.
	 */
	function watchNewTrustedPaths(paths: string[]): void {
		for (const path of paths) {
			if (watchedTrustedPaths.has(path)) continue;
			try {
				const watcher = watch(path, () => scheduleDebouncedScan(path));
				watchers.push(watcher);
				watchedTrustedPaths.add(path);
			} catch (err) {
				console.warn(`[fim] failed to watch trusted binary ${path}:`, err);
			}
		}
	}

	function reportUnreadablePaths(): void {
		for (const root of config.fim.watchPaths) {
			if (!existsSync(root)) {
				console.warn(`[fim] configured path does not exist, skipping: ${root}`);
			}
		}
	}

	async function scanNow(): Promise<void> {
		const oldBaseline = readJson<Baseline>(baselinePath, {});
		const isFirstRun =
			Object.keys(oldBaseline).length === 0 && !existsSync(baselinePath);

		const trustedProcessPaths = config.fim.watchTrustedProcessBinaries
			? getTrustedProcessPaths(config.dataDir)
			: [];
		const trustedPathSet = new Set(trustedProcessPaths);
		watchNewTrustedPaths(trustedProcessPaths);
		const newBaseline = buildBaseline([
			...config.fim.watchPaths,
			...trustedProcessPaths,
		]);

		if (!isFirstRun) {
			const oldPaths = new Set(Object.keys(oldBaseline));
			const newPaths = new Set(Object.keys(newBaseline));

			for (const path of oldPaths) {
				if (!newPaths.has(path)) {
					recorder.record({
						module: "fim",
						severity: "critical",
						summary: `Watched file deleted: ${path}`,
						detail: { path, previous: oldBaseline[path] },
					});
				}
			}
			for (const path of newPaths) {
				if (!oldPaths.has(path)) {
					if (trustedPathSet.has(path)) {
						// Not a new file on disk — FIM is just catching up to watch a binary the
						// network module started trusting. Onboard silently, same as any other
						// baseline-seeding event elsewhere in this project.
						continue;
					}
					recorder.record({
						module: "fim",
						severity: "warning",
						summary: `New file appeared in watched path: ${path}`,
						detail: { path, current: newBaseline[path] },
					});
				} else if (oldBaseline[path]!.hash !== newBaseline[path]!.hash) {
					if (trustedPathSet.has(path)) {
						recorder.record({
							module: "fim",
							severity: "critical",
							summary: `Trusted process binary changed since last verified — possible tampering: ${path}`,
							detail: {
								path,
								previous: oldBaseline[path],
								current: newBaseline[path],
							},
						});
					} else {
						recorder.record({
							module: "fim",
							severity: "critical",
							summary: `Watched file modified: ${path}`,
							detail: {
								path,
								previous: oldBaseline[path],
								current: newBaseline[path],
							},
						});
					}
				}
			}
		}

		writeJsonAtomic(baselinePath, newBaseline);
		upsertScanStatus(db, "fim", isFirstRun ? "baseline created" : "ok");
	}

	function scheduleDebouncedScan(key: string): void {
		const existing = debounceTimers.get(key);
		if (existing) clearTimeout(existing);
		debounceTimers.set(
			key,
			setTimeout(() => void scanNow(), config.fim.debounceMs),
		);
	}

	function start(): void {
		reportUnreadablePaths();
		for (const root of config.fim.watchPaths) {
			if (!existsSync(root)) continue;
			try {
				const watcher = watch(root, { recursive: true }, () =>
					scheduleDebouncedScan(root),
				);
				watchers.push(watcher);
			} catch (err) {
				console.warn(
					`[fim] failed to watch ${root}, relying on periodic reconcile only:`,
					err,
				);
			}
		}
		reconcileTimer = setInterval(
			() => void scanNow(),
			config.fim.reconcileIntervalMs,
		);
	}

	function stop(): void {
		for (const w of watchers) w.close();
		watchers.length = 0;
		watchedTrustedPaths.clear();
		for (const t of debounceTimers.values()) clearTimeout(t);
		debounceTimers.clear();
		if (reconcileTimer) clearInterval(reconcileTimer);
	}

	return { scanNow, start, stop };
}
