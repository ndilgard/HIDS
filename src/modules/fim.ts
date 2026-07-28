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

export function createFimModule(ctx: ModuleContext): Module {
	const { config, db, recorder } = ctx;
	const baselinePath = `${config.dataDir}/baseline-fim.json`;
	const watchers: FSWatcher[] = [];
	const debounceTimers = new Map<string, ReturnType<typeof setTimeout>>();
	let reconcileTimer: ReturnType<typeof setInterval> | null = null;

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
		const newBaseline = buildBaseline(config.fim.watchPaths);

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
					recorder.record({
						module: "fim",
						severity: "warning",
						summary: `New file appeared in watched path: ${path}`,
						detail: { path, current: newBaseline[path] },
					});
				} else if (oldBaseline[path]!.hash !== newBaseline[path]!.hash) {
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
		for (const t of debounceTimers.values()) clearTimeout(t);
		debounceTimers.clear();
		if (reconcileTimer) clearInterval(reconcileTimer);
	}

	return { scanNow, start, stop };
}
