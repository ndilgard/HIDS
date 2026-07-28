import {
	appendFileSync,
	existsSync,
	mkdirSync,
	readFileSync,
	renameSync,
	writeFileSync,
} from "node:fs";
import { readJson, writeJsonAtomic } from "./json-store.ts";

/**
 * Alert storage lives on a network (SMB/CIFS) mount, not local disk (Nate's explicit choice —
 * NAS-hosted output). bun:sqlite was the original design here, but writes over this mount
 * reliably fail with SQLITE_BUSY/"database is locked" — confirmed empirically, not just a
 * theoretical risk: network filesystems and SQLite's fcntl-based locking don't get along, even
 * with a single writer. Plain appendFileSync/writeFileSync+renameSync both work fine on the same
 * mount, so alerts are an append-only JSONL file and scan_status is a small atomically-written
 * JSON object — no sqlite dependency needed at all.
 */

export type Severity = "info" | "warning" | "critical";

export interface Alert {
	id: string;
	ts: string;
	module: string;
	severity: Severity;
	summary: string;
	detail: unknown;
	emailed: boolean;
}

export interface ScanStatus {
	last_scan_ts: string;
	last_result: string;
}

let counter = 0;
function nextId(): string {
	counter += 1;
	return `${Date.now()}-${process.pid}-${counter}`;
}

export interface HistoryStore {
	dataDir: string;
}

export function openHistoryDb(dataDir: string): HistoryStore {
	mkdirSync(dataDir, { recursive: true });
	return { dataDir };
}

function alertsPath(store: HistoryStore): string {
	return `${store.dataDir}/alerts.jsonl`;
}

function statusPath(store: HistoryStore): string {
	return `${store.dataDir}/scan_status.json`;
}

function readAllAlerts(store: HistoryStore): Alert[] {
	const path = alertsPath(store);
	if (!existsSync(path)) return [];
	const lines = readFileSync(path, "utf-8")
		.split("\n")
		.filter((l) => l.trim());
	const alerts: Alert[] = [];
	for (const line of lines) {
		try {
			alerts.push(JSON.parse(line));
		} catch {
			// corrupted/partial line — skip rather than fail the whole read
		}
	}
	return alerts;
}

/** Only ever called when a finding actually crosses the alert-worthy threshold. */
export function insertAlert(
	store: HistoryStore,
	args: {
		module: string;
		severity: Severity;
		summary: string;
		detail: unknown;
	},
): string {
	const id = nextId();
	const alert: Alert = {
		id,
		ts: new Date().toISOString(),
		module: args.module,
		severity: args.severity,
		summary: args.summary,
		detail: args.detail,
		emailed: false,
	};
	appendFileSync(alertsPath(store), `${JSON.stringify(alert)}\n`);
	return id;
}

/** Rewrites the whole file with the matching row updated — fine at the low volume this sees. */
export function markEmailed(store: HistoryStore, id: string): void {
	const path = alertsPath(store);
	const alerts = readAllAlerts(store).map((a) =>
		a.id === id ? { ...a, emailed: true } : a,
	);
	const content =
		alerts.map((a) => JSON.stringify(a)).join("\n") +
		(alerts.length ? "\n" : "");
	const tmpPath = `${path}.tmp-${process.pid}`;
	writeFileSync(tmpPath, content);
	renameSync(tmpPath, path);
}

export function getAlerts(
	store: HistoryStore,
	opts: { since?: string; module?: string; limit?: number } = {},
): Alert[] {
	let alerts = readAllAlerts(store);
	if (opts.since) alerts = alerts.filter((a) => a.ts >= opts.since!);
	if (opts.module) alerts = alerts.filter((a) => a.module === opts.module);
	alerts.sort((a, b) => (a.ts < b.ts ? 1 : -1));
	return alerts.slice(0, opts.limit ?? 200);
}

/** Fixed-size, one row per module — overwritten every scan, never grows. */
export function upsertScanStatus(
	store: HistoryStore,
	module: string,
	result: string,
): void {
	const all = readJson<Record<string, ScanStatus>>(statusPath(store), {});
	all[module] = { last_scan_ts: new Date().toISOString(), last_result: result };
	writeJsonAtomic(statusPath(store), all);
}

export function getScanStatus(
	store: HistoryStore,
): (ScanStatus & { module: string })[] {
	const all = readJson<Record<string, ScanStatus>>(statusPath(store), {});
	return Object.entries(all).map(([module, status]) => ({ module, ...status }));
}
