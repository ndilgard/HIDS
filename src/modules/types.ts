import type { AlertRecorder } from "../alert/policy.ts";
import type { HidsConfig } from "../config.ts";
import type { HistoryStore } from "../state/history-db.ts";

export interface ModuleContext {
	config: HidsConfig;
	db: HistoryStore;
	recorder: AlertRecorder;
}

export interface Module {
	/** Runs one scan immediately; used by both the daemon's schedule and `hids scan-now`. */
	scanNow(): Promise<void>;
	/** Starts the module's ongoing schedule (interval or event stream). No-op for CLI-only use. */
	start(): void;
	stop(): void;
}
