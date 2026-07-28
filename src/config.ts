import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export interface HidsConfig {
	dataDir: string;
	gmailEnvPath: string;
	web: { host: string; port: number };
	fim: {
		watchPaths: string[];
		reconcileIntervalMs: number;
		debounceMs: number;
	};
	process: { pollIntervalMs: number; suspiciousDirs: string[] };
	auth: { reconnectBackoffMs: number };
	network: {
		pollIntervalMs: number;
		alertOnNewListener: boolean;
		alertOnOutbound: boolean;
	};
	alert: { debounceMs: number; emailOnNewBinary: boolean };
}

const CONFIG_PATH = join(import.meta.dir, "..", "config", "hids.config.json");
const EXAMPLE_CONFIG_PATH = join(
	import.meta.dir,
	"..",
	"config",
	"hids.config.json.example",
);

function expandHome(path: string): string {
	if (path.startsWith("~")) return join(homedir(), path.slice(1));
	return path;
}

export function loadConfig(): HidsConfig {
	const path = existsSync(CONFIG_PATH) ? CONFIG_PATH : EXAMPLE_CONFIG_PATH;
	const raw = JSON.parse(readFileSync(path, "utf-8")) as HidsConfig;

	raw.dataDir = process.env.HIDS_DATA_DIR ?? raw.dataDir;
	raw.gmailEnvPath = process.env.HIDS_GMAIL_ENV_PATH ?? raw.gmailEnvPath;
	raw.fim.watchPaths = raw.fim.watchPaths.map(expandHome);

	return raw;
}
