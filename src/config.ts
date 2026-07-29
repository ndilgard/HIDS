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
		watchTrustedProcessBinaries: boolean;
	};
	process: { pollIntervalMs: number; suspiciousDirs: string[] };
	auth: { reconnectBackoffMs: number };
	network: {
		pollIntervalMs: number;
		alertOnNewListener: boolean;
		alertOnOutbound: boolean;
		alertOnUdp: boolean;
	};
	alert: { debounceMs: number; emailOnNewBinary: boolean };
	heartbeat: { enabled: boolean; url: string; intervalMs: number };
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
	raw.network.alertOnUdp ??= false; // default off — UDP "listeners" are mostly ephemeral app noise (WebRTC/QUIC/DNS)
	raw.fim.watchTrustedProcessBinaries ??= true;
	raw.heartbeat ??= { enabled: false, url: "", intervalMs: 120000 };

	return raw;
}
