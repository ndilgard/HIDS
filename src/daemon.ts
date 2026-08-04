import { existsSync, mkdirSync } from "node:fs";
import { createMailer } from "./alert/email.ts";
import { AlertRecorder, safeCreateMailer } from "./alert/policy.ts";
import { loadConfig } from "./config.ts";
import { createAuthModule } from "./modules/auth.ts";
import { createFimModule } from "./modules/fim.ts";
import { createHeartbeatModule } from "./modules/heartbeat.ts";
import { createNetworkModule } from "./modules/network.ts";
import { createProcessModule } from "./modules/process.ts";
import type { Module } from "./modules/types.ts";
import { openHistoryDb } from "./state/history-db.ts";

async function waitForDataDir(
	dataDir: string,
	maxWaitMs = 60000,
): Promise<boolean> {
	const start = Date.now();
	while (Date.now() - start < maxWaitMs) {
		if (existsSync(dataDir)) return true;
		await new Promise((r) => setTimeout(r, 2000));
	}
	return false;
}

async function main() {
	const config = loadConfig();

	const dataDirReady = await waitForDataDir(config.dataDir);
	if (!dataDirReady) {
		console.warn(
			`[startup] WARNING: ${config.dataDir} not available after 60s — starting in degraded mode. ` +
				`Baselines/alerts won't persist until it appears, but detection and email alerts still work.`,
		);
		// Fall back to a local dir so the daemon can still run (baselines just won't be on the NAS
		// until it's back — this is intentionally not a crash).
		mkdirSync("/tmp/hids-fallback", { recursive: true });
		config.dataDir = "/tmp/hids-fallback";
	}

	const db = openHistoryDb(config.dataDir);
	const mailer = safeCreateMailer(createMailer, config.gmailEnvPath);
	const recorder = new AlertRecorder(
		db,
		mailer,
		config.alert.debounceMs,
		config.web.port,
	);

	const ctx = { config, db, recorder };
	const modules: Record<string, Module> = {
		fim: createFimModule(ctx),
		process: createProcessModule(ctx),
		auth: createAuthModule(ctx),
		network: createNetworkModule(ctx),
		heartbeat: createHeartbeatModule(ctx),
	};

	for (const [name, mod] of Object.entries(modules)) {
		console.log(`[daemon] starting ${name} module`);
		mod.start();
	}

	const shutdown = () => {
		console.log("[daemon] shutting down");
		for (const mod of Object.values(modules)) mod.stop();
		process.exit(0);
	};
	process.on("SIGTERM", shutdown);
	process.on("SIGINT", shutdown);

	console.log("[daemon] HIDS running");
}

void main();
