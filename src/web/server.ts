import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { HidsConfig } from "../config.ts";
import {
	getAlerts,
	getScanStatus,
	type HistoryStore,
} from "../state/history-db.ts";

const INDEX_HTML_PATH = join(import.meta.dir, "public", "index.html");

export function startDashboard(db: HistoryStore, config: HidsConfig) {
	const server = Bun.serve({
		hostname: config.web.host,
		port: config.web.port,
		fetch(req) {
			const url = new URL(req.url);

			if (url.pathname === "/" || url.pathname === "/index.html") {
				return new Response(readFileSync(INDEX_HTML_PATH, "utf-8"), {
					headers: { "content-type": "text/html" },
				});
			}

			if (url.pathname === "/api/status") {
				return Response.json(getScanStatus(db));
			}

			if (url.pathname === "/api/alerts") {
				const since = url.searchParams.get("since") ?? undefined;
				const module = url.searchParams.get("module") ?? undefined;
				const limit = url.searchParams.get("limit");
				return Response.json(
					getAlerts(db, {
						since,
						module,
						limit: limit ? Number(limit) : undefined,
					}),
				);
			}

			return new Response("Not found", { status: 404 });
		},
	});

	// Explicit security assumption: localhost-only, no auth — single-user personal PC.
	console.log(
		`[web] dashboard listening on http://${config.web.host}:${config.web.port} (localhost-only)`,
	);
	return server;
}
