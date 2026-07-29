import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { HidsConfig } from "../config.ts";
import {
	getAlerts,
	getScanStatus,
	type HistoryStore,
} from "../state/history-db.ts";

const INDEX_HTML_PATH = join(import.meta.dir, "public", "index.html");

/** healthchecks.io's own view of the check (up/down/grace), polled server-side rather than on
 * every dashboard load — this is a convenience mirror of what's already visible on their site, not
 * a replacement for it. If HIDS itself is down, this endpoint (and the whole dashboard) is exactly
 * as unavailable as everything else on this host; healthchecks.io's email alert remains the only
 * signal that actually survives that case. */
let remoteHeartbeatCache: { data: unknown; fetchedAt: number } | null = null;
const REMOTE_HEARTBEAT_CACHE_MS = 60_000;

function extractCheckUuid(pingUrl: string): string | null {
	const match = pingUrl.match(/([0-9a-f]{8}-[0-9a-f-]{27})\/?$/i);
	return match ? match[1]! : null;
}

async function getRemoteHeartbeatStatus(config: HidsConfig): Promise<unknown> {
	if (!config.heartbeat.enabled || !config.heartbeat.apiKey) {
		return { configured: false };
	}
	if (
		remoteHeartbeatCache &&
		Date.now() - remoteHeartbeatCache.fetchedAt < REMOTE_HEARTBEAT_CACHE_MS
	) {
		return remoteHeartbeatCache.data;
	}

	const uuid = extractCheckUuid(config.heartbeat.url);
	if (!uuid) return { configured: false };

	try {
		const res = await fetch(`https://healthchecks.io/api/v3/checks/${uuid}`, {
			headers: { "X-Api-Key": config.heartbeat.apiKey },
		});
		if (!res.ok) {
			const data = { configured: true, error: `HTTP ${res.status}` };
			remoteHeartbeatCache = { data, fetchedAt: Date.now() };
			return data;
		}
		const check = (await res.json()) as {
			status: string;
			last_ping: string | null;
			next_ping: string | null;
		};
		const data = {
			configured: true,
			status: check.status,
			last_ping: check.last_ping,
			next_ping: check.next_ping,
		};
		remoteHeartbeatCache = { data, fetchedAt: Date.now() };
		return data;
	} catch (err) {
		const data = { configured: true, error: (err as Error).message };
		remoteHeartbeatCache = { data, fetchedAt: Date.now() };
		return data;
	}
}

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

			if (url.pathname === "/api/heartbeat-remote") {
				return getRemoteHeartbeatStatus(config).then((data) =>
					Response.json(data),
				);
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
