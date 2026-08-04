import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { HidsConfig } from "../config.ts";
import {
	getAlerts,
	getScanStatus,
	type HistoryStore,
	type ScanStatus,
} from "../state/history-db.ts";
import {
	addWhitelistRule,
	getWhitelistRules,
	removeWhitelistRule,
} from "../state/whitelist-store.ts";

/** Modules with a genuinely fixed, short poll interval — the only reliable signal that the
 * detection daemon (not just this dashboard process) is actually still alive and scanning. FIM's
 * reconcile pass is 15 minutes and only reruns on a config change or a real file event, and auth's
 * journalctl stream only updates its timestamp on (re)connect, not per line watched — both can sit
 * "stale" for hours while working perfectly normally, so neither belongs in this check. */
const LIVENESS_MODULES = ["process", "network", "heartbeat"];
const LIVENESS_STALE_MS = 5 * 60 * 1000; // 5 minutes — comfortably more than 3x the slowest of the three (heartbeat, 2 min)

function computeLiveness(statuses: (ScanStatus & { module: string })[]) {
	const relevant = statuses.filter((s) => LIVENESS_MODULES.includes(s.module));
	if (relevant.length === 0) {
		return { aliveAsOf: null, staleMs: null, likelyDown: true };
	}
	const mostRecentMs = Math.max(
		...relevant.map((s) => new Date(s.last_scan_ts).getTime()),
	);
	const staleMs = Date.now() - mostRecentMs;
	return {
		aliveAsOf: new Date(mostRecentMs).toISOString(),
		staleMs,
		likelyDown: staleMs > LIVENESS_STALE_MS,
	};
}

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
		async fetch(req) {
			const url = new URL(req.url);

			if (url.pathname === "/" || url.pathname === "/index.html") {
				return new Response(readFileSync(INDEX_HTML_PATH, "utf-8"), {
					headers: { "content-type": "text/html" },
				});
			}

			if (url.pathname === "/api/status") {
				return Response.json(getScanStatus(db));
			}

			if (url.pathname === "/api/liveness") {
				return Response.json(computeLiveness(getScanStatus(db)));
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

			if (url.pathname === "/api/whitelist" && req.method === "GET") {
				return Response.json(getWhitelistRules(db));
			}

			if (url.pathname === "/api/whitelist" && req.method === "POST") {
				const body = (await req.json()) as {
					module?: string;
					field?: string;
					value?: string;
					note?: string;
				};
				if (!body.module || !body.field || !body.value) {
					return Response.json(
						{ error: "module, field, and value are required" },
						{ status: 400 },
					);
				}
				const rule = addWhitelistRule(db, {
					module: body.module,
					field: body.field,
					value: body.value,
					note: body.note,
				});
				return Response.json(rule, { status: 201 });
			}

			if (
				url.pathname.startsWith("/api/whitelist/") &&
				req.method === "DELETE"
			) {
				const id = url.pathname.slice("/api/whitelist/".length);
				removeWhitelistRule(db, id);
				return new Response(null, { status: 204 });
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
