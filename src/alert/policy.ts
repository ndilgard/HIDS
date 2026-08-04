import {
	type HistoryStore,
	insertAlert,
	markEmailed,
	type Severity,
} from "../state/history-db.ts";
import {
	findMatchingRule,
	recordWhitelistMatch,
} from "../state/whitelist-store.ts";
import { type Mailer, MailerNotConfigured } from "./email.ts";

export interface Finding {
	module: string;
	severity: Severity;
	summary: string;
	detail: unknown;
}

/**
 * Central recorder: modules call record() only for findings they've already decided are
 * alert-worthy per their own per-module rules (see each modules/*.ts). Routine/non-alert-worthy
 * observations never reach this — that's what keeps disk usage tied to real triggers only.
 *
 * Batches findings into one summarizing email per debounce window instead of one email per
 * finding, so a burst (e.g. a whole watched directory deleted) doesn't flood the inbox.
 */
export class AlertRecorder {
	private pending: { id: string; finding: Finding }[] = [];
	private timer: ReturnType<typeof setTimeout> | null = null;

	constructor(
		private db: HistoryStore,
		private mailer: Mailer | null,
		private debounceMs: number,
	) {}

	record(finding: Finding): void {
		const whitelisted = findMatchingRule(
			this.db,
			finding.module,
			finding.detail,
		);
		if (whitelisted) {
			// Still recorded (as `suppressed`) rather than dropped entirely — a bad whitelist rule
			// should be catchable after the fact from the dashboard's "Suppressed Events" view, not
			// silently invisible. Just skipped from the normal alert list/email flow below.
			insertAlert(this.db, {
				module: finding.module,
				severity: finding.severity,
				summary: finding.summary,
				detail: finding.detail,
				suppressed: true,
				whitelistRuleId: whitelisted.id,
			});
			recordWhitelistMatch(this.db, whitelisted.id);
			return;
		}

		const id = insertAlert(this.db, {
			module: finding.module,
			severity: finding.severity,
			summary: finding.summary,
			detail: finding.detail,
		});
		this.pending.push({ id, finding });
		console.log(
			`[alert:${finding.module}] ${finding.severity} — ${finding.summary}`,
		);

		if (this.timer) clearTimeout(this.timer);
		this.timer = setTimeout(() => void this.flush(), this.debounceMs);
	}

	private async flush(): Promise<void> {
		const batch = this.pending;
		this.pending = [];
		this.timer = null;
		if (batch.length === 0) return;

		if (!this.mailer) {
			console.warn(
				`[alert] ${batch.length} finding(s) queued but email is not configured — see startup warning.`,
			);
			return;
		}

		const subject =
			batch.length === 1
				? `HIDS alert: ${batch[0]!.finding.module} — ${batch[0]!.finding.summary}`
				: `HIDS alert: ${batch.length} findings`;
		const body = batch
			.map(
				({ finding }) =>
					`[${finding.module}] ${finding.severity.toUpperCase()}: ${finding.summary}\n${JSON.stringify(finding.detail, null, 2)}`,
			)
			.join("\n\n---\n\n");

		try {
			await this.mailer.send(subject, body);
			for (const { id } of batch) markEmailed(this.db, id);
		} catch (err) {
			console.error("[alert] failed to send alert email:", err);
		}
	}
}

export function safeCreateMailer(
	createMailer: (path: string) => Mailer,
	gmailEnvPath: string,
): Mailer | null {
	try {
		return createMailer(gmailEnvPath);
	} catch (err) {
		if (err instanceof MailerNotConfigured) {
			console.warn(`[startup] ${err.message}`);
			return null;
		}
		throw err;
	}
}
