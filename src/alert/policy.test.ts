import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	getAlerts,
	type HistoryStore,
	openHistoryDb,
} from "../state/history-db.ts";
import { addWhitelistRule } from "../state/whitelist-store.ts";
import type { Mailer } from "./email.ts";
import { AlertRecorder, type Finding } from "./policy.ts";

let db: HistoryStore;

function mockMailer() {
	const sent: { subject: string; body: string }[] = [];
	const mailer: Mailer = {
		async send(subject, body) {
			sent.push({ subject, body });
		},
	};
	return { mailer, sent };
}

function finding(overrides: Partial<Finding> = {}): Finding {
	return {
		module: "network",
		severity: "warning",
		summary: "test finding",
		detail: { exePath: "/usr/bin/test" },
		...overrides,
	};
}

beforeEach(() => {
	db = openHistoryDb(mkdtempSync(join(tmpdir(), "hids-test-")));
});

afterEach(() => {
	rmSync(db.dataDir, { recursive: true, force: true });
});

describe("AlertRecorder — severity-gated email", () => {
	test("a critical finding is emailed", async () => {
		const { mailer, sent } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 5, 0);
		recorder.record(
			finding({ severity: "critical", summary: "critical thing" }),
		);
		await Bun.sleep(20);
		expect(sent).toHaveLength(1);
		expect(sent[0]!.subject).toContain("critical thing");
	});

	test("a warning finding is recorded but never emailed", async () => {
		const { mailer, sent } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 5, 0);
		recorder.record(finding({ severity: "warning", summary: "warning thing" }));
		await Bun.sleep(20);
		expect(sent).toHaveLength(0);
		const alerts = getAlerts(db, { module: "network" });
		expect(alerts).toHaveLength(1);
		expect(alerts[0]!.summary).toBe("warning thing");
	});

	test("an info finding is recorded but never emailed", async () => {
		const { mailer, sent } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 5, 0);
		recorder.record(finding({ severity: "info", summary: "info thing" }));
		await Bun.sleep(20);
		expect(sent).toHaveLength(0);
		expect(getAlerts(db, { module: "network" })).toHaveLength(1);
	});

	test("a mixed batch only emails the critical finding, not the warning alongside it", async () => {
		const { mailer, sent } = mockMailer();
		const recorder = new AlertRecorder(db, mailer, 20, 0);
		recorder.record(finding({ severity: "warning", summary: "noisy warning" }));
		recorder.record(
			finding({ severity: "critical", summary: "the real thing" }),
		);
		await Bun.sleep(40);
		expect(sent).toHaveLength(1);
		expect(sent[0]!.body).toContain("the real thing");
		expect(sent[0]!.body).not.toContain("noisy warning");
		// Both still land in the alert store for the dashboard, regardless of email routing.
		expect(getAlerts(db, { module: "network" })).toHaveLength(2);
	});

	test("a whitelisted critical finding is still suppressed, not emailed", async () => {
		const { mailer, sent } = mockMailer();
		addWhitelistRule(db, {
			module: "network",
			field: "exePath",
			value: "/usr/bin/test",
		});
		const recorder = new AlertRecorder(db, mailer, 5, 0);
		recorder.record(
			finding({ severity: "critical", detail: { exePath: "/usr/bin/test" } }),
		);
		await Bun.sleep(20);
		expect(sent).toHaveLength(0);
		const [alert] = getAlerts(db, { module: "network", suppressed: true });
		expect(alert?.suppressed).toBe(true);
	});

	test("with no mailer configured, a critical finding is still recorded without throwing", async () => {
		const recorder = new AlertRecorder(db, null, 5, 0);
		expect(() =>
			recorder.record(finding({ severity: "critical" })),
		).not.toThrow();
		await Bun.sleep(20);
		expect(getAlerts(db, { module: "network" })).toHaveLength(1);
	});
});
