import { describe, expect, test } from "bun:test";
import { checkSuspiciousExePath } from "./suspicious-process.ts";

const suspiciousDirs = ["/tmp", "/dev/shm", "/var/tmp"];

describe("checkSuspiciousExePath", () => {
	test("flags a deleted binary and strips the ' (deleted)' suffix", () => {
		const result = checkSuspiciousExePath(
			"/usr/bin/curl (deleted)",
			suspiciousDirs,
		);
		expect(result).toEqual({
			suspicious: true,
			reason: "deleted",
			resolvedExePath: "/usr/bin/curl",
		});
	});

	test("flags a binary running from a suspicious directory", () => {
		const result = checkSuspiciousExePath("/tmp/payload", suspiciousDirs);
		expect(result.suspicious).toBe(true);
		expect(result.reason).toBe("suspicious-path");
		expect(result.resolvedExePath).toBe("/tmp/payload");
	});

	test("flags a binary under any configured suspicious dir, not just the first", () => {
		expect(
			checkSuspiciousExePath("/dev/shm/x", suspiciousDirs).suspicious,
		).toBe(true);
		expect(
			checkSuspiciousExePath("/var/tmp/x", suspiciousDirs).suspicious,
		).toBe(true);
	});

	test("does not flag a normal binary in a trusted path", () => {
		const result = checkSuspiciousExePath("/usr/bin/bash", suspiciousDirs);
		expect(result).toEqual({
			suspicious: false,
			reason: null,
			resolvedExePath: "/usr/bin/bash",
		});
	});

	test("a deleted binary that also lives in a suspicious dir is reported as 'deleted', not 'suspicious-path'", () => {
		const result = checkSuspiciousExePath(
			"/tmp/payload (deleted)",
			suspiciousDirs,
		);
		expect(result.reason).toBe("deleted");
	});

	test("respects an empty suspiciousDirs list (nothing path-based flags)", () => {
		const result = checkSuspiciousExePath("/tmp/payload", []);
		expect(result.suspicious).toBe(false);
	});
});
