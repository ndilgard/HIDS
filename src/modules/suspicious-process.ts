import { readlinkSync } from "node:fs";

export interface SuspiciousCheck {
	suspicious: boolean;
	reason: "deleted" | "suspicious-path" | null;
	resolvedExePath: string | null;
}

/**
 * Shared with process.ts's own binary checks: exe path under a suspicious dir (/tmp, /dev/shm,
 * /var/tmp) or a binary that's been deleted from disk post-launch — both classic tamper/fileless
 * indicators. Used both when scanning /proc directly (process.ts) and when resolving a PID found
 * via `ss` (network.ts's outbound checks), so the two modules share one definition of "suspicious"
 * instead of drifting apart.
 */
export function checkSuspiciousExePath(
	exePath: string,
	suspiciousDirs: string[],
): SuspiciousCheck {
	const deleted = exePath.endsWith(" (deleted)");
	const resolvedExePath = deleted
		? exePath.slice(0, -" (deleted)".length)
		: exePath;

	if (deleted) {
		return { suspicious: true, reason: "deleted", resolvedExePath };
	}
	if (suspiciousDirs.some((dir) => resolvedExePath.startsWith(dir))) {
		return { suspicious: true, reason: "suspicious-path", resolvedExePath };
	}
	return { suspicious: false, reason: null, resolvedExePath };
}

export function resolveExePath(pid: number): string | null {
	try {
		return readlinkSync(`/proc/${pid}/exe`);
	} catch {
		return null; // process exited between listing and resolving, or not our user
	}
}
