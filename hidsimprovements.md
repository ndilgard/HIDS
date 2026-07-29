# HIDS Improvement Backlog

Ideas for what to build next, roughly in the order they were proposed. Not commitments — pull
from this list when there's appetite for the next round of work.

## 1. Self-protection (heartbeat / dead-man's-switch) — DONE

Closes the "who watches the watcher" gap. Right now, if the daemon crashed, got killed, or an
attacker with root disabled it outright, nothing would notice — every existing module only
detects *other* things going wrong on the host, not HIDS itself going quiet. The fix has to live
outside the host, since anything running only on this machine can be silenced the same way the
daemon itself can.

## 2. Real-time detection via eBPF

Process and network activity are currently caught by polling (10s / 30s intervals). Something
fast-lived — a process that starts, does something, and exits between two polls — could slip
through entirely. eBPF hooks on `exec`/`connect` syscalls would catch activity the instant it
happens instead of sampling for it. Heavier build: new toolchain, likely a small Rust or C
component alongside the existing TypeScript/Bun modules.

## 3. Daily health digest

A quiet, scheduled email confirming all four modules (FIM, process, auth, network) are alive and
scanning. Today, HIDS is silent by design unless something triggers an alert — which means a
silent failure in one module could go unnoticed for a long time with no signal either way.

## 4. Automated test suite

No tests exist yet. Several real bugs this session (UDP `ss` column mis-indexing, the CLI email
leak) were only caught by live production use, not by any pre-merge check. A test suite covering
the parsing/detection logic would catch regressions before they reach the actual machine.

## Other ideas raised in passing (not yet scoped)

- Rootkit / hidden-process detection (kernel module loading, process list discrepancies)
- Installed-package drift baseline (apt/dpkg) for supply-chain awareness
- Alert severity routing (critical → push notification in addition to email, not just warning-level email)
- Dashboard improvements: historical alert search/filtering, not just current status
