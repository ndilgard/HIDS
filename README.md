# HIDS

Custom lightweight Host Intrusion Detection System for a single personal Linux PC. Detection-only
(read-only observers, no enforcement/blocking) across four modules:

- **File integrity** — hashes a configurable watch list (`~/.ssh`, dotfiles, `/etc/passwd`,
  hal-skeleton's `credentials/` dir), real-time via `fs.watch` plus a periodic full re-walk
  safety net. `/etc/sudoers` is deliberately excluded — not readable by a normal user.
- **Process** — polls `/proc` every 10s; flags anything running from `/tmp`/`/dev/shm`/`/var/tmp`
  or a deleted-on-disk binary immediately. New-but-legitimate binaries are absorbed into an
  allowlist silently (no email, keeps this the noisy case in the polling world).
- **Auth** — streams `journalctl -f`; failed SSH logins, accepted SSH logins, and failed sudo
  attempts are always alert-worthy.
- **Network** — polls every 30s. Listening ports (`ss -tulnp`): new TCP listeners always alert;
  new UDP listeners only alert after fewer than 3 distinct ephemeral ports have been seen from that
  process (kills WebRTC/QUIC noise without blinding detection to an unrecognized process).
  Outbound connections (`ss -tnp state established` + `ss -unp`): a process already flagged
  suspicious (deleted binary / running from `/tmp`, `/dev/shm`, `/var/tmp`) always alerts the
  moment it talks to the network; any other binary's first-ever outbound connection alerts once,
  then goes quiet for that binary.

**Only real triggers ever touch disk** — routine scans that find nothing are never persisted, so
there's no retention/rotation job to maintain. All runtime data (baselines + the alerts database)
lives on the NAS at `/mnt/omv/HIDS/`, not in this repo.

## Setup

```bash
bun install
bun src/cli.ts init          # build baselines for all four modules
bun src/cli.ts test-email    # confirm Gmail alerting works
```

## Running persistently (24/7 while the PC is on)

```bash
mkdir -p ~/.config/systemd/user
cp systemd/hids.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now hids.service
loginctl enable-linger nate   # makes it survive logout and start at boot — do this once
```

`loginctl enable-linger` is a persistent setting (stored in `/var/lib/systemd/linger/nate`) — it
does not need to be re-run. Verify anytime with `loginctl show-user nate --property=Linger`.

## CLI

| Command | What it does |
|---|---|
| `hids init [module] [--force]` | Build/rebuild a baseline (fim/process/network; auth has none) |
| `hids scan-now [module]` | Run a one-off scan immediately, no daemon needed — records to `alerts` but never sends real email, only the daemon does |
| `hids status` | Last-scan time + result per module |
| `hids alerts [--since] [--module]` | List recorded alerts |
| `hids config` | Print resolved config |
| `hids test-email` | Send a test alert email |
| `hids daemon` | Run the foreground daemon (what systemd execs) |
| `hids start` / `stop` / `restart` | Thin wrappers around `systemctl --user` |

Dashboard: `http://127.0.0.1:8787` while the daemon is running (localhost-only, no auth — a
deliberate assumption for a single-user personal PC).

## Config

`config/hids.config.json` (copy from `config/hids.config.json.example`). Key fields: `dataDir`
(defaults to `/mnt/omv/HIDS`, override via `HIDS_DATA_DIR`), `gmailEnvPath` (defaults to
hal-skeleton's existing `credentials/gmail-smtp.env`, override via `HIDS_GMAIL_ENV_PATH`), and
per-module intervals/thresholds.

## Known limits

- No `auditd` installed, so process monitoring is polling-based (10s interval) — a process that
  spawns and exits between polls is invisible. `sudo apt install auditd` + execve rules would
  close this gap, out of scope for v1.
- Dashboard has no auth and binds to `127.0.0.1` only — revisit if remote/LAN access is ever
  wanted.
