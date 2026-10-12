---
name: lab
description: Inspect or diagnose the vh-storage production test lab VM (ssh vh-storage), which tests the real apt repo install/upgrade path (never install candidate .debs on it), including checking daemon/FUSE/DB health and collecting evidence after a failed upgrade. Use whenever work touches the lab host or needs real-host validation of packaging or runtime behavior.
---

# vh-storage lab

`vh-storage` (10.0.0.33) is the production test lab: Ubuntu 24.04, hardware TPM, local PostgreSQL 16 +
nginx, a 1 TB disk at `/var/lib/vaulthalla`, and packages from the real `apt.vaulthalla.sh stable` repo.
**Treat it as production.** Topology is in `.claude/context/environment.md`.

## Permission boundary

- **Allowed without asking:** read-only inspection. That covers `scripts/inspect.sh`, `journalctl`, `systemctl status/show`,
  `dpkg-query`, `ps`, `/proc`, `/sys/fs/fuse/connections/*`, and reading files under `/etc/vaulthalla` (never print
  secrets; `config.yaml` may hold none, but `vaulthalla.env` and certbot `cloudflare.ini` do).
- **Ask first, in this conversation, every time:** installing, upgrading, or removing packages, `dpkg --configure`,
  restarting or stopping services, `vh setup|teardown`, any PostgreSQL write or restart, unmount/abort of the FUSE
  connection, killing processes, and editing files. Approval for one action doesn't cover the next.

## FUSE hazard (read before running anything)

A wedged daemon leaves any `stat`/`ls`/`df`/`mountpoint`/`find` touching `/mnt/vaulthalla` in
**uninterruptible sleep**. `timeout` and SIGKILL can't clear it, and each attempt leaks another stuck
process. So:
- Detect the mount through `/proc/self/mountinfo` and check health through the
  `/sys/fs/fuse/connections/<minor>/waiting` counter (needs sudo). `scripts/inspect.sh` does both.
- Use `df -x fuse.vaulthalla-fuse`. Never run a bare `df`.
- Only touch the mount itself after `waiting` reads 0.

## Procedures

### Health snapshot

```bash
bash .claude/skills/lab/scripts/inspect.sh
```

This reports package state (`ii` good; `iF`/`iU` half-configured/unpacked), apt/dpkg activity and lock,
unit states with restart counts and timestamps, the FUSE wedge indicator, D-state processes, daemon thread wait channels
(many `futex_wait_queue` plus a stuck FUSE counter usually means DB pool starvation), storage, TPM, and journal warnings.

### No candidate packages on the lab

**Never install a pre-release, candidate or locally built .deb on vh-storage**: no `lab-smoke --deb`, no
`apt-get install ./x.deb`, no CI dry-run artifacts. The lab exists to test the real `apt.vaulthalla.sh` install and
upgrade path, so it has to sit on a published version when a release is cut. Pre-flashing a candidate defeats that,
and on 2026-10-02 it also broke DNS resolution on the maintainer's network. Prove candidates on the dev VM
(`/verify`, `make itest`) and with a CI dry run. Lab upgrades come from the real repo, after publishing, and only
when the maintainer asks.

When the maintainer asks for a real-repo upgrade: baseline `inspect.sh` (must be `ii`, lock free, `waiting=0`), then
`ssh vh-storage 'sudo apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y vaulthalla'`, then
`inspect.sh` again and `ssh vh-storage 'timeout 10 vh status'`. Check that `/etc/vaulthalla/config.yaml` is unchanged
(compare `sha256sum` before and after).

### Restoring the lab from a wedged upgrade (after approval)

The daemon is wedged when `waiting` stays > 0, and the postinst is blocked. In order of least disruption:
1. `sudo systemctl restart vaulthalla`. If stop hangs, `sudo systemctl kill -s KILL vaulthalla` targets only the
   unit's cgroup. **Never** `pkill -f vaulthalla` (see `packaging-lifecycle.md`, teardown safety).
2. If the mount stays wedged: `echo 1 | sudo tee /sys/fs/fuse/connections/<minor>/abort`, then
   `sudo fusermount3 -uz /mnt/vaulthalla`. This fails the stuck requests, and the blocked postinst resumes.
3. `sudo dpkg --configure -a`, then re-run `inspect.sh`.

Capture evidence first (inspect output, `journalctl -u vaulthalla -u postgresql@16-main --since …`), because
restarting destroys the wedged state.

## Reporting

State what you ran on the lab, which parts were read-only, and anything you left behind (for example, stuck probe processes).
