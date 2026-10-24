# Environment topology

The dev infrastructure is on the maintainer's home Proxmox server. All VMs are on one host, as separate nodes on `10.0.0.0/24`.

| Host | Role | Access | Disposable? |
|---|---|---|---|
| `dev` (10.0.0.11) | **This VM.** Agent dev box, checkout at `/srv/vaulthalla` | local, `coop` (uid 1000, passwordless sudo, in `vaulthalla` + `fuse` groups) | Yes, it's a disposable agent VM |
| `vh-storage` (10.0.0.33) | **Production test lab.** Ubuntu 24.04, 8 vCPU, 31 GiB, 1 TB `/dev/sdb1` mounted at `/var/lib/vaulthalla`, **hardware TPM** (`/dev/tpm0`), local PostgreSQL 16 + nginx, installs from the real `apt.vaulthalla.sh` repo | `ssh vh-storage` (user `coop`, passwordless sudo) | **No.** Treat it as production. Get approval before any mutation |
| `vps` (GitHub Actions runner) | Off-site VPS shared with the ValkyrianLabs runner. Vaulthalla's runner is user `gh-vaulthalla` (no sudo, no docker), service `github-vaulthalla-runner.service` in `ci.slice`; CI runs in rootless Podman containers (`ci/run-ci`) | through GitHub Actions only (labels `vaulthalla`, `vps-ci`) | No: shared CI host |
| `dev-db` (10.0.0.20) | Shared PostgreSQL 16 for the maintainer's side projects (2 vCPU, 7.7 GiB, 19 GB root disk at 50%). **Not used by the vaulthalla core daemon or its tests** | `ssh dev-db` (user `coop`, passwordless sudo). PG listens on `127.0.0.1` + `10.0.0.20:5432`, scram auth from `10.0.0.0/24` | Partly. Agents may create and drop their **own** burner DBs and roles (via `sudo -u postgres`), but must never modify existing DBs. **Prefer the dev VM's local PostgreSQL**, which is simpler |

## This VM (`dev`)

- A live source install runs here: `vaulthalla`, `vaulthalla-cli(.socket)`, `vaulthalla-web` are active,
  FUSE is mounted at `/mnt/vaulthalla`, and local PostgreSQL 16 is running. `make uninstall` tears that down; `make dev` now installs the isolated dev instance beside it (`/opt/vaulthalla-dev`,
  `vaulthalla-dev*.service`, `/mnt/vh_dev`, DB `vaulthalla_dev`, ports +100, `vh-dev`), and `VH_INSTANCE= make dev` is
  the old in-place dev install.
- `vaulthalla-price-bot.service` (gunicorn on `127.0.0.1:36933`) runs the **price bot**, a separate repo checked out at
  `/srv/vaulthalla-price-bot` (github.com/vaulthalla/vaulthalla-price-bot). It drives S3 cost estimates; see
  `architecture.md` → S3 pricing. It's outside this repo's install lifecycle: `make uninstall/dev` must not touch it,
  and `vaulthalla*` unit globs match it.
- Dev HTTPS: `Caddyfile` → `https://vh.home.arpa:8443` (tls internal; `/ws`→36969, `/preview|/download|/upload`
  →36970, everything else → Next dev on 36968). nginx owns :80/:443.
- Toolchain: gcc/g++ 14.2 (Ubuntu), meson 1.3.2, ninja 1.11, python 3.12, clang-format 18, conan 2.17
  (unused), pmdocs 1.0.5, ripgrep. **No `gh`, no `shellcheck`.**
  - **Node is v22.16 but `web/.nvmrc` wants 24.13. pnpm is 10.12.4 but `packageManager` pins 11.0.8.** Check
    `pnpm --dir web typecheck` works before trusting web results; install a matching toolchain if not.
- Secrets live on disk in gitignored files: repo-root `.bashrc` (the only local env file: R2 admin/SES/test-DB creds;
  dev's `/srv/vaulthalla/.bashrc` is byte-identical to the Mac's) and root-owned `cloudflare.ini`. **Never cat, print,
  or commit these.** Source them to use them. The two older env files under `deploy/` are retired
  (2026-10-22); `bin/tests/retire_legacy_test_env.sh` offers to delete stray copies.
- Git remotes: `origin` (github.com/vaulthalla/server), `web-repo` (legacy web repo history).

## dev-db contents (surveyed 2026-09-30)

- `vaulthalla_io`, `vh_io`: **the vaulthalla.io website** (Payload CMS; separate repo, not this project). `vh_io`
  currently has 0 tables, and `~/vh-io*.sql` on dev-db are 2026-04-04 dumps of the website schema. Not ours to touch.
  The website is the likely receiver of `pmdocs push` (`DOCS_SYNC_ENDPOINT`).
- `vaulthalla_price_bot`: the price bot's DB (provider sources, price meters/tiers/profiles, fetch runs,
  publish records). It's used by `/srv/vaulthalla-price-bot` on the dev VM (`DB_HOST=10.0.0.20`). The vaulthalla
  daemon never connects to it directly; it only consumes the price bot's signed published artifacts over HTTP.
- Other DBs (`ah`, `uri`, `portfolio`, `payload_*`, `mollie_jayne_hair_co`, …) belong to unrelated projects.
- **Uptime coupling:** PostgreSQL here came up at 2026-09-30 20:34 UTC, after the price bot started on dev (19:35 UTC).
  Price bot behavior while its DB is unavailable hasn't been checked.
- Roles are only `coop` and `postgres` (both superuser). **There is no `vaulthalla` role or core DB here.** The daemon
  always uses the host-local PostgreSQL (`localhost:5432`, DB/role `vaulthalla`), and tests use `VH_TEST_DB_HOST=127.0.0.1`.
- **Burner DB policy (maintainer, 2026-09-30):** agents may create throwaway DBs and roles here. Prefix them `claude_burner_*`,
  drop them when done, and never touch existing DBs. The default is still the dev VM's local PostgreSQL. Use dev-db
  only when a *separate host* matters, for example exercising `vh setup remote-db`, or reproducing P0-1 by restarting
  PostgreSQL under a running daemon without the lab. **Restarting PostgreSQL on dev-db disrupts the other projects
  and the price bot, so ask first.**
- Unattended-upgrades is enabled here too, so PostgreSQL restarts will happen under any client (see P0-1).

## vh-storage state (after Phase 1, 2026-10-01)

- Runs CI-built Phase 1 candidates (see `phase1-results.md`); `gdb` and `systemd-coredump` are installed for crash triage.
- `/etc/vaulthalla/testing/providers.env` (root:vaulthalla 0640) holds the TEST-ONLY S3/R2 scaffold, unfilled.
- The maintainer granted blanket mutation authority for Phase 1 work only; outside it, the rules below apply.
- sshd has no sftp Subsystem: use `ssh vh-storage 'cat > /tmp/f' < f` instead of `scp`.

## vh-storage safety rules

- **Wrap every command that might touch `/mnt/vaulthalla` in `timeout`.** When the daemon is wedged, `df`, `stat`,
  `ls`, and `mountpoint` block in uninterruptible FUSE wait, and even SIGKILL won't clear them.
  Use `df -x fuse.vaulthalla-fuse`, and `stat -f` (statfs) instead of `stat`.
- Read-only inspection (journalctl, systemctl status/show, dpkg -l, ps, /proc) is fine without asking.
- Installing packages, restarting services, running `vh setup/teardown`, touching PostgreSQL, killing
  processes, or running `dpkg --configure` all need the maintainer's explicit go-ahead in the current conversation.
- Use the `/lab` skill for standard procedures.
