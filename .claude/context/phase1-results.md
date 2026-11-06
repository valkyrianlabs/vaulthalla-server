# Phase 1 results: bombproof Debian packaging (2026-09-30 → 10-01)

Proven facts for Phase 2 to start from. Raw journal + evidence files: `.claude/scratch/phase1/` (gitignored).
Integration branch `phase1/hardening` → PR #124. Issues #97–#133 on the "Vaulthalla Roadmap" project.

## How things were proven

- **Candidates are CI-built.** Every fix was installed on vh-storage from a `release.yml` *dry-run* artifact
  (`gh workflow run release.yml --ref <branch> -f publish=dry-run`, then `gh run download`): same pipeline,
  same runner, nothing published. Local `.deb` builds aren't possible on the dev VM (private web icons live
  only on the CI runner).
- **Copying to the lab:** vh-storage's sshd has no sftp Subsystem, so modern `scp` fails. Stream instead:
  `ssh vh-storage 'cat > /tmp/x.deb' < x.deb` (`tools/lab/lab_smoke.py` does this; since 2026-10-02 candidates never go on vh-storage).
- **Crash diagnosis on the lab:** `systemd-coredump` + `gdb` are installed there. Shipped binaries are stripped;
  build `meson setup build-relg --buildtype=debugoptimized -Db_ndebug=false`, copy to
  `/usr/local/sbin/vaulthalla-server-debug`, point a `vaulthalla.service.d` `ExecStart=` drop-in at it, reproduce,
  `sudo coredumpctl gdb <pid>`. Remove the drop-in afterwards. (The CI toolchain matches dev: gcc 14.2.0,
  Boost 1.83, meson 1.3.2 per the artifact's `.buildinfo`.)
- **Lab tooling** (`tools/lab/`): `vhws.py` (ws client), `parity_smoke.py` (CLI↔web parity, 32 checks),
  `ws_churn.py` (connection churn; asserts same daemon PID), `test_providers.sh` (S3/R2 test-credential scaffold).
  Since #357/#359 the ws clients sign admins in with TOTP and answer step-up through `tools/lab/mfa.py`
  (`--totp-file` / `--admin-totp-file`, a 0600 TotpStore file; `vhws.py --enroll-totp` enrolls one; #395).
  Web: `web/tests/e2e/lab-first-run.spec.ts` (opt-in `VAULTHALLA_E2E_LAB=1`).

## Real-host matrix (vh-storage, Ubuntu 24.04.5, HW TPM, PG16, nginx, data disk at /var/lib/vaulthalla)

| Flow | Result on final candidate |
|---|---|
| Fresh install (Recommends present) | ok, ~5–13s; DB bootstrapped; nginx stock default site disabled + verified serving |
| Fresh install with PostgreSQL down | installs (ii), daemon intentionally not started, instruction printed; `vh setup db` later works and reports truthfully |
| Upgrade 1.5.1 → 1.6.6 (published) | **broken in published packages** (migration 060 checksum crash loop) → fixed (#98) |
| Upgrade over running / stopped / failed service | running: restarted; stopped: stays stopped; failed: started |
| Upgrade over published 1.6.6 with legacy `vaulthalla-cli.{socket,service}` | units stopped + purged, daemon owns `/run/vaulthalla/cli.sock`; config + providers.env byte-identical; config becomes an obsolete conffile |
| `apt remove` → reinstall | units restored enabled+active; data kept; nginx default site restored on remove, re-disabled on reinstall |
| `apt purge` with mounted data disk | ok; mount kept + emptied (root:root 0755); DB kept with post-purge psql commands; certbot creds + `/etc/vaulthalla/testing/` kept |
| Reinstall onto purged-but-kept DB | noninteractive: abort with exact `sudo env VH_EXISTING_DB_ACTION=adopt|overwrite dpkg --configure -a`; adopt keeps users/vault metadata (encrypted keys lost, JWT secret regenerated); overwrite = fresh DB |
| `dpkg-reconfigure` ×2 | idempotent; restores a deleted config.yaml from `/usr/share/vaulthalla/config/` |
| PostgreSQL restart ×5 under load | pool 4/4 healthy, FUSE waiting 0, same PID (P0-1 fixed) |
| Reboot | units back; data disk mounted before daemon; FUSE ok |
| Malformed / missing config | clean `cannot load config …: yaml-cpp: error at line N, column M` exit 1; StartLimit bounds retries |
| Web console over plain HTTP | Playwright first-run 3/3 (nginx serves console; default admin forced to change password; admin pages live) |
| CLI ↔ web parity | 32/32 (vault/group/user CRUD both ways, duplicate/missing rejected on both, #126 edit targeting) |
| ws churn (login/logout/abort/garbage/failed logins/sweeper) | 432 lifecycles @24 concurrent: no crash; latency limit at that load is #132 |
| Daemon ports | 36968–36970 loopback-only on fresh installs; LAN reaches only nginx :80 |

## Behaviors to know (new in this phase)

- Existing-DB resolution: `VH_EXISTING_DB_ACTION=adopt|overwrite|abort` (noninteractive default abort; empty DB auto-adopted).
- CLI exit codes: 69 no daemon, 75 timeout (`VAULTHALLA_CLI_TIMEOUT`), 76 bad reply, 77 socket permission; `vh status` 0/1/2.
- Session cookie `Secure` iff the browser-facing request was HTTPS (`X-Forwarded-Proto` from a loopback peer).
- Default admin `vh!adm1n` stays (maintainer decision) but the daemon restricts that session to password change.
  *Superseded in 1.8.0:* no universal default; a per-install generated password and no gate (see architecture.md).
- `auth.login` rate limit counts failures only (10/min, 30/15min per IP+account).
- Ownerless vaults (owner deleted) load as owner N/A; what deleting an owner *should* do is open (#133).

## Release pipeline facts

- Rulesets: `main` needs a PR with 1 approving review; release-tag creation is core-maintainer only (org admins bypass).
- `Production` environment has no protection rules (maintainer deferred adding a reviewer, #118).
- The AI changelog runs in `release-artifacts`, which has **no environment**: its key and profile must be
  repository-level (`VH_AI_RELEASE_DEEPSEEK_API_KEY` secret, `VH_AI_RELEASE_PROFILE=ds-flash` variable). Copies on
  the Production environment are not visible to it. v1.7.0 was the first release with hosted AI (DeepSeek
  `ds-flash`, strict json_schema, ~13 min).
- Nexus can take more than 2.5 min to list an upload in the APT index. v1.7.0's publish job timed out verifying,
  then passed on `gh run rerun --failed` (same SHA256, so the upload is skipped). The verify window is now ~10 min.
- **v1.7.0 shipped 2026-10-01** (run 36903232826). GitHub asset, `SHA256SUMS` and APT `Packages` all list
  sha256 `9287f3a5…`. `lab-smoke --from-version 1.6.6-1 --apt-version 1.7.0-1 --pg-restart --reboot` passed
  on vh-storage.
- Lab gotchas: putting published 1.6.6 back over a CI build with the same version label stops at a dpkg conffile
  prompt (config.yaml); finish with `dpkg --force-confold --configure -a`. Published 1.6.6 denies FUSE `getattr`
  to an unlinked Unix user, so the lab-smoke mount probe runs as root.
- `python3 -m tools.release run-tests` was the only test entrypoint CI used (superseded in 1.8.0 by vl-release and
  `tools/dev/verify.sh` `run_suite` floors).

## Debian/Ubuntu assumptions to exercise later (#120)

noble-only ABI (t64 names, libstdc++ ≥14, libfmt9, spdlog 1.12, repo libpqxx-7.10/libpdfium-2025) in one `stable`
suite; unversioned `nodejs` (Next 16 wants ≥20.9, noble ships 18.19); `postgresql@NN-main` + port 5432; DEP17 unit
paths; Ubuntu AppArmor swtpm paths; adduser/deluser semantics; needrestart; nginx `sites-*` layout; keyring path
drift (`/usr/share/keyrings` vs `/etc/apt/trusted.gpg.d`); APT signing key expires 2027-08-08 (#121).

## Open follow-ups

#118 (Production reviewer gate), #120 (distro matrix), #121 (APT key/keyring package), #122 (runner reproducibility),
#123 (unit binary > meson timeout), #125 (trust X-Forwarded-For for login limiter), #132 (single protocol io thread),
#133 (owner-deletion semantics). Phase 2: fill `/etc/vaulthalla/testing/providers.env` (see `testing.md`).
