# Phase 2 results (trustworthy CLI/web, v1.8.0 candidate)

Branch `phase2/trustworthy`, PR to `main`. What was proven, and how to re-prove it.

## Lab matrix (vh-storage, 2026-10-02, candidate `vaulthalla_1.8.0-1_amd64.deb` sha256 `359d35a0…`, CI run 37022678594)

| Flow | Result |
|---|---|
| Upgrade published 1.7.0-1 → candidate (`lab-smoke --from-version 1.7.0-1 --pg-restart --reboot`) | pass; candidate sha verified on host; config + providers.env byte-identical |
| Stopped-service upgrade 1.7.0 → candidate | stays stopped; starts healthy; installed `vaulthalla-server` matches the candidate's |
| `apt purge` with mounted data disk | mount kept + emptied (root:root 0755), FUSE unmounted, DB kept with removal instructions |
| Reinstall with `VH_EXISTING_DB_ACTION=adopt` | healthy, accounts kept |
| Fresh install (`VH_EXISTING_DB_ACTION=overwrite`) | healthy; daemon ports loopback-only, nginx :80 |
| Restart with an ownerless vault | healthy; vault listed with owner N/A |
| `parity_smoke.py` (now with the Phase 2 scenario set) | 71/71 |
| `ws_churn.py --rounds 12 --concurrency 6` | 288 connections, 0 client errors, same PID, no sweeper errors |

Candidate 1 (`ce05dc0f…`) showed nginx 502s exactly when the 30s session sweep ran: the sweeper closed sessions
still in their handshake (indexed at TCP accept, no tokens yet). Fixed in `ddc32949`; candidate 2 shows none.

The lab was returned to published 1.7.0-1 afterwards, so the release's own `lab-smoke --from-version 1.7.0-1`
starts from a published package (its apt options don't allow downgrades).

## Lab recipe on 1.8.0+

Operator for the parity smoke without the real admin password: `vh role admin create parity-op --from super_admin`,
`vh user create parity_operator --role parity-op`, keep the `^Password: ` line in a 0600 file, run
`tools/lab/parity_smoke.py --admin-user parity_operator ...`, then `vh user delete parity_operator --yes` (its vaults go
with it) and delete the role.

## S3/R2

- **R2: live.** `core/tests/unit/test_S3Provider.cpp` runs against Cloudflare R2 when `VAULTHALLA_TEST_R2_*` is set; the
  dev VM's `deploy/vaulthalla.env` (and the project `.bashrc`) carry those test credentials, so every local full-suite
  run exercised R2: credential validation, upload/download/list/delete, multipart and abort, unicode keys, encrypted
  metadata, bucket-empty checks (11 tests). CI skips them: the credentials aren't configured there.
- **AWS S3: not exercised yet**, deliberately (maintainer: R2 first, AWS later). Only SES credentials exist.
- The lab's `/etc/vaulthalla/testing/providers.env` is still placeholders; a packaged-host R2 run needs it filled.

## Open after Phase 2

- #133 is resolved on this branch: deleting an account asks first and transfers or destroys its vaults.
- Vault/API-key resolver scopes still classify owners with `User::isAdmin()` (a strict "full admin" predicate also used
  as a gate for S3 policy bypass; system stats moved to `admin.stats.view` in #166); account management uses
  `ops::users::isAdminIdentity`.
- Fixed: every account had an empty global vault policy (one all-zero `self` row in `user_global_vault_policy`):
  `VaultGlobals`' default constructor labelled all three scopes `self`, and roles loaded from `admin_role` carry no
  preset. Only the super admin (who bypasses the check) could use vaults through the global policy, which is why the
  gateway bucket list (it follows filesystem rights) came back empty. Accounts on a built-in role now start from its
  preset, and `seed::reconcileGlobalVaultPolicies` repairs existing ones at startup.
- Decided (maintainer, 2026-10-02): `--from` (CLI) or the web's **Start from** list only seeds a new role's fields;
  once saved the role owns its bitmasks, with no inheritance chain. No `--from` starts from `unprivileged`. Global vault
  policy is per account and is seeded when a role is assigned: a built-in role seeds its preset, a custom role seeds
  `Admin::None(userId)`. `admin_role` stores no global vault policy, by design.
- Fixed: stopping the S3 gateway (and the HTTP preview service) freed its io_context while a pool-thread session could
  still be closing its socket (ASan heap-use-after-free in `S3GatewayServiceTest`). Sessions are now registered at
  accept, cancelled after the io threads join, and the context is freed only once every session object is gone
  (`protocols/SessionLifetimes.hpp`); past a 10s deadline it is kept for the process lifetime and an error is logged.
- `make run_test` is 71/72 on this branch and on `642b02b4` alike: "FUSE deny: ls seed" gets EACCES where it expects
  ENOENT (an unprivileged user is denied below the vault root instead of the root looking missing). The other deny
  cases hold. Root-caused 2026-10-09 (#170): the kernel dentry cache is shared across uids, so right after the admin
  seeded the tree the denied user's `ls` skipped LOOKUP of the vault root and the daemon first saw readdir on `seed`
  (or getattr), which answered EACCES. Fixed by `fuse::resolver::deniedErrno` (hidden = ENOENT for every op); see architecture.md, FUSE.
- Replaced (2026-10-02): the universal default password `vh!adm1n` and its gate. The gate was split-brained: the ws
  Router refused every non-allowlisted command for *any* session whose own password verified against the default,
  while the web's RequireAuth asked an unauthenticated lifecycle command whether the *admin* account had it and
  redirected everyone to `/users/admin/change-password`. Pages that loaded anything beyond the allowlist got
  `password_change_required` errors, which surfaced as logouts or hangs. Now: a per-install generated password, a
  plaintext file under `/var/lib/vaulthalla`, `vh setup set-super-admin-password`, an advisory web warning and a
  `vh setup nginx` safeguard. See architecture.md "Super-admin initial credential".
- ws-only endpoints that kept their own authorization: pricing preflight/overrides/notifications, email test-send and
  history.
- Revocation that races a session's in-flight request reads token fields off the strand (pre-existing for CLI-driven
  revocation; more threads make it likelier).
