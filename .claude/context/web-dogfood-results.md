# Web console overhaul: dogfood results (2026-10-03/04)

Branch `web-overhaul`. Plan: `.claude/scratch/web_overhaul/goal.md` (Phase A overhaul, Phase B dogfood). Board: epics
#155 (overhaul, sub-issues #137–#154) and #156 (dogfood).

## Where it ran

- **Local dev VM, source dev install** (daemon 1.8.0, MST PostgreSQL), nginx with a self-signed cert on
  `https://localhost`, the new console from a production build (`next start` on 36968). First pass, 2026-10-03/04.
- **Local dev VM, packaged upgrade** (2026-10-04): the dev install wiped (`make uninstall`), **released 1.8.0 from
  apt.vaulthalla.sh**, seeded (MST timestamps, a FUSE tree), then **upgraded to the candidate `.deb`** built from the
  branch with `make deb`. Console on `http://localhost` through the package's nginx site. Dev mode is off here, which
  matters: dev installs skip the daemon's `/auth/session` check.
- `make run_test` (integration harness): 71/72, the one known pre-existing failure (#170).
- **Not run yet:** the lab (`vh-storage`): real apt only, after a release; Firefox / iOS Safari passes.

## Packaged upgrade (1.8.0 → candidate)

- The upgrade takes 16 s: config preserved, DB reused, units restarted, nginx verified. Migrations 099–102 are
  applied; all 97 naive `timestamp` columns are now `timestamptz`; users created at 14:52 UTC that 1.8.0 stored as
  07:52 read 14:52 UTC; `s3_api_key_id_fkey` is RESTRICT; the share-upload parent FK is SET NULL; `password_changed_at` exists.
- **Found and fixed:** the deployer ran migrations in the daemon's UTC session, so rows written earlier in the same
  deploy (099's `schema_migrations` row on upgrade; every 000–099 row and their seed data on a fresh install) were
  shifted +7 h by migration 100. `SqlDeployer::applyDir` now runs in the database's own zone (transaction-local);
  `DbTimezoneTest.RowsWrittenEarlierInTheSameDeployAreNotShifted` fails without it.
- FUSE on the new daemon: renaming a directory with siblings works (the #158 EIO path), moves/deletes keep
  directory totals. Reinstalling the same candidate and a second clean 1.8.0 → candidate cycle were also clean.
- **Found and fixed:** every console page waited ~2.5 s and the route sweep hung. Next strips `Next-Router-Prefetch`
  before middleware runs, so "skip prefetches" never matched: each prefetch (5–9 per page) cost a ~0.57 s
  password-hash verify in the daemon, and they queued past the middleware's 2.5 s timeout. Middleware now checks only
  `Sec-Fetch-Dest: document` loads. Superseded by the #171 fix: the middleware now only checks that the refresh
  cookie exists (guard: console e2e "middleware only checks for a refresh cookie").
- **Found, not fixed (filed):** #173 (P0) FUSE serves ciphertext for web-uploaded and renamed files and reports wrong
  sizes after a restart (pre-existing: FUSE never decrypts, `createFile` and the rename slow path encrypt); #171 every
  refresh-token check is a password-hash verify, so a full page load still spends ~1 s on it; #172 the cost-alerts
  bell fetches up to 50 alerts (~12 KB) on every page.
- Unexplained, once: right after the first upgrade the HTTP server (36970) wasn't listening while ws (36969) was.
  It didn't recur across a restart, a reinstall and a second clean install/upgrade; nothing was logged.

## Suites (all in `web/tests/e2e`, run against `https://localhost`, production build)

| Suite | Result |
|---|---|
| `console.spec.ts` route sweep (17 routes: no page/console errors, no endless loading, no denial for a super admin) | pass |
| redirects from every old console URL | pass |
| file lifecycle: folder, upload incl. `naïve résumé (1) #hash %20.txt` and a dotfile, F2 rename, preflighted download, copy/move, URL path + reload/back, confirmed delete | pass |
| multi-item drop (5 files through Chrome's native drag events) | pass |
| logout hygiene (no `vaulthalla-*` storage, `/files` → login) | pass |
| share links: recipient browses a folder link; dropbox link is upload-only and the upload arrives | pass on the candidate (cleanup failed on 1.8.0: the share_upload FK bug fixed by migration 101) |
| ws bootstrap ≤ 20 KB on `/files` + no stats polling after leaving `/health` | pass on the candidate (`auth.refresh` 6 KB, was 13 KB+ on 1.8.0); fails when 50 open cost alerts pile up (#172) |
| only page loads pay the upstream session check | pass on the candidate |
| `personas.spec.ts`: unprivileged user, plain `admin` role, inactive user | pass |
| `s3-gateway.spec.ts` (13 tests) | pass; now deletes the vaults it creates (it left five per run) |
| `pnpm budgets` (34 routes, hard CI gate) | pass |
| core unit suite (DB-backed) | see the PR's validation for the final run |

## Bugs found while dogfooding (fixed on this branch)

- Selecting a row inserted the selection bar above the list and pushed rows down, so a double-click opened the
  folder above (fs). Fixed: the bar overlays the toolbar.
- Native checkbox glyph in a Tailwind class broke `tailwind-merge`; checked boxes looked empty. Fixed (CSS class).
- Two `router.replace` calls in a row dropped the second in production builds, so S3 gateway / cost tabs stopped
  switching. Fixed: `replaceQuery()` (history.replaceState).
- Share-dialog role templates filtered on a `type` field vault roles don't carry; nothing was selectable. Fixed.
- Folder that received a share upload couldn't be deleted (raw FK violation shown to the user). Fixed in core
  (migration 101).
- Session payload ~13 KB of permission descriptions on every page load. Fixed in core (slim session user).

## Bugs found and filed (open)

Fixed on this branch (with regression tests): #157 timestamps off by the UTC offset (UTC sessions + migration 100) ·
#158 directory totals on move/rename/copy/delete (also: renaming a directory with siblings failed with EIO; ancestor
chains loaded in the wrong order; empty directories survived delete) · #159 overview severities (unknown is never
healthy; oldest_tx excluded the stats query's own transaction; expected errnos don't warn) · #161 every vault
reported the shared backing root's size — and quota enforcement charged every vault for all the others · #163
`password_changed_at` stored (migration 102, trigger on password_hash).
#171: refresh tokens are stored as a `sha256:` digest (legacy Argon2 rows verify once and are rewritten), and the
middleware only checks that the refresh cookie exists, so a page load no longer pays a ~0.57 s verify (twice).
#168 (decided: keep folders): deleting a file never removes its parent folders, from the console, the mount, the
gateway or sync; FUSE rmdir of a non-empty folder is ENOTEMPTY. #167: `fs.entry.copy` copies a folder's whole subtree,
and every copied file is readable at once at the alias backing layout (sealed bytes copied with their IV), checked per
entry (Copy + Read on the source, Write/Touch at the destination) and against the quota. See architecture.md,
"Delete keeps folders; copy is deep".
#165: `s3.gateway.credentials.*` ws handlers read only explicit ids (`credential_id`, `override_id`,
`permission_id`); a payload carrying a bare `id` is refused with `data.code: "invalid"` naming the expected field.

#160, #162, #164, #166, #167 and #168 are fixed on `fix/decision-bugs` (see architecture.md: "Safe vault deletion
with retention", "Delete keeps folders; copy is deep", and the stats/sharing sections).

Still open: #170 harness `FUSE deny: ls seed` · #172 cost-alerts bell payload · **#173 FUSE serves
ciphertext for web-uploaded/renamed files (P0, decision on the local at-rest model)**.

`make run_test` ran on 2026-10-04: 71/72, the known `FUSE deny: ls seed` EACCES/ENOENT case (#170), as in Phase 2.

## How to re-run

On a packaged install use `VH_BUILD_MODE=dev bash tools/e2e/provision_e2e_user.sh --force` and
`VAULTHALLA_E2E_BASE_URL=http://localhost` (the package's nginx site is HTTP). Each run's `globalSetup` provisions a
fresh e2e user (`--fresh-user`), so users accumulate across runs. The e2e user is an admin, so provisioning also
enrolls its TOTP factor over the daemon's ws (#405; needs Python with `websockets`: `VAULTHALLA_E2E_PYTHON`, and
`VAULTHALLA_E2E_WS_URL` when the daemon's ws isn't where the console settings say).

```bash
bash tools/e2e/provision_e2e_user.sh                                  # local dev DB only
cd web && pnpm build && PORT=36968 node_modules/.bin/next start --hostname 127.0.0.1 --port 36968   # behind nginx
VAULTHALLA_E2E_BASE_URL=https://localhost VAULTHALLA_E2E_NO_WEB_SERVER=1 \
  pnpm exec playwright test tests/e2e/console.spec.ts tests/e2e/personas.spec.ts tests/e2e/s3-gateway.spec.ts
```

Use a production build: React StrictMode doubles every request under `next dev`, which breaks the ws budget test.
