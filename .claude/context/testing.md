# Testing and local verification

## Surfaces → proof

| Changed | Minimum proof | Stronger proof |
|---|---|---|
| `core/**` C++ | `meson compile -C build` (unity build) | `meson test -C build --print-errorlogs` (unit, DB-backed), `make run_test` (integration harness) |
| `web/**` | `pnpm --dir web typecheck && pnpm --dir web lint` | `pnpm --dir web build` (needs private icons), Playwright `pnpm --dir web test:e2e` |
| `release.toml`, `.release/`, `VERSION`, version targets | `vlr check && vlr version check` | `make deb` (local release rehearsal: prepare + build + validate in a worktree of HEAD) |
| `debian/**`, `deploy/systemd`, `deploy/psql` | `bash tools/dev/verify.sh packaging` (`tools/contracts`) | `make deb`, then install it on the dev VM (never on vh-storage; `/lab`) |
| `deploy/lifecycle/**` | `bash tools/dev/verify.sh lifecycle` | a dev VM `vh setup …` run |
| `docs/**` | `python3 .claude/skills/payload-markdown/scripts/check_payload_markdown_doc.py <files>` | `pmdocs validate --source docs` |
| `bin/**` shell | `bash -n <script>` | a real `make test` / `make dev` cycle, after asking first |

`bash tools/dev/verify.sh <profile>` wraps the common profiles. See the `/verify` skill.

## Build dirs

- `build/`: the working dev build (`meson setup build -Dbuild_unit_tests=true`; the default buildtype is `debug`,
  i.e. -O0, which is what PR CI builds and tests with `-Dwerror=true`). `make clean-full` wipes the build dirs.
- Compile-time layout: unit-test objects are their own `vh_unit_test_objects` target ahead of the library (ninja
  starts them first), always -O0, linked whole into `vh_unit_tests`. -O0 compiles use precompiled headers
  (`core/pch/`): tests always, the library only when the buildtype is -O0. Optimized builds never use a PCH: GCC
  drops `#pragma GCC diagnostic`/`push_options` state across one (see the header comments).
- `make build` is **broken**: it calls `conan install . -r vaulthalla` but there is no conanfile. Use meson directly.
  `run-test` is declared `.PHONY` in the Makefile but has no recipe. Use `run_test`.
- **Zero-warning bar (2026-10-04):** the tree builds with no output but `[n/N]` progress at `-O3 -Werror`, both unity
  (`meson setup build-o3 -Dbuildtype=release -Dwerror=true -Dbuild_unit_tests=true -Dintegration_tests=true`) and
  per-file (the same plus `-Dunity=off`; `core/meson.build` forces `unity=on` on `lib_usage_native`, so drop that
  override in a scratch copy). Unity hides missing includes; check per-file before calling a warning fix done. The
  one suppression is `core/include/compat/gcc_variant.hpp` (force-included for GCC): a libstdc++ `<variant>`
  `-Wmaybe-uninitialized` false positive reached through `pqxx::params`. Fix warnings at the source; don't add flags.

## DB-backed unit tests

- **Teardown hazard:** `make test`/`make run_test`/`make uninstall` run `bin/tests/uninstall_db.sh`, which executes
  `DROP OWNED BY vaulthalla_test` in *every* database before dropping the role. A burner DB created with
  `-O vaulthalla_test` (the usual way to give tests their own DB) is emptied, and the role drop then fails. Don't run
  those targets while a burner owned by that role is in use; `install_db.sh` also rotates the role's password.

1. `make test`. It uninstalls the test env, creates the test DB role and DB, and rewrites the generated `VH_TEST_DB_*`
   credentials into the ignored `deploy/vaulthalla.env`.
2. `set -a; source ./deploy/vaulthalla.env; set +a`
3. `./build/core/vh_unit_tests --gtest_filter='<Filter>'`

CLI ↔ ws parity for families migrated to `core/ops/`:
`--gtest_filter='*Parity*:OpsGroups*:AuthPasswordChange*'` (groups, roles, API keys, vaults, users, S3 gateway,
pricing/config, sync conflicts). The whole binary takes ~7 minutes against a local DB; meson's test timeout is 30 minutes (#123). A parity case
runs one logical operation through `shell::Router::executeLine` and through the ws handler, for every seeded admin
role, and compares allow/deny (against an oracle from the role's permission bits) and resulting DB state, never text.
New families add a `test_ops_parity_<family>.cpp` on the same pattern.

Don't assume the shell `.bashrc` has current credentials. **Never print or commit secret values.** If you hit DB auth,
stale secrets, or port conflicts: `make uninstall` → `make test` → re-source.

## Rich-preview / HTTP suites

| Suite (file) | Covers | Needs |
|---|---|---|
| `GcmCtrDecryptAt`, `GcmFileReaderTest`, `GcmStreamVerifier`, `GcmOneShot`, `EncryptionManagerKeys`, `EngineReader`, `HttpRange` (`test_gcm_range_reader.cpp`) | CTR positioning at every block boundary vs authenticated decrypt, OpenSSL/libsodium interop, AAD/tag/body tampering (optimistic + strict), supersession, shared verification, key snapshots during rotation, the RFC 9110 range parser | nothing (DB-free) |
| `HttpArchiveZip`, `HttpArchiveSessionTest` (`test_http_archive.cpp`) | streamed folder ZIP validated by Python `zipfile` + `unzip -t` (`tests/helpers/zip_check.hpp`; skip without them): UTF-8/dot names, empty file, empty dir, exact length, one member open at a time, integrity failure truncates before the CRC, size drift aborts, zip-slip names, ZIP64 (> 4 GiB member as a sparse file, ~25 s; > 65535 entries), and over a socket: HEAD length without opening members, disconnect, stalled client | nothing |
| `HttpSessionTest` (`test_http_session.cpp`) | socket-level streaming, client disconnect stopping work, stalled/idle deadlines, HEAD framing | nothing |
| `HttpAccessDbTest` (`test_http_access.cpp`) | human preview/download RBAC matrix, no path-existence oracle, D9 (SVG/WebP not Preview), Range/conditional/HEAD, 300 MiB download, folder ZIP of encrypted files (RBAC, HEAD, independent validation, tampered member truncates), text save 428/412/422/413/415/403 + ciphertext-only on disk, PDF paging, hostile size/scale/page, no `/tmp` plaintext residue | test DB env |
| `HttpSharePreviewTest`, `HttpContentDisposition` (`test_http_share_preview.cpp`) | share lanes (Preview vs Download, Content-Disposition), `max_downloads` per logical download (files and folder ZIPs; HEAD never counts), scoped folder ZIP entries | nothing (injected fakes) |
| `PreviewStoreDbTest` (`test_preview_store.cpp`) | `VHDERIV1` round trip (ciphertext only on disk), identity/AAD binding, invalidation by source id and generator version, negative cache TTL, writer limit, LRU eviction, legacy-thumbnail sweep, not charged to quota, purge, one-shot `read` (page count, tamper drops the artifact), index-only `status`, batched `last_accessed`, orphan-file sweep | test DB env |
| `IdentitiesManagerDbTest`, `IdentitiesDetached` (`test_identities_manager.cpp`) | canonical objects (held pointers see admin updates, memberships, group roles, overrides, role templates), deactivation/deletion tombstones, failed writes, stale reads never win, out-of-band SQL via `reconcile()`, coherent user+group views, concurrent writers/readers, zero DB loads on warm lookups, no password hash in state | test DB env; run under TSan too (below) |
| `DeriveRunnerTest`, `PreviewConfigTest` (`test_derive_runner.cpp`) | Runner against `vh_fake_derive_helper` (range pulls, caps, timeout, crash, RLIMIT_AS, fd/env hygiene), `preview.*` parsing | nothing |
| `PreviewCadHelperTest`, `PreviewMediaHelper`, `PreviewMediaBrowser` | the real helpers via the protocol | skip when the helper isn't built (media also skips without the `ffmpeg` CLI) |
| `KeyRotationSafetyTest` (`test_key_rotation_safety.cpp`) | crash/failure-safe rotation, seam-injected | nothing |
| `SyncConflictsTest`, `SyncConflictBaseline` (`test_sync_conflicts.cpp`), `ConflictParityTest` (`test_ops_parity_conflicts.cpp`) | #187: `ask` records a two-sided conflict once and syncs one-sided changes, converges on its own, keep_local / keep_remote through an in-memory bucket (`tests/helpers/sync_conflict_harness.hpp`: fake controller + real passes run inline), stale refusals, RBAC (no permission, no Overwrite, vault role, admin via vault globals), vault-role and group-role sync permissions through the shared resolver (#189), keep_remote/keep_newest not re-downloading an in-sync file (#190), the `/download/conflict` lane, CLI vs ws for every seeded admin role | test DB env |
| `VaultRetentionTest` (`test_vault_retention.cpp`) | safe deletion (#162): schedule → restore, purge after the window (injected pass clock), delete now, resumed purge, key tombstone + expiry, S3 key-loss gate, bounded upstream purge (fake controller), shared-bucket guard, path guard | test DB env |

- **ThreadSanitizer** for the identity publication code: `meson setup build-tsan -Db_sanitize=thread
  -Dbuild_unit_tests=true -Db_lundef=false && ninja -C build-tsan core/vh_unit_tests`, then run with ASLR off (TSan
  aborts with "unexpected memory mapping" on this kernel otherwise): `setarch -R ./build-tsan/core/vh_unit_tests
  --gtest_filter='Identities*'`. Don't run two DB-backed test processes at once: each suite drops and recreates the
  test schema.
- Tests that write identity or role rows with raw SQL must call `identities::manager().reconcile()` afterwards (the
  revision watcher does it in the daemon) or the canonical objects they read keep the old state.
- Tests that run helpers under `RLIMIT_AS` (`DeriveRunnerTest`, the helper suites) need a **non-sanitized** build:
  ASan reserves far more address space than the limit allows, so a sanitized helper can't start.
- `bench_http_paths.cpp` holds `DISABLED_HttpBench*` benchmarks (256 MiB download TTFB/throughput/peak RSS, 192 MiB
  folder ZIP HEAD/TTFB/peak RSS, 4 concurrent downloads, 1 MiB range at 200 MiB, HEAD vs GET, 12 MP preview cold/warm, thumbnail generation). Run with
  a release build and the test DB env:
  `./build-o3/core/vh_unit_tests --gtest_also_run_disabled_tests --gtest_filter='DISABLED_HttpBench*'`. The same file
  compiles against the pre-rich-preview tree with `-DVH_BENCH_LEGACY` for like-for-like numbers.
- `tools/dev/bench/vhbench.py` (`seed` / `run` / `compare`, dev VM only) measures what FUSE operations, preview grids,
  PDF pages and imports cost the live daemon as admin and as the non-admin `bench_user`: PG transactions, per-statement
  counts/time/buffers via `pg_stat_statements` (enabled on the dev VM's PostgreSQL 16 by
  `/etc/postgresql/16/main/conf.d/90-pg-stat-statements.conf`, extension created in `vaulthalla`), daemon CPU and
  latency. Swap a package-flag server into the dev install to compare against the apt build.
- Web: `web/tests/e2e/preview.spec.ts` (Playwright) drives plans, image/PDF paging, ranged video/audio, text
  edit/412 conflict, markdown safety, 3D models, the lazy Babylon chunk and preview-only vs download share links
  against a running install behind the reverse proxy (fixtures from `tests/e2e/fixtures/preview/generate.mjs`; see
  `web-client.md`).

## Integration harness (preferred for FUSE / CLI end-to-end)

```bash
make uninstall && make clean-full && make run_test   # destructive to local dev/test state
```

This runs `core/tests/integrations/main.cpp` in test mode: it wipes, inits, and seeds the DB, starts FUSE + shell, and runs the CLI and FUSE suites
against **`/tmp/vh_mount`**. The last known result was 97/97 (2026-10-10, `fix/decision-bugs`: #143 #162 #164 #166 #167 #168 #187). It's isolated from systemd/prod state.
The "Copy And Delete" stage (#167/#168, 14 cases, runs unprivileged too) copies a nested folder over ws
`fs.entry.copy` and reads every copied file through FUSE and through `/download` (in-process `http::Router`), then checks
that unlink / `fs.entry.delete` keep folders and that rmdir of a non-empty folder is ENOTEMPTY; with it the expected
total is 97.
If `apt-get update` fails in `bin/setup/install_deps.sh` on an unrelated host apt source (e.g. a Caddy Cloudsmith
`402 Payment Required`), run the remaining steps directly: `bin/tests/uninstall.sh`, `bin/setup/install_users.sh`,
`bin/tests/install_dirs.sh`, `bin/tests/install_db.sh`, `bin/tests/install_core.sh --run`.

## Production-style mount dogfooding (`/mnt/vaulthalla`)

Only use this when the prod mount is specifically what's under test. `make dev` (a working-tree install; `bin/vh/install.sh` installs
the *apt* package, not your checkout) → `id -nG | grep -qw vaulthalla` → `vh setup assign-admin`. If the
`vaulthalla` group was created after your shell started, CLI failures are environmental; start a new login.
Dev mode requires both `VH_BUILD_MODE=dev` and the gitignored `enable_dev_mode` sentinel (`bin/lib/dev_mode.sh`).

## Other harnesses

- `tools/smoke/s3_gateway_{e2e,merge_ready,scoped_budget_smoke}.sh`: S3 gateway smoke runs against a live install.
- `tools/e2e/{load_env.sh,provision_e2e_user.sh}` + `web/tests/e2e` (Playwright).
- `tools/dev/share_preview_smoke.mjs`: public share preview smoke.
- Real R2 dogfooding writes to the real `vaulthalla-test` bucket. Use a unique prefix, clean it up, and check that
  `.vaulthalla/index-v1.json` isn't left stale.

## Known test gaps

- Copying a cloud file with no local copy (hydrate-then-copy in `Filesystem::copy`) has no test: `FsCopyDbTest`
  covers local vaults, and the cloud fakes in `test_cloud_remote_read.cpp` are DB-free.
- DB-backed suites share the process-wide `runtime::Deps` (fs cache, storage engines) across schema resets, so ids
  reused by a later suite can hit an earlier suite's cached entries. `FsCopyDbTest` installs a fresh cache and reloads
  engines in `SetUpTestSuite`; copy that if a suite drives ws handlers that reach the sync controller.

- Web has no unit runner (`pnpm test` is typecheck + lint only).
- Stats: `StatsAccessTest` covers who may read stats, the overview payload contract and that 24 h trends come from the
  rollups; there are still no seeded DB tests for the other stats rollups or share stats. No operator-email dedupe, digest scheduler, or security-enqueue tests.
- DB loss/reconnect and pool exhaustion: `DBPoolReconnectTest` (`test_db_pool_reconnect.cpp`) kills pool backends
  with `pg_terminate_backend` (never restart the shared system PostgreSQL). Its unreachable-DB case needs a
  non-superuser test role that owns its DB, and skips otherwise. A burner DB works:
  `sudo -u postgres createdb -O <role> claude_burner_*`, then drop both afterwards.
- The full `vh_unit_tests` binary against a real DB runs about 230s (S3CostSafety plus S3GatewayDb take about 185s),
  so `meson test` hits its 120s timeout. Run `./build/core/vh_unit_tests` directly for the DB-backed run.

## Provider test credentials (Phase 2 scaffold)

- Canonical file: `/etc/vaulthalla/testing/providers.env` (root:vaulthalla 0640, dir 0750). Operator-managed and TEST-ONLY:
  dedicated S3 + R2 buckets with bucket-scoped keys. The package never ships, reads, rewrites or deletes it (upgrade and
  purge leave it; contract-tested), and the daemon never loads it.
- Template + tooling: `tools/lab/providers.env.example` (placeholder `CHANGE_ME` values; variable names are the
  `VAULTHALLA_TEST_{S3,R2}_*` ones core tests and `tools/smoke` already read, plus `VAULTHALLA_TEST_PROVIDER_PREFIX` /
  `VAULTHALLA_TEST_PROVIDER_DESTRUCTIVE` safety rails). `bash tools/lab/test_providers.sh install|check [--host vh-storage]`
  creates the scaffold without overwriting and reports set/placeholder/missing per variable, never values.
- Harness wiring: `tools/e2e/load_env.sh` sources it when readable (override path with `VH_TEST_PROVIDERS_ENV`). Run
  provider harnesses as a `vaulthalla`-group user or via sudo. Installed on vh-storage 2026-09-30 (unfilled).
- Guard: `python3 -m unittest tools.lab.tests.test_provider_scaffold_contract`.
