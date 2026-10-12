# Testing and local verification

## Surfaces → proof

| Changed | Minimum proof | Stronger proof |
|---|---|---|
| `core/**` C++ | `meson compile -C build` (unity build) | `meson test -C build --print-errorlogs` (unit, DB-backed), `make proof` (Tier A, private instance), `tools/harness/vhh.sh run --target launch` (Tier B) |
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

## Integration proofs (Tier A, preferred for FUSE / CLI end-to-end)

```bash
make proof                      # = bash bin/tests/run_proof.sh (needs sudo; never touches the dev install)
VH_TEST_CONFIG=default VH_TEST_SEED=0x... bash bin/tests/run_proof.sh --build-dir build
make proof-selftest             # negative controls + fail-closed env checks
```

`core/tests/integrations/main.cpp` (`vh_integration_tests`) runs in-process against a **private** instance: a per-run
database owned by the harness role `vh_harness`, `/tmp/vhh_proof_<run>/` paths, its own FUSE mount. It refuses to
start (exit 78) without a complete private environment (`runtime/TestInstance.hpp`); `VH_TEST_LEGACY_SHARED_ENV=1`
(set by `bin/tests/install_core.sh`, i.e. `make run_test`) keeps the old shared env. Last results (2026-10-11):
minimal 102/102, default 270/270 (seed 0x8f86ba60a0e5ccba; it caught the admin-role deletion defect fixed in bf56dec3).
- Seeds: `VH_TEST_SEED` (printed in the header, summary and reports); per-test BLAKE2b-64 streams, so a seed
  reproduces the same command lines. `VH_TEST_SEED_THREADS=1` for exact DB-id repro.
- Knobs: `VH_TEST_CONFIG` (minimal|default|medium|large), `VH_TEST_STAGES`, `VH_TEST_NEGATIVE_CONTROL=assertion|oracle`
  (must fail), `VH_TEST_UID_BASE` (default 2100000000; `users.linux_uid` is a signed INTEGER), `VH_TEST_FS_OP_TIMEOUT_MS`.
- Reports: JSON + JUnit in `<build>/proof-artifacts/<run>/`. Exit non-zero on any failure or zero tests.
- Filesystem probes go through `vh_fs_actor` (`core/tests/helpers/fs_actor.cpp`, built with `-Dintegration_tests=true`):
  posix_spawn'd per uid, JSON lines, per-op deadline, fusectl abort of the run's own mount on a wedge.
- Integration is no longer a meson `test()`.

## Integration engine (Tier B, `tools/harness`)

Out-of-process, against a private daemon instance (`vaulthalla-server` with `VH_TEST_MODE=1`). One engine, two intent
sources: seeded planners and external agents (fake-agent gateway in `vhh/gateway.py`), sharing the operation catalog,
identity broker, guardrails, recorder and judges. Design: `~/VAULTHALLA_INTEGRATION_HARNESS_AUDIT.md`.

```bash
sudo tools/harness/bootstrap.sh                                    # once: venv, vh_harness role, vhh-actor-NN accounts
sudo tools/harness/vhh.sh run --target launch --build build --seed 0x2a --sessions 8 --ops 30 \
     --surfaces ws,fuse --schedule barrier                         # launch, provision pentest-v1, run, tear down
sudo tools/harness/vhh.sh replay --target launch --build build --trace runs/<run>/trace.jsonl --window 15..30
sudo tools/harness/vhh.sh shrink --target launch --build <fault build> --trace ... --predicate oracle --out x.jsonl
sudo tools/harness/vhh.sh regress --build build                    # every tools/harness/regressions/*.jsonl must not reproduce
sudo tools/harness/vhh.sh scenario hang|crash --build build        # daemon stopped/killed with a FUSE op in flight
tools/harness/vhh.sh world oracle-check                            # RBAC model vs the fixture's 59 expectations
bash tools/dev/verify.sh harness                                   # unit + self tests (CI tooling job)
```

- Every failed run prints a one-line `reproduce with:` command; artifacts hold `trace.jsonl` (redacted), `summary.json`,
  `instance/` (daemon log, target.json, evidence on wedges, sanitizer logs) and `instance.json`.
- Surfaces: `ws` (the console: ws for metadata, HTTP lanes for bytes), `fuse` (vh_fs_actor per actor account),
  `cli_sock` / `cli_bin` (real peer uid via the `vhh-actor-NN` accounts). Admin-side provisioning reuses the pentest
  `Seeder` against the private socket.
- Judges: oracle (RBAC model, revocation grace window), parity (same probe across surfaces), canary, integrity
  (deterministic content), liveness/wedge, unexplained errors, harness faults. Any harness fault, unexplained error,
  daemon death, unclean stop, sanitizer report or zero executed ops fails the run.
- Replay reproduces the op sequence and overlap, not the daemon's internal thread interleavings; use `barrier`,
  `--repeat` and a TSan build for races.
- Fault fixtures (`tools/harness/faults/*.patch`, `build.sh <fault>` builds a throwaway worktree): libmagic race,
  stale revocation, ws list without RBAC. The ws list fault is caught (oracle) and shrinks to one op.
- Lessons: the engine never touches the mount itself (a `Path.resolve()` blocked it in D state under a stopped
  daemon); `Instance.watchdog()` aborts the run's own FUSE connection past a hard deadline.
- Never point mutating commands at vh-storage: targets are validated (a live `VH_TEST_MODE=1` daemon serving a
  `vh_harness_*` database), anything else fails closed.

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
