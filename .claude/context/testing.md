# Testing and local verification

## Surfaces → proof

| Changed | Minimum proof | Stronger proof |
|---|---|---|
| `core/**` C++ | `meson compile -C build` (unity build) | `meson test -C build --print-errorlogs` (unit, DB-backed), `make itest` (Tier A, private instance), `tools/harness/vhh.sh run --target launch` (Tier B) |
| `web/**` | `pnpm --dir web typecheck && pnpm --dir web lint` | `pnpm --dir web build` (needs private icons), Playwright `pnpm --dir web test:e2e` |
| `release.toml`, `.release/`, `VERSION`, version targets | `vlr check && vlr version check` | `make deb` (local release rehearsal: prepare + build + validate in a worktree of HEAD) |
| `debian/**`, `deploy/systemd`, `deploy/psql` | `bash tools/dev/verify.sh packaging` (`tools/contracts`) | `make deb`, then install it on the dev VM (never on vh-storage; `/lab`) |
| `deploy/lifecycle/**` | `bash tools/dev/verify.sh lifecycle` | a dev VM `vh setup …` run |
| `docs/**` | `python3 .claude/skills/payload-markdown/scripts/check_payload_markdown_doc.py <files>` | `pmdocs validate --source docs` |
| `bin/**` shell | `bash -n <script>` (and `/bin/bash -n`: 3.2 on macOS), `tools/contracts/test_dev_instance_contract.py`, `bin/tests/kill_dev_artifacts_classifier.sh` | `make dev-plan` (macOS, prints every privileged step); `make test` / `make itest` (isolated); a `make dev` cycle only after asking |

`bash tools/dev/verify.sh <profile>` wraps the common profiles. See the `/verify` skill.

## Build dirs

- `build/`: the working dev build (`meson setup build -Dbuild_unit_tests=true`; the default buildtype is `debug`,
  i.e. -O0, which is what PR CI builds and tests with `-Dwerror=true`). `make clean-full` wipes the build dirs.
- Compile-time layout: unit-test objects are their own `vh_unit_test_objects` target ahead of the library (ninja
  starts them first), always -O0, linked whole into `vh_unit_tests`. -O0 compiles use precompiled headers
  (`core/pch/`): tests always, the library only when the buildtype is -O0. Optimized builds never use a PCH: GCC
  drops `#pragma GCC diagnostic`/`push_options` state across one (see the header comments).
- `make build` is **broken**: it calls `conan install . -r vaulthalla` but there is no conanfile. Use meson directly.
  Tests never use `build/`: they build `build-itest/` (pinned options, configured only when they differ).
- **Zero-warning bar (2026-10-04):** the tree builds with no output but `[n/N]` progress at `-O3 -Werror`, both unity
  (`meson setup build-o3 -Dbuildtype=release -Dwerror=true -Dbuild_unit_tests=true -Dintegration_tests=true`) and
  per-file (the same plus `-Dunity=off`; `core/meson.build` forces `unity=on` on `lib_usage_native`, so drop that
  override in a scratch copy). Unity hides missing includes; check per-file before calling a warning fix done. The
  one suppression is `core/include/compat/gcc_variant.hpp` (force-included for GCC): a libstdc++ `<variant>`
  `-Wmaybe-uninitialized` false positive reached through `pqxx::params`. Fix warnings at the source; don't add flags.

## Isolated test runs (setup, credentials, cleanup)

- One-time host setup: `sudo tools/harness/bootstrap.sh` (Python 3.14 venv, the `vh_harness` PostgreSQL role with its
  settings in the root-only `/var/lib/vaulthalla-harness/db.env`, the `vhh-actor-NN` nologin accounts). The run path
  never installs or changes the host; `bin/tests/lib/itest.sh` only checks the setup (preflight) and points here.
- Every run gets its own database, owned by `vh_harness`, dropped afterwards (`make test`: empty, the suites build their
  schema; `make itest`: cloned from the migrated template `vh_harness_tpl_<hash of deploy/psql>`, built once per
  migration set by `vh_migrate` = the daemon's SqlDeployer; `ITEST_DB_TEMPLATE=0` starts empty to cover migrations).
  No role is rotated or dropped, no repo env file gets credentials, nothing is installed into `/usr`.
- Guards in code: test mode takes all five `VH_TEST_DB_*` from the environment or throws (no fallback to the configured
  database or `/run/vaulthalla/db_password`; no repo env file is read); `wipe_all_data_restart_identity` /
  `nuke_and_recreate_schema_public` refuse outside test mode or on a database that isn't `vh_harness_*`/`*test*`;
  test instances refuse to start on `vh-storage*` or inside `vaulthalla.service`.
- `bin/tests/prove_isolation.sh`: fingerprints `/usr` binaries, env files, the dev service, role password hashes,
  databases and dev DB content, runs `make itest`, `make test` (subset) and a launched Tier B run, and requires no
  change (passed 2026-10-12, ~45 s). `make clean-test` drops leftovers of interrupted runs only.
- The retired shared `make run_test` (it installed an ASan build over `/usr`, rotated the `vaulthalla_test` password into
  the dev daemon's env file, could truncate the dev DB, ran `DROP OWNED` cluster-wide) is gone; `run_test`, `run-test`
  and `proof` are aliases of `itest`. `bin/tests/retire_legacy_test_env.sh` removes its leftovers once, explicitly.
- Audit: `~/VAULTHALLA_RUN_TEST_AUDIT.md`.

## DB-backed unit tests

```bash
make test                                              # whole vh_unit_tests binary against a per-run DB (~7 min)
make test ARGS="--gtest_filter='RoleParity*'"           # or: bash bin/tests/run_unit.sh -- --gtest_filter=...
```

The tests run as you (not root), with the role's settings only in the test process's environment.

CLI ↔ ws parity for families migrated to `core/ops/`:
`--gtest_filter='*Parity*:OpsGroups*:AuthPasswordChange*'` (groups, roles, API keys, vaults, users, S3 gateway,
pricing/config, sync conflicts). The whole binary takes ~7 minutes against a local DB; meson's test timeout is 30 minutes (#123). A parity case
runs one logical operation through `shell::Router::executeLine` and through the ws handler, for every seeded admin
role, and compares allow/deny (against an oracle from the role's permission bits) and resulting DB state, never text.
New families add a `test_ops_parity_<family>.cpp` on the same pattern.

**Never print or commit secret values.** DB auth problems mean the harness role's settings and the role disagree:
re-run `sudo tools/harness/bootstrap.sh` (it never rotates an existing role's password; remove the settings file first
to re-key).

## File recovery suites

DB-backed ones skip without `VH_TEST_DB_*` (run them with `make test ARGS="--gtest_filter='Recovery*:S3Versioned*'"`).
Design and invariants: `recovery.md`.

| Suite (file) | Covers |
|---|---|
| `RecoveryKeysTest`, `RecoveryKeysDbTest` (`test_recovery_keys.cpp`) | historical key snapshots, streaming re-seal, retired-key guard, export `historical_keys`, mid-rotation key load |
| `RecoveryModel`, `RecoveryJson`, `RecoveryDbTest` (`test_recovery_db.cpp`) | model text/JSON forms; every `db::query::recovery` query on migration 111 |
| `RecoveryStoreNames`, `RecoveryStoreTest` (`test_recovery_store.cpp`) | blob layout, link capture, dedupe, abort/commit, orphan sweep, quota in `freeSpace`, purge |
| `RecoveryVersionsTest` (`test_recovery_versions.cpp`) | local versioning capture/no-capture, off path, retention, upstream backlog replay order |
| `RecoverySnapshotsTest` (`test_recovery_snapshots.cpp`) | snapshot capture/skips, mode gate, dedupe, quotas, RBAC, crash cleanup, deletion |
| `RecoveryLocalRestoreTest` (`test_recovery_local_restore.cpp`) | local plans/restores: original and alternate destinations, conflicts, re-seal across rotations |
| `RecoveryProviderTest` (`test_recovery_provider.cpp`) | version index, provider points, point-in-time plans, provider copy / bounded transfer |
| `RecoverySmartCacheTest` (`test_recovery_smart_cache.cpp`) | release-blocking acceptance: cache vault, history only in the bucket, restore without a second upload; one manifest publish per pass (#248: first pass, early stop, a manifest written after the LIST never replaces the listed index) |
| `RecoveryPolicyTest`, `RecoveryDisclosureToken`, `RecoveryManifestRule` (`test_recovery_policy.cpp`) | status/update/disclosure/suspend/costs ordering, R2 refusal, protection, adoption, retention lifecycle |
| `RecoveryCostModel`, `RecoveryCostCatalog` (`test_recovery_costs.cpp`) | golden decimals from the signed fixture `core/test-assets/pricing/versioning`, ranges, illustrative, unpriced |
| `RecoveryUsageLedger`, `RecoveryUsageDbTest` (`test_recovery_usage.cpp`) | per-vault UTC-day counters, request tags, first put/overwrite/delete classification, failed flushes |
| `RecoveryParityTest` (`test_ops_parity_recovery.cpp`) | CLI ↔ ws verdicts and state for `vh vault recovery` / `snapshot` / `recovery` |
| `S3VersionedOps*`, `S3VersionedFake` (`test_s3_versioned_ops.cpp`) | the real `s3::Controller` versioned ops (signing, parsing, metering, lock) and the `VersionedBucket` fake (DB-free) |
| `RecoveryProviderTest.AnR2VaultRefusesProviderVersioningAndKeepsLocalSnapshotsLocal` | R2: provider versioning refused, nothing sent; local snapshot → overwrite → restore on the same vault, 0 data-plane/admin requests (was the live `R2VersioningRefused`) |
| `Live/LiveObjects.ProviderVersionsInsideThePrefix` (`test_live_bucket.cpp`) | live, shared bucket: R2 answers ListObjectVersions 501; on a versioned AWS test bucket two PUTs, HEAD ?versionId, CopyObject restore |

Helpers: `tests/helpers/{recovery_local,recovery_pricing,recovery_provider_harness,versioned_bucket}.hpp`. Contract:
`tools/contracts/test_backing_writers_contract.py` (no in-place writer of vault backing files; `verify.sh packaging`).
Web: `web/tests/e2e/recovery.spec.ts` (scripted ws answers; see `web-client.md`). No Tier A/B recovery scenario yet.

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
| `S3VersionedOpsSigning`, `S3VersionedOpsTest`, `S3ListObjects*`, `S3VersionedFake` (`test_s3_versioned_ops.cpp`) | legacy whole-bucket LIST never partial (#246: a failed page throws, every page parsed); provider-version data plane: version-id encoding (URL = signed query), HEAD/list/copy parsing, delete markers, 200-with-`<Error>`, > 5 GiB copy refusal, metering kinds, protection lock and budgets before sending, PutOutcome; the `VersionedBucket` fake (`tests/helpers/versioned_bucket.hpp`) semantics | nothing |
| `RecoveryVersionsTest` (`test_recovery_versions.cpp`) | local versioning: createFile overwrite and FUSE seal (`WorkingCopies::daemonHooks`) keep decryptable prior generations, deletes (file, folder) keep the last one, rename/copy/key rotation keep none, off path loads the policy once, empty generations skipped, concurrent writers, crash leftover swept, keep_last at capture, max age / quota, snapshot-held blob survives; upstream backlog through the `VersionedBucket` fake: outage → ordered replay (own IV/hash per version, a failed replay holds the upload back), key rotation between generations (encrypted and plaintext upstream), unversioned/propagating/suspended → skipped, smart-cache release, replays in `Planner::estimateS3Cost`, orphaned backlog of a deleted file settled by maintenance (#249: replayed + re-deleted / `orphaned`, live and trashed keys untouched, waits while propagating) | test DB env |
| `VaultRetentionTest` (`test_vault_retention.cpp`) | safe deletion (#162): schedule → restore, purge after the window (injected pass clock), delete now, resumed purge, key tombstone + expiry, S3 key-loss gate, bounded upstream purge (fake controller), shared-bucket guard, path guard | test DB env |

## Device listener and pairing suites

| Suite (file) | Covers | Needs |
|---|---|---|
| `DeviceCryptoVectors`, `DeviceCryptoEncodings`, `DeviceNames`, `DeviceServerIdentity`, `DeviceAuditOrigin` (`test_device_crypto.cpp`) | every docs/pairing.md §8 vector (commitment, SAS, leading-zero code, generator SPKI, rotation message, the spec's signature and one made here), hex/base64, code input, names, certificate re-issue keeps the pin | nothing |
| `DevicePairing` (`test_device_pairing.cpp`) | the in-memory state machine with an injected clock: one window per node, commit-then-reveal, three choices, wrong code denies, expiry, limits | nothing |
| `DeviceListenerTest` (`test_device_listener.cpp`) | real TLS 1.3 against a `Listener` on 127.0.0.1:0 (`tests/helpers/device_client.hpp`): TLS profile (1.2, no cert, P-384 refused), pairing-only → `device_unknown`, the full pairing flow through the Router, revocation, rotation (replays, idempotent retry), RBAC/deactivation/`revokeSessions` on live sessions, sweeper, contract auth levels vs the Router, `DeviceServer` rebinding loopback ↔ every interface | test DB env |
| `DeviceHttpTest` (`test_device_http.cpp`) | S1b over real TLS (`HttpClient` in `device_client.hpp`): download + Range + HEAD as the device's user, another user's device 403, share lane 403, `/auth/session` 404, pairing-only 403, an upload session (create, PUT, finish, read back), revocation ending a keep-alive connection; `/mcp` initialize/notification 202/tools/list/tools/call, exclusions (key export, pairing, remote), destructive gate, deadline, transport checks (Origin, version, content type, batches, GET); vault key export/confirm over TLS, refused to a console session and unreachable from `/mcp` | test DB env |
| `VaultKeyCheck`, `VaultKeysDbTest` (`test_vault_keys.cpp`) | key backup (`key-backup.md`): the key-check vectors, `vault.keys.status` (rotation, recovery, missing, deleted vaults), export refused on console/agent and carrying an unfinished rotation's key, confirm (mismatch, rotation in between), CLI ↔ ws verdicts for every seeded admin role; import (`Import*`): restore + read back, wrong/damaged/other-vault/held keys refused, partial sets mid-rotation, a missing retired row, a deleted vault; revision 2: a missing key row over sealed files (no mint, unavailable in status/health, import restores) vs an empty vault (minted), a fresh rotation target accepted on its key check, a cloud vault verified against its smallest upstream object (fake bucket, price refusal, wrong key) | test DB env (the vectors: nothing) |
| `DeviceParityTest` (`test_ops_parity_devices.cpp`) | `vh device` vs ws `device.*`: windows, number matching, list/rename/revoke ownership, remote switch for every seeded admin role (settings written to a private config copy) | test DB env |

On macOS, run DB suites on a private cluster when another checkout may be testing: `VH_TEST_PG_DIR=$TMPDIR/<name>
VH_TEST_PG_PORT=<port> tools/macos/test-db.sh up` (two runs on one cluster drop each other's schema). Device tests
never bind 36972 (port 0).

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

## Integration proofs (Tier A, `make itest`, preferred for FUSE / CLI end-to-end)

```bash
make itest                      # = bash bin/tests/run_proof.sh (needs sudo; never touches the dev install)
VH_TEST_CONFIG=default VH_TEST_SEED=0x... bash bin/tests/run_proof.sh --build-dir build
make itest-selftest             # negative controls + fail-closed env checks
```

`core/tests/integrations/main.cpp` (`vh_integration_tests`) runs in-process against a **private** instance: a per-run
database owned by the harness role `vh_harness`, `/tmp/vhh_proof_<run>/` paths, its own FUSE mount. It refuses to
start (exit 78) without a complete private environment (`runtime/TestInstance.hpp`); there is no opt-out. Last results (2026-10-11):
minimal 102/102, default 270/270 (seed 0x8f86ba60a0e5ccba; it caught the admin-role deletion defect fixed in bf56dec3).
- Seeds: `VH_TEST_SEED` (printed in the header, summary and reports); per-test BLAKE2b-64 streams, so a seed
  reproduces the same command lines. `VH_TEST_SEED_THREADS=1` for exact DB-id repro.
- Knobs: `VH_TEST_CONFIG` (minimal|default|medium|large), `VH_TEST_STAGES`, `VH_TEST_NEGATIVE_CONTROL=assertion|oracle`
  (must fail), `VH_TEST_UID_BASE` (default 2100000000; `users.linux_uid` is a signed INTEGER), `VH_TEST_FS_OP_TIMEOUT_MS`.
- Reports: JSON + JUnit in `build-itest/proof-artifacts/<run>/`. A run takes ~7.7 s (binary ~4.9 s, of which ~2.6 s
  tests; wrapper ~0.6 s; template clone 0.07 s vs ~0.5 s of in-binary migrations from empty). Exit non-zero on any failure or zero tests.
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
- Fault fixtures (`tools/harness/faults/*.patch`, `build.sh <fault>` builds a throwaway worktree), all caught
  (2026-10-12): libmagic race (`scenario magic`: ASan heap-use-after-free, trace replay 8/10 on the fault build vs
  0/10 fixed; `RACE_ACCEPTANCE.md`), stale revocation (`scenario revoke`: the next request after an unassign is still
  allowed; the documented contract is that CLI/console changes apply to the very next request), ws list without
  RBAC (oracle; shrinks to one op). `vhh regress` keeps all of them (`regressions/*.jsonl`, `*.scenario.json`).
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
- Real R2 dogfooding uses the one shared test bucket (`VAULTHALLA_TEST_R2_BUCKET`, `vh-test`), never a new one. Write
  under `vh-test-runs/<host>-<pid>-<unix time>/…` and clean it up. The gateway smokes default to such prefixes and refuse
  a remote run outside `vh-test-runs/`. A remote-cache gateway bucket is a vault on the whole upstream bucket, so its
  `.vaulthalla/index-v1.json` lands at the bucket root: remove it after a remote smoke (no test may delete outside
  `vh-test-runs/`).

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

## Live provider tests (`Live/*`, never CI)

**No test creates, deletes or reconfigures a bucket** (versioning, lifecycle, locks, event notifications, CORS). Agents
running the old provisioning suites (`VH_LIVE_UPSTREAM=1` with account-admin keys) left 7-8 buckets in the maintainer's
Cloudflare account; those suites, their credentials (`VH_{R2,AWS}_ADMIN_*`, `VH_CF_API_TOKEN`) and
`tools/lab/upstream_live_smoke.py` are gone (2026-10-22). Bucket administration and events are covered by the fakes:
`UpstreamProviderTest` (real adapters over the `curl::http` transport seam: create/collision codes, location
constraints, HEAD routing, lifecycle round trip with foreign rules, versioning get/put, R2 refusals, protection,
SQS/Cloudflare queues and notifications), `upstream_admin_fakes.hpp` / `upstream_event_fakes.hpp` (`UpstreamOps*`,
`UpstreamEvent*`, `UpstreamParity*`, `RecoveryPolicyTest`), `RecoverySmartCacheTest` and `RecoveryProviderTest`
(the former AWS recovery acceptance, incl. restore across a key rotation).

- **One shared bucket per provider**, provisioned by hand: Cloudflare R2 `VAULTHALLA_TEST_R2_{ACCESS_KEY,
  SECRET_ACCESS_KEY,ENDPOINT,REGION,BUCKET}` (`vh-test`, a bucket-scoped token: ListBuckets and GetBucketVersioning are
  403, object calls work); AWS `VAULTHALLA_TEST_S3_*` (none configured: those instances skip; the bucket must be
  unversioned or versioning Enabled). They live in the gitignored repo `.bashrc` (dev: `/srv/vaulthalla/.bashrc`);
  source only those lines, never print them: `eval "$(grep -E '^export VAULTHALLA_TEST_R2_' .bashrc)"`.
- **One helper:** `tests/helpers/live_bucket.hpp`. Fixtures derive from `LiveBucketTest` (parameterized `r2`/`aws`):
  none of a provider's five variables set = skip; some set = fail naming the missing ones; all set but the bucket not
  usable = fail with the provider's answer (never a silent skip). Each test gets `live().key(…)`,
  `live().controller()` (data plane) and `live().admin()` (guarded admin client).
- **A prefix per test:** `vh-test-runs/<host>-<pid>-<start>/<Suite>.<Test>/`. `TearDown` (an RAII `LivePrefix`, so
  also after a failed assertion or an exception) deletes every object, every version and delete marker where the
  provider has versions, and every unfinished multipart upload under it, then fails unless the prefix lists empty.
  R2 has no versions (ListObjectVersions answers 501 NotImplemented), so a plain listing is complete there.
- **Sweep:** the first live test of a process deletes `vh-test-runs/` runs that started more than 6 h ago (crashed or
  killed runs; LastModified for a name without a start time). Nothing outside `vh-test-runs/` is ever deleted.
- **Runtime guard:** `GuardedAdmin` refuses CreateBucket, DeleteBucket, lifecycle and versioning writes, ListBuckets
  and probes without forwarding them, any bucket but the configured one, and deletes outside the test's prefix; while
  a live test runs, `adminFor` hands out only that client (for the test credential) and `eventsFor` nothing. A
  violation fails the test even if the code under test swallows the exception, and `TearDown` fails a test that left a
  key outside `vh-test-runs/`. `LiveBucketGuard.*` (DB-free, runs in CI) proves the guard; the source half is
  `tools/contracts/test_live_bucket_contract.py` (no provisioning credentials or bucket-administration commands in
  tests/tooling, real adapters only in the helper or behind the transport seam, live test files reach the provider
  only through the helper, `run_unit.sh` hands through only the shared-bucket variables).
- Suites: `Live/S3ProviderIntegrationTest.*` (`test_S3Provider.cpp`: upload/download/delete, unicode keys, metadata,
  multipart + abort, listing, previews from downloaded buffers, credential validation), `Live/LiveObjects.*`
  (`test_live_bucket.cpp`: admin object calls + protection lock in the prefix, SigV4 on every ListObjectsV2 page,
  provider versions, the cleanup guard on a scope that throws with an open multipart upload). All DB-free:
  `(eval "$(grep -E '^export VAULTHALLA_TEST_R2_' .bashrc)"; build/core/vh_unit_tests --gtest_filter='Live*')`
  (~30 s on R2). Through the per-run DB runner, `VH_LIVE_TESTS=1` hands exactly `LIVE_ENV_VARS` through on a pipe:
  `(eval "$(grep -E '^export VAULTHALLA_TEST_R2_' .bashrc)"; VH_LIVE_TESTS=1 bash bin/tests/run_unit.sh -- --gtest_filter='Live*')`.
- Proof it leaves nothing (2026-10-22, macOS and dev): `vh-test` held 0 objects before and after full live runs, also
  after runs with a forced assertion failure and a forced exception mid-test, and a planted 8 h old run was swept.
  Check with the aws CLI and the test credential: `list-objects-v2 --prefix vh-test-runs/`, the whole bucket and
  `list-multipart-uploads`.

## Provider test credentials (Phase 2 scaffold)

- Canonical file: `/etc/vaulthalla/testing/providers.env` (root:vaulthalla 0640, dir 0750). Operator-managed and TEST-ONLY:
  dedicated S3 + R2 buckets with bucket-scoped keys. The package never ships, reads, rewrites or deletes it (upgrade and
  purge leave it; contract-tested), and the daemon never loads it.
- Template + tooling: `tools/lab/providers.env.example` (placeholder `CHANGE_ME` values; variable names are the
  `VAULTHALLA_TEST_{S3,R2}_*` ones the live tests and `tools/smoke` read, plus `VAULTHALLA_TEST_PROVIDER_PREFIX` /
  `VAULTHALLA_TEST_PROVIDER_DESTRUCTIVE` safety rails). `bash tools/lab/test_providers.sh install|check [--host vh-storage]`
  creates the scaffold without overwriting and reports set/placeholder/missing per variable, never values.
- Harness wiring: `tools/e2e/load_env.sh` sources it when readable (override path with `VH_TEST_PROVIDERS_ENV`). Run
  provider harnesses as a `vaulthalla`-group user or via sudo. Installed on vh-storage 2026-09-30 (unfilled).
- Guard: `python3 -m unittest tools.lab.tests.test_provider_scaffold_contract`.
