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

On macOS, `make test` needs no host setup and no sudo (#217): it sources `tools/macos/env.sh`, builds the same
`build-itest` options (ASan/UBSan) and runs `vh_unit_tests` against a cluster of its own (`tools/macos/test-db.sh up`
in `$TMPDIR/vh-unit-pg-<pid>` on a free port, or `VH_TEST_PG_PORT`), removed on exit (`--keep-db` leaves it
running), with `ASAN_OPTIONS=detect_container_overflow=0` (libc++ false positives, see macos.md). A cluster started
by hand is never reused or torn down. `make itest` (and `run_proof*.sh`) refuses on
macOS with a pointer to `make test`: Tier A needs a kernel FUSE mount, /proc and sudo. The test scripts stay bash 3.2
compatible (`/bin/bash -n`); `itest_abspath` in `bin/tests/lib/itest.sh` replaces GNU `realpath -m`.

CLI ↔ ws parity for families migrated to `core/ops/`:
`--gtest_filter='*Parity*:OpsGroups*:AuthPasswordChange*'` (groups, roles, API keys, vaults and the accessible-vaults list, users, S3 gateway,
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

Helpers: `tests/helpers/{recovery_local,recovery_pricing,recovery_provider_harness,versioned_bucket}.hpp`. Contract:
`tools/contracts/test_backing_writers_contract.py` (no in-place writer of vault backing files; `verify.sh packaging`).
Web: `web/tests/e2e/recovery.spec.ts` (scripted ws answers; see `web-client.md`). No Tier A/B recovery scenario yet.

## Rich-preview / HTTP suites

| Suite (file) | Covers | Needs |
|---|---|---|
| `GcmCtrDecryptAt`, `GcmFileReaderTest`, `GcmStreamVerifier`, `GcmOneShot`, `EncryptionManagerKeys`, `EngineReader`, `HttpRange` (`test_gcm_range_reader.cpp`) | CTR positioning at every block boundary vs authenticated decrypt, OpenSSL/libsodium interop, AAD/tag/body tampering (optimistic + strict), supersession, shared verification, key snapshots during rotation, the RFC 9110 range parser | nothing (DB-free) |
| `HttpArchiveZip`, `HttpArchiveSessionTest` (`test_http_archive.cpp`) | streamed folder ZIP validated by Python `zipfile` + `unzip -t` (`tests/helpers/zip_check.hpp`; skip without them): UTF-8/dot names, empty file, empty dir, exact length, one member open at a time, integrity failure truncates before the CRC, size drift aborts, zip-slip names, ZIP64 (> 4 GiB member as a sparse file, ~25 s; > 65535 entries), and over a socket: HEAD length without opening members, disconnect, stalled client | nothing |
| `HttpSessionTest` (`test_http_session.cpp`) | socket-level streaming, client disconnect stopping work, stalled/idle deadlines, HEAD framing | nothing |
| `VaultScopeRbacTest` (`test_vault_scope_rbac.cpp`) | the global vault policy read in the vault's scope (own / admin-owned / other): accounts whose self scope grants more than its others' scopes and the reverse, every filesystem action on a file and a directory against the evaluator applied to exactly that scope, then ws `fs.dir.list` / `fs.dir.create` / `fs.entry.delete` / `storage.vault.get`, `vh fs ls`, the access layer (HTTP human/device lanes, `vh fs`) and the accessible list; every seeded role decides as before | test DB env |
| `StorageEngineRegistryTest` (`test_vault_lifecycle_regressions.cpp`) | one engine per vault id after a schema reset reuses ids (the DeviceHttpTest key-export flake on macOS) and after `initStorageEngines` | test DB env |
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
| `VaultKeyCheck`, `VaultKeysDbTest` (`test_vault_keys.cpp`) | key backup (`key-backup.md`): the key-check vectors, `vault.keys.status` (rotation, recovery, missing, deleted vaults), export refused on console/agent and carrying an unfinished rotation's key, confirm (mismatch, rotation in between), CLI ↔ ws verdicts for every seeded admin role; import (`Import*`): restore + read back, wrong/damaged/other-vault/held keys refused, partial sets mid-rotation, a missing retired row, a deleted vault; revision 2: a missing key row over sealed files (no mint, unavailable in status/health, import restores) vs an empty vault (minted), a fresh rotation target accepted on its key check, a cloud vault verified against its smallest upstream object (fake bucket, price refusal, wrong key); revision 3: attested recovery, out-of-range attestation key ids, salvage (mode salvage always confirms as `vault_key_salvage`). The import document's contract model against the import's parser: `ContractModels.VaultKeyImportDocument*` / `VaultKeyAttestationKeyId*` (`contract/models_keys.cpp`, DB-free) | test DB env (the vectors and the contract tests: nothing) |
| `DeviceParityTest` (`test_ops_parity_devices.cpp`) | `vh device` vs ws `device.*`: windows, number matching, list/rename/revoke ownership, remote switch for every seeded admin role (settings written to a private config copy) | test DB env |

On macOS, run DB suites on a private cluster when another checkout may be testing: `VH_TEST_PG_DIR=$TMPDIR/<name>
VH_TEST_PG_PORT=<port> tools/macos/test-db.sh up` (two runs on one cluster drop each other's schema; agents sharing a
scratchpad must keep the printed exports in a file only they write, or one agent's runs land on the other's cluster). Device tests
never bind 36972 (port 0).

- **ThreadSanitizer** for the identity publication code: `meson setup build-tsan -Db_sanitize=thread
  -Dbuild_unit_tests=true -Db_lundef=false && ninja -C build-tsan core/vh_unit_tests`, then run with ASLR off (TSan
  aborts with "unexpected memory mapping" on this kernel otherwise): `setarch -R ./build-tsan/core/vh_unit_tests
  --gtest_filter='Identities*'`. Don't run two DB-backed test processes at once: each suite drops and recreates the
  test schema.
- Tests that write identity or role rows with raw SQL must call `identities::manager().reconcile()` afterwards (the
  revision watcher does it in the daemon) or the canonical objects they read keep the old state.
- Helpers that run under `RLIMIT_AS` can't be sanitized: ASan reserves far more address space than the limit allows,
  so a sanitized helper aborts at start. `vh_fake_derive_helper` is therefore always built with `b_sanitize=none`
  (per-target override, honoured by meson 1.3 and 1.8), and `DeriveRunnerTest`/`DeriveQueueDbTest` pass in the
  sanitized `build-itest` (`make test`; #224). The real preview helpers (`core/tools/preview-*`, the helper suites)
  are still sanitized in such a build: run those suites from a non-sanitized one.
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

## Authorized PentAGI fixture (2026-10-20)

The separate, operator-authorized network pentest targets HTTPS `/ws`, `/ws/share`, uploads/downloads on
`vh-local.cooperhlarson.com` only. The installed host is **not** a private harness instance; do not bypass Tier B's
target guard to run its mutating engine on vh-storage. Provision/verify through `tools/lab/pentest` instead.

- Published handoff: `vh-storage:/srv/vaulthalla-pentest`; secrets and recovered seed state stay root-only under
  `/srv/vaulthalla-pentest-private`. The Python tools, exact exported `usage.json` and private venv are under
  `/opt/vaulthalla-pentest-tools`. The target remains the released apt package (`1.15.0-1`).
- Current proof: 84/84 live checks, including all 59 oracle expectations, actual disposable uploads/overwrites/deletes,
  share isolation/expiry/revocation, inactive login, 14 plaintext hashes (bytes never logged), and exact
  `meta.contract.get` parity with `vh_usage --json`. Errors/404/5xx no longer masquerade as permission denials.
- `publish.py` copies the sanitized report and contract, excludes the checksum file itself on every publication,
  and rejects known passwords/share tokens/canary plaintext in public files. Build time is unknown (`null`) unless
  supplied independently; fixture creation time is not binary build time.
- `readiness.py <published-dir> --build-version 1.15.0` is offline and never opens credentials. It requires complete
  checksums, a matching build/contract, fresh verification (24 hours), and restore evidence or an explicit operator
  waiver. `--snapshot-id` alone never claims a successful restore. Snapshot `ready-state-2` was supplied by Cooper;
  restore testing was explicitly waived because all data on vh-storage is disposable. Do not describe it as tested.
- PentAGI has an enabled `pentagi-assessment.service`: static-address worker/scraper firewall rules are installed
  before containers start; the guard fails closed on topology changes. 13 isolation checks pass. Offline browser/WS
  wheels and `scripts/prepare-worker.py <flow-id>` provision an existing worker without copying credentials. The
  sanitized handoff is at `pentagi:/home/coop/pentagi/assessment/fixtures/current`. Campaigns are not auto-launched.
  The management UI is exposed on the explicitly authorized LAN address `https://10.10.10.33:8443` plus loopback;
  it uses a local certificate with matching IP/DNS SANs. Existing login credentials are unchanged. Worker access
  to this management endpoint remains blocked. The eleven April flows were labeled as previous sessions. Flow 12
  is now `Vaulthalla A1 — ready to start`: its public fixture/tools and private 0600 carol/dave/eve credentials are
  installed; `/work/pentest_client.py` authenticates internally and emits sanitized responses or hashes. Positive
  download and negative list controls pass from the worker. No model-driven attack campaign has started, and no
  flow contents were deleted. This remains the legacy external fixture, **not** native integration-fixture
  provisioning: the native provisioner still reuses the external Seeder and its agent gateway refuses external
  targets. Do not describe this engagement as migrated to native fixtures.

The workstation's separate `/Users/cooper/dev/pentagi-vaulthalla` workspace holds the attacker scripts and runbook.
Refresh live proof before launching if it is stale; such verification mutates only disposable probe resources and
authentication/audit state, and still needs authorization under `/lab` for a new conversation.

## Production-style mount dogfooding (`/mnt/vaulthalla`)

Only use this when the prod mount is specifically what's under test. `make dev` (a working-tree install; `bin/vh/install.sh` installs
the *apt* package, not your checkout) → `id -nG | grep -qw vaulthalla` → `vh setup assign-admin`. If the
`vaulthalla` group was created after your shell started, CLI failures are environmental; start a new login.
Dev mode requires both `VH_BUILD_MODE=dev` and the gitignored `enable_dev_mode` sentinel (`bin/lib/dev_mode.sh`).

## Other harnesses

- `tools/smoke/s3_gateway_{e2e,merge_ready,scoped_budget_smoke}.sh`: S3 gateway smoke runs against a live install.
- `tools/e2e/{load_env.sh,provision_e2e_user.sh}` + `web/tests/e2e` (Playwright).
- `tools/dev/share_preview_smoke.mjs`: public share preview smoke.
- The remote gateway smoke (`s3_gateway_scoped_budget_smoke.sh`, needs a running install) has no upstream knobs: it
  creates the fixed test bucket `vh-test-gateway-smoke` with `build/core/vh_live_bucket` (the guarded helper; a
  leftover of a crashed run is emptied and deleted first), registers `VH_R2_ADMIN_*` as the daemon's upstream API key,
  and deletes the bucket in its EXIT trap after the gateway bucket and key are gone (the tool then checks HeadBucket).
  `vh_live_bucket` refuses every name but the fixed ones. Real R2 dogfooding otherwise: only in a bucket you create
  and delete yourself.

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

## Live provider tests (`LiveR2.*`, opt-in, never CI)

Two hard rules, enforced by `tests/helpers/live_bucket.hpp` (the only way a test reaches a real provider):

1. **Names.** Every bucket a test creates is named `vh-test-<host>-<pid>-<run start>` (`kRunBucketPattern`); tooling
   has exactly one fixed name, `vh-test-gateway-smoke` (`fixedTestBuckets()`, managed by `vh_live_bucket`). The
   helper's `GuardedAdmin` refuses to create, delete, empty, inspect or reconfigure any other bucket, and
   `GuardedEvents` any other bucket or queue, before anything is sent. Every production bucket is unreachable by
   construction.
2. **Cleanup.** Every bucket a test creates is emptied (objects, unfinished multipart uploads; R2 has no versions) and
   deleted after the run, also when tests fail, and the run fails unless HeadBucket then says it is gone. Before
   creating its bucket a run sweeps orphans: buckets matching `kRunBucketPattern` whose run started more than 6 h ago,
   nothing else.

- **Opt-in only:** live tests run only with `VH_LIVE_TESTS=1`, whatever credentials are in the environment. `meson test`,
  `verify.sh`, `make test` and CI never set it, so agents running the unit suite never reach R2. Credential: the R2
  admin key `VH_R2_ADMIN_{ACCESS_KEY,SECRET_KEY,ENDPOINT,REGION}` in the gitignored repo-root `.bashrc` (Mac and dev
  hold the same file). Source only those lines and never print them. The R2 event test also needs `VH_CF_API_TOKEN`
  (a Cloudflare API token with Queues: Edit and Workers R2 Storage: Edit) and skips without it; the account id comes
  from the R2 endpoint host, so nothing else is configured. Its queue is named like the run bucket (plus
  `<queue>-dlq`). Teardown removes the bucket's rules by id, then both queues BY NAME (`QueueAdmin`, retried while the
  Queues listing lags; never via the `ChannelRef`, since `ensureChannel`/`subscribe` can fail after creating them),
  and the run's environment repeats both before deleting the bucket. The orphan sweep also removes test queues of
  runs older than 6 h. The test uploads a fresh object every 15 s until an event arrives and retries pulls answering
  405/5xx (R2 facts: upstream-control-plane.md). AWS has no live tests.
  The old shared-bucket keys and their variables were revoked and removed, as were `VH_LIVE_UPSTREAM` and
  `VH_R2_EVENTS_*`.
- **One bucket per run:** `RunBucket` creates it with the real adapter on the first live test; the global test
  environment (`RunBucketEnvironment`) deletes it after the last. Each test works under its own `<Suite>.<Test>/`
  prefix, which `TearDown` empties and checks empty.
- **Suite** (`test_live_r2.cpp`, `LiveR2.*`): `TheRunBucketCameFromTheAdapter` (exists, listed, a second CreateBucket
  is a non-destructive 409, versioning refused without a request), `DataPlaneRoundTrip` (put with metadata and a
  unicode key, get, ranged get, head, paged list, delete, multipart complete and abort),
  `CleanupRemovesObjectsAndOpenUploads`, `EventNotificationsOnTheRunBucket` (queue named like the bucket, rule on the
  test's prefix; rule and queue removed even on failure). Everything else stays with the fakes: bucket admin and
  events through the real adapters over the `curl::http` transport seam (`UpstreamProviderTest`), the admin and event
  fakes (`UpstreamOps*`, `UpstreamEvent*`, `UpstreamParity*`, `RecoveryPolicyTest`), recovery (`RecoverySmartCacheTest`,
  `RecoveryProviderTest`), listing edge cases (`S3ListObjects*`, `S3VersionedOps*`).
- **Guard:** `LiveBucketGuard.*` (no credentials, no DB; runs in CI) proves the name checks, the orphan selection and
  the guarded provider factory. A violation fails the test even if the code under test swallows the exception.
  `tools/contracts/test_live_bucket_contract.py`: the old shared-bucket variables appear nowhere but published history; only the
  helper reads the live credential and nothing a default run uses sets `VH_LIVE_TESTS`; real adapters only in the
  helper or behind the transport seam; every bucket/queue call of the guarded clients is name-checked first; the
  pattern rejects real and near-miss names; the cleanup guard is wired; live test files reach the provider only
  through the helper; tooling has no bucket provisioning commands.
- **Run:** `(eval "$(grep -E '^export VH_R2_ADMIN_' .bashrc)"; VH_LIVE_TESTS=1 build/core/vh_unit_tests --gtest_filter='Live*')`.
  Through the per-run DB runner, `VH_LIVE_TESTS=1` hands exactly `LIVE_ENV_VARS` through on a pipe:
  `(eval "$(grep -E '^export VH_R2_ADMIN_' .bashrc)"; VH_LIVE_TESTS=1 bash bin/tests/run_unit.sh -- --gtest_filter='Live*')`.
  To check that nothing was left behind, list the account's bucket names (read-only) before and after a run; they must
  be identical.

## Provider test credentials (Phase 2 scaffold)

- Canonical file: `/etc/vaulthalla/testing/providers.env` (root:vaulthalla 0640, dir 0750). Operator-managed and TEST-ONLY:
  a test account's R2 admin key for the live tests. The package never ships, reads, rewrites or deletes it (upgrade and
  purge leave it; contract-tested), and the daemon never loads it.
- Template + tooling: `tools/lab/providers.env.example` (placeholder `CHANGE_ME` values for the live tests' R2 admin
  key `VH_R2_ADMIN_*` and the optional `VH_CF_API_TOKEN`). `bash tools/lab/test_providers.sh install|check [--host vh-storage]`
  creates the scaffold without overwriting and reports set/placeholder/missing per variable, never values.
- Harness wiring: `tools/e2e/load_env.sh` sources it when readable (override path with `VH_TEST_PROVIDERS_ENV`). Run
  provider harnesses as a `vaulthalla`-group user or via sudo. Installed on vh-storage 2026-09-30 (unfilled).
- Guard: `python3 -m unittest tools.lab.tests.test_provider_scaffold_contract`.
