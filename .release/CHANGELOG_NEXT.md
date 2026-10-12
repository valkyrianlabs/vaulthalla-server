<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
## Fixes
- rbac: count_admin_role_assignments_by_role_id counted vault_role_assignments; removing a held admin role
  succeeded and ON DELETE CASCADE stripped it from its holders. Regression test in RoleParityTest.
- ws: fs.entry.move/rename/copy with a missing source or destination folder raise ops::NotFound (typed not_found)
  instead of an untyped engine error.
## Contracts
- core/usage: field generators on CLI usage entries, an operation catalog (bindings, refusal maps, deadlines) and a
  ws command book; vh_usage --json publishes them (build/core/usage.json).
- web: wsContract.ts generated from the ws book; WebSocketCommandMap is type-checked against it; drift fails the
  meson test ws_contract_drift and tools/contracts/test_ws_contract.py.
- ws: meta.contract.get (signed-in sessions) returns the contract identity; the console shows a reload notice when
  the daemon's ws_hash differs from its own.
## Testing
- VH_TEST_MODE=1 private daemon instance with a fail-closed environment guard (runtime/TestInstance, exit 78);
  VH_TEST_CLI_SOCKET / VH_TEST_LOG_PATH; client VAULTHALLA_CLI_SOCKET.
- Tier A proofs: bin/tests/run_proof.sh (make proof): per-run database and /tmp paths, seeded (BLAKE2b-64 streams),
  state oracles, JSON/JUnit reports, negative controls, vh_fs_actor instead of fork() from the test process.
- tools/harness: Tier B integration engine (world, RBAC model, multi-surface sessions, lockstep/barrier/free
  schedules, trace, replay, shrink, regressions, fault fixtures, hang/crash scenarios); verify.sh harness profile in CI.
- Test isolation: Makefile test (bin/tests/run_unit.sh) and itest (bin/tests/run_proof.sh) use per-run databases owned by
  vh_harness (bin/tests/lib/itest.sh: preflight only, build-itest/ configured on change, no install); itest clones a
  migrated template built by vh_migrate (the daemon's SqlDeployer). run_test/run-test/proof alias itest; the shared
  bin/tests install/uninstall scripts and VH_TEST_LEGACY_SHARED_ENV are removed; bin/tests/prove_isolation.sh,
  clean_itest.sh, retire_legacy_test_env.sh.
- db/Connection: test mode requires all VH_TEST_DB_* from the environment (no env-file or production fallback;
  VH_TEST_ENV_PATH removed); seed wipe/nuke helpers check test mode and a test database name; test instances refuse
  vh-storage* hosts and the vaulthalla.service cgroup (runtime/TestInstance::hostRefusal).
- doctor.sh masks environment file values. tools/harness runs on Python 3.14 (CI image: deadsnakes python3.14).
- vhh: external:<descriptor> targets (env lab|production; production needs --allow-production and
  VHH_ALLOW_PRODUCTION=1) for non-destructive verify-fixture only; destructive commands refuse them.

