<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
## Identities
- identities::Manager owns one canonical User/Group object per id and publishes immutable states into it
  (atomic shared_ptr); readers take one state per check, user+group views are coherent across a publication.
- Identity and RBAC writes (users, groups, memberships, vault role assignments, overrides, role templates) commit,
  reload what they touched in one snapshot and publish before returning; ops/auth/seed/CLI paths go through it.
- Migration 108: identity_revision counter and identity_change_log maintained by triggers (NOTIFY vh_identity);
  the daemon polls it every second to apply out-of-band changes; a state never replaces a newer one.
- Batched identity loader: any number of accounts and groups in ~8 statements, no group member lists, no
  password hashes; credential checks use a dedicated query.
- FUSE: the caller and vault owner come from memory; deactivated accounts are refused (they were not).
- Vault permission checks no longer load the vault owner from the database; API key listing no longer
  dereferences a missing owner.
- Contract test: identity writes outside identities::Manager are rejected (tools/contracts).
- HTTP cookie auth: refresh-token row read in one round trip (Transactions::read); the owner comes from the row and
  the canonical account (the users JOIN per request is gone); JWT secret cached in crypto::secrets::Manager.
## Previews
- /preview/batch: index-only readiness in one query per engine (Store::status), "failed" for known-bad sources, no
  artifact decrypts and no cache hit/miss accounting for status checks.
- Derived cache hits: Store::read (one round trip via Transactions::read, one open, one decrypt), in-memory hit
  tracking flushed in batches; migration 109 adds cache_index.page_count for PDF renders.
- Render: single flight per source generation and page; a decode emits all missing thumbnail sizes at or below the
  rendered size; separate interactive and background render gates.
- Disposable artifacts (thumbnails, page renders) skip fsync; the startup sweep removes artifact files without rows.
- Generator version 3: fast IDCT and 4:2:0 for thumbnail sizes, alpha composited over white.
- Web grid requests 256/512 px thumbnails for its tiles; the legacy ws share.preview.get renders through the cached,
  gated pipeline and never fetches remote-only bytes.
- Deferred outputs: an on-demand page-0 render returns the requested size, then finishes the smaller thumbnail
  sizes from the same raster on the thumbnail pool while holding the decode's flight.
## Filesystem
- fs cache listDir: completeness checked with one statement (direct child count, subtree totals) instead of two
  transactions reloading the directory and its subdirectories; parent->children index replaces a scan of every
  cached entry per listing.
- Directory totals: one recursive statement updates every ancestor (rows locked nearest-first) instead of an UPDATE
  and a parent lookup per level; ancestor chains load in one statement; signed size delta in the rename re-encrypt
  path (a shrinking file no longer wraps).
- Web/API overwrite refreshes the cached ancestor directory totals.
## Sync
- rbac::resolver::Vault: sync config/action permissions also come from a vault role on the vault (the account's
  own or a group's), unioned with the admin vault globals (#189); ops::conflicts::canResolveIn uses the resolver
  alone. Vault-role roles permissions stay globals-only.
- Planner: a file whose sides are unchanged since the per-file baseline is skipped under every conflict policy, so
  keep_remote / keep_newest no longer re-download a file they downloaded (#190).
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

