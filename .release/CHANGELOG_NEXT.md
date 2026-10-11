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
