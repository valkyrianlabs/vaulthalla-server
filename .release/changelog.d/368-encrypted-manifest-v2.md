- Encrypted metadata manifest v2 for `opaque_v1` vaults (#368, WS3-a; design/encryption/03 §3-§4): a copy-on-write
  root (VHF1 kind 3, epoch-chained, pinning segments by SHA-256 and size) and uid-partitioned segments (VHF1 kind 2)
  carrying the tree, trash, tombstones, provider versions, prior names, snapshot records and the key history with
  attestations; segments are written with `If-None-Match: *`, the root with `If-Match`, a 412 is merged, never
  overwritten; garbage collection keeps the last three roots' segments. Readers apply the rollback/fork/gap chain
  rules with provider-version and older-root fallbacks and a blind header-only rebuild floor. `opaque_v1` stays test
  mode only (#371); `path_v0` and `transparent` vaults keep `index-v1.json` unchanged.
- Migration 125: `remote_manifest_state` gains `epoch`, `root_sha256`, the refused root (`refused_reason`,
  `refused_epoch`, `refused_root_sha256`, `refused_at`) and `gc_at`; new `remote_manifest_root` (sids of the last
  three roots); `directories.uid` and `symlinks.uid` (libsodium uids assigned by the manifest collector, immutable);
  `files_trashed.object_uid` (set when a file is trashed). Additive and idempotent.
- A refused manifest root raises one `manifest_rollback` / `manifest_fork` security notification per root and stalls
  the vault's sync pass until the bucket's root is acceptable again.
- `vectors.json` gains `root_epoch_3` and the chain cases `gap_1_to_3` and `rollback_3_to_2` (72 vectors; existing ones
  byte-identical). Tests: `ManifestVectors`, `ManifestDocument`, `ManifestPartition`, `ManifestPublish*`,
  `ManifestChain*`, `ManifestContent*`, `ManifestReplay*`, `ManifestDbTest.*`,
  `SqlDeployerHistoryDb.ManifestV2MigrationIsAdditiveAndIdempotent`.
