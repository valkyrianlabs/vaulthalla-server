- Bucket layout migration `path_v0` → `opaque_v1` (#373, WS1-c; design/encryption/01 §6 as simplified on the issue,
  2026-11-06: no soak/rollback, no `encrypt_upstream` toggling): `vault::layout` (`vault/LayoutMigration.hpp`),
  `vault::LayoutMigrationService` (runtime service after FormatConversionService), `db::query::vault::LayoutMigration`,
  migration 133 `vault_layout_migration` + `vault_layout_migration_item`. Operator-started only: `vh vault
  migrate-layout <vault> [--status|--cleanup [--confirm <name>]] [--accept-unpriced]`, ws `vault.layout.status` /
  `.migrate` (keys step-up) / `.cleanup` (data.destroy step-up with confirm); encryption-key View / Rotate permission.
  Audit events `vault.layout.migrate`, `vault.layout.cutover`, `vault.layout.failed`, `vault.layout.cleanup`,
  `vault.layout.cleanup.run`.
- The run holds the vault's sync pass lease from the inventory to the cutover: complete ListObjectVersions (R2:
  ListObjectsV2) inventory, one HEAD per legacy version, `LayoutMigrationCost` estimate + price preflight
  (`layout_migration`), then per object oldest first: legacy versions (GET `?versionId` If-Match), pending backlog
  generations and the current content re-sealed as VHF1 bound to the file uid under the same key version (gcm0 local
  copies through the #372 live-file protocol first), PUT `o/<uid>` without metadata, delete markers carried as DELETE
  of `o/<uid>`; proof of storage by MD5/multipart-MD5 ETag or read-back; random sample read-back (max(1 %, 100)); a
  second complete listing; one cutover transaction (layout, index-only rows' generations by compare-and-set, no live
  gcm0 row or pending gcm0 backlog blob allowed, remote index and baselines on `o/<uid>`, backlog and sent local
  versions remapped, re-sealed versions keep their original `last_modified`); then manifest v2 publish and a
  bucket-only load check. A bucket changed since the last sync refuses (`diverged`). Failures before the cutover leave
  `path_v0` (state `failed`, resumable).
- Cleanup after `cleanup_after` (default 7 days) with the manifest verified, never on a protected bucket: dry run, then
  explicit version-id deletes (`s3::Controller::deleteObjectVersion`; unversioned: DELETE after a HEAD matched the
  inventoried ETag) of exactly the inventoried, verified/superseded legacy versions; Object Lock retention and legal
  holds read by `HEAD ?versionId` (`ObjectVersionHead::{object_lock_mode,retain_until,legal_hold}`) and respected;
  refused deletes (`s3::DeleteRefused`) stay `cleanup_blocked` with their reason, retried daily; `complete` only after a
  complete listing shows no legacy key, version or marker.
- `s3::ScopedLegacyLayoutCleanup` lets the cleanup HEAD/DELETE inventoried legacy keys of an opaque_v1 controller (never
  PUT/COPY). `ObjectKeyPage::objects` (ETag, size, last modified). path_v0 listings and the event applier ignore
  `o/<uid>` objects (the migration's, before the cutover). `ObjectIdentity::pathOfUid` falls back to the migrated
  legacy key for history whose file is gone. `encrypt_upstream` can't change while a migration copies.
- Health `legacy_content` {remaining, path_v0_vaults, layout_migrations_unfinished, legacy_files, legacy_blobs,
  legacy_upload_files} (#376 readiness; informational, never degrades). Removed with no callers left:
  `crypto/util/reseal.{hpp,cpp}` (the gcm0→gcm0 re-sealer), `crypto/util/verify.{hpp,cpp}`
  (`aes256_gcm_file_authenticates`), `crypto::util::read_file`. Legacy content is only read now.
- Config `vaults.layout_migration.cleanup_wait_days` (1..365, default 7). Test-instance env
  `VH_TEST_NEW_ENCRYPTING_LAYOUT=path_v0` (test mode only). Harness `vhh drill migrate`; unit suites `LayoutMigration*`,
  live `LiveR2.LayoutMigrationPrimitives`.
