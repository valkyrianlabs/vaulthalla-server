- Provider-blind storage schema (#366, WS1-a; design/encryption/01 §4.1, §4.6): migration 122 adds `vault.uid` and
  `files.object_uid` (UUID columns of 16 raw libsodium bytes, unique, immutable once set by trigger),
  `s3.storage_layout` (`transparent` / `path_v0` / `opaque_v1`) with `s3_storage_layout_check` tying it to
  `encrypt_upstream`, and makes `s3.encrypt_upstream` NOT NULL (NULL rows, always read as true, become TRUE).
  Existing rows get `path_v0` or `transparent`; a deployer data step (`SqlDeployer` `kMigrationDataSteps`) assigns
  uids to existing vaults and files in the deploy transaction, and migration 123 makes them NOT NULL.
- `Vault::upsertVault` draws a vault's uid and resolves its layout from `encrypt_upstream` (a request never sets it);
  `opaque_v1` is refused outside test mode until the restore drill (#371), and turning encryption off on an
  `opaque_v1` vault is refused. `File::upsertFile` keeps a rewritten file's uid and draws one for a new row; copies
  get a new one. Data plane unchanged (#369).
- `vh vault info` prints the vault uid (Crockford base32) and an S3 vault's storage layout; the ws `Vault` model adds
  the optional, read-only `storage_layout`. New `crypto::id::ObjectUid` (CSPRNG uid, UUID and strict base32 forms,
  checked against `vectors.json` `object_ids`).
- Removed the unused `upsert_file_by_entry_id` and `insert_s3_vault` prepared statements.
- Tests: `ObjectUid.*`, `StorageLayout.*`, `ObjectUidDbTest.*`, `SqlDeployerHistoryDb.StorageLayoutMigration*`,
  `SqlDeployerHistoryDb.LayoutCheckConstraint*`.
