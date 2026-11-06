-- Every vault and every file has its uid (#366, WS1-a). 120_storage_layout.sql added the columns; the deployer's data
-- step for it (seed/SqlDeployer, kMigrationDataSteps) assigned libsodium uids to the existing rows in this same
-- transaction. From here on every insert names its uid: db::query::vault::Vault::upsertVault and
-- db::query::fs::File::upsertFile draw one for a new row. Idempotent: SET NOT NULL on a NOT NULL column is a no-op.

ALTER TABLE vault ALTER COLUMN uid SET NOT NULL;
ALTER TABLE files ALTER COLUMN object_uid SET NOT NULL;
