-- Provider-blind storage, schema only (#366, WS1-a; design/encryption/01-provider-blind-storage.md §4.1, §4.6).
-- Nothing reads these yet: the opaque data plane (#369) and the layout migration come later.
--
--   vault.uid          16 random bytes naming the vault in its bucket (layout descriptor, manifest, object headers).
--                      Stable for the vault's life and across a restore into a new instance.
--   files.object_uid   16 random bytes naming the file's object (`o/<uid>` under opaque_v1). Assigned when the files
--                      row is created (FUSE create, uploads, sync downloads, copies: a copy is a new file); kept by
--                      rename, move, overwrite and key rotation.
--   s3.storage_layout  internal and versioned, never a user choice: `transparent` (readable keys and plaintext
--                      objects; encrypt_upstream = false), `path_v0` (today's encrypted layout: path keys, legacy GCM
--                      objects, plaintext index) or `opaque_v1` (spec 01). The CHECK ties it to encrypt_upstream.
--                      New encrypting vaults stay path_v0 until opaque_v1 leaves internal staging (the restore drill,
--                      #371); the daemon refuses opaque_v1 outside test mode.
--
-- Uids are raw CSPRNG bytes from libsodium (crypto::id::newObjectUid), not UUIDs PostgreSQL generates (those carry
-- version bits): UUID is only the 16-byte column type. This file adds them nullable; the deployer's data step for this
-- file (seed/SqlDeployer, kMigrationDataSteps) assigns one to every existing vault and file in the same transaction,
-- and 123_object_uids_required.sql then makes them NOT NULL. Neither uid ever changes once set (triggers below).
--
-- Existing rows: s3.encrypt_upstream NULL was always read as true (vault::model::S3Vault) and becomes TRUE; encrypting
-- vaults get path_v0, the others transparent. Idempotent and safe on upgraded installs.

ALTER TABLE vault ADD COLUMN IF NOT EXISTS uid UUID;
CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_uid ON vault (uid);

-- Unique across the instance, which is stricter than the spec's per vault: a bucket binds to one vault here, so no two
-- vaults can hold the same file uids.
ALTER TABLE files ADD COLUMN IF NOT EXISTS object_uid UUID;
CREATE UNIQUE INDEX IF NOT EXISTS idx_files_object_uid ON files (object_uid);

UPDATE s3 SET encrypt_upstream = TRUE WHERE encrypt_upstream IS NULL;
ALTER TABLE s3 ALTER COLUMN encrypt_upstream SET NOT NULL;

ALTER TABLE s3 ADD COLUMN IF NOT EXISTS storage_layout TEXT;
UPDATE s3
SET storage_layout = CASE WHEN encrypt_upstream THEN 'path_v0' ELSE 'transparent' END
WHERE storage_layout IS NULL;
ALTER TABLE s3 ALTER COLUMN storage_layout SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 's3'::regclass AND conname = 's3_storage_layout_check') THEN
        ALTER TABLE s3 ADD CONSTRAINT s3_storage_layout_check
            CHECK ((encrypt_upstream AND storage_layout IN ('path_v0', 'opaque_v1')) OR
                   (NOT encrypt_upstream AND storage_layout = 'transparent'));
    END IF;
END
$$;

-- A uid names objects and manifests outside the database: once assigned it never changes. Assigning one (NULL → uid)
-- is allowed: that is the backfill.
CREATE OR REPLACE FUNCTION vh_uid_immutable() RETURNS TRIGGER AS $$
BEGIN
    IF to_jsonb(OLD) -> TG_ARGV[0] <> 'null'::jsonb AND
       to_jsonb(OLD) -> TG_ARGV[0] IS DISTINCT FROM to_jsonb(NEW) -> TG_ARGV[0] THEN
        RAISE EXCEPTION '%.% cannot change once assigned', TG_TABLE_NAME, TG_ARGV[0];
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS vh_uid_immutable ON vault;
CREATE TRIGGER vh_uid_immutable BEFORE UPDATE OF uid ON vault FOR EACH ROW EXECUTE FUNCTION vh_uid_immutable('uid');

DROP TRIGGER IF EXISTS vh_uid_immutable ON files;
CREATE TRIGGER vh_uid_immutable BEFORE UPDATE OF object_uid ON files FOR EACH ROW
    EXECUTE FUNCTION vh_uid_immutable('object_uid');
