-- Encrypted manifest v2 for opaque_v1 vaults (#368, WS3-a; design/encryption/03-metadata-recovery.md §3, §4).
--
--   remote_manifest_state  gains the chain position of the vault's last published root (manifest_key
--                          '.vaulthalla/root'): epoch and the root object's SHA-256, which the reader checks every
--                          root against (rollback, fork, gap). A refused root (rollback or fork) is recorded once, so
--                          the operator is alerted once per root, and gc_at is the last segment collection.
--   remote_manifest_root   the sids each of the vault's last three roots names: garbage collection keeps every
--                          segment one of them names (a reader that loaded an older root a moment ago still finds its
--                          segments). The publisher keeps three rows per vault.
--   directories.uid        the manifest names directories and symlinks by uid like files (files.object_uid): the tree
--   symlinks.uid           is parent uid + name, so a folder rename changes one entry. 16 raw bytes from libsodium,
--                          assigned by the manifest collector the first time it lists the entry, never by PostgreSQL;
--                          immutable once set (vh_uid_immutable, 122_storage_layout.sql).
--   files_trashed          keeps the trashed file's object uid, so the manifest's trash entry names the object.
--     .object_uid
--
-- Idempotent and safe on upgraded installs: new nullable columns and a new table only; nothing existing changes.

ALTER TABLE remote_manifest_state ADD COLUMN IF NOT EXISTS epoch BIGINT DEFAULT NULL;
ALTER TABLE remote_manifest_state ADD COLUMN IF NOT EXISTS root_sha256 TEXT DEFAULT NULL;
ALTER TABLE remote_manifest_state ADD COLUMN IF NOT EXISTS refused_reason TEXT DEFAULT NULL;
ALTER TABLE remote_manifest_state ADD COLUMN IF NOT EXISTS refused_epoch BIGINT DEFAULT NULL;
ALTER TABLE remote_manifest_state ADD COLUMN IF NOT EXISTS refused_root_sha256 TEXT DEFAULT NULL;
ALTER TABLE remote_manifest_state ADD COLUMN IF NOT EXISTS refused_at TIMESTAMPTZ DEFAULT NULL;
ALTER TABLE remote_manifest_state ADD COLUMN IF NOT EXISTS gc_at TIMESTAMPTZ DEFAULT NULL;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'remote_manifest_state'::regclass AND conname = 'remote_manifest_state_chain_check') THEN
        ALTER TABLE remote_manifest_state ADD CONSTRAINT remote_manifest_state_chain_check
            CHECK ((epoch IS NULL) = (root_sha256 IS NULL) AND
                   (epoch IS NULL OR (epoch >= 1 AND root_sha256 ~ '^[0-9a-f]{64}$')));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'remote_manifest_state'::regclass AND conname = 'remote_manifest_state_refused_check') THEN
        ALTER TABLE remote_manifest_state ADD CONSTRAINT remote_manifest_state_refused_check
            CHECK (refused_reason IS NULL OR refused_reason IN ('rollback', 'fork'));
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS remote_manifest_root
(
    vault_id     INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    epoch        BIGINT      NOT NULL CHECK (epoch >= 1),
    root_sha256  TEXT        NOT NULL CHECK (root_sha256 ~ '^[0-9a-f]{64}$'),
    sids         TEXT[]      NOT NULL DEFAULT '{}',
    published_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (vault_id, epoch)
);

ALTER TABLE directories ADD COLUMN IF NOT EXISTS uid UUID;
CREATE UNIQUE INDEX IF NOT EXISTS idx_directories_uid ON directories (uid);
ALTER TABLE symlinks ADD COLUMN IF NOT EXISTS uid UUID;
CREATE UNIQUE INDEX IF NOT EXISTS idx_symlinks_uid ON symlinks (uid);
ALTER TABLE files_trashed ADD COLUMN IF NOT EXISTS object_uid UUID;

DROP TRIGGER IF EXISTS vh_uid_immutable ON directories;
CREATE TRIGGER vh_uid_immutable BEFORE UPDATE OF uid ON directories FOR EACH ROW EXECUTE FUNCTION vh_uid_immutable('uid');

DROP TRIGGER IF EXISTS vh_uid_immutable ON symlinks;
CREATE TRIGGER vh_uid_immutable BEFORE UPDATE OF uid ON symlinks FOR EACH ROW EXECUTE FUNCTION vh_uid_immutable('uid');
