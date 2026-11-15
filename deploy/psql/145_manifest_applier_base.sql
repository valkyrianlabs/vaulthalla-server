-- The first pieces of the manifest applier (design/sync/manifest-applier.md, work items 1 and 3).
--
--   recovery_snapshot.uid               a snapshot's identity in the manifest, the same on every server that holds
--                                       the record (recovery_snapshot.id is a per-server sequence: two servers'
--                                       snapshot 7 are different snapshots). 16 raw bytes from libsodium, assigned by
--                                       the manifest collector the first time it lists a ready snapshot, never by
--                                       PostgreSQL; a restore keeps the manifest's. Immutable once set
--                                       (vh_uid_immutable, 122_storage_layout.sql).
--   remote_manifest_state.base_root     the local base copy of the recorded root: its sealed bytes, written in the
--   remote_manifest_base                transaction that records it, and the sealed bytes of every segment and
--                                       snapshot segment it names, by sid (a sid no longer named is deleted). The
--                                       merge base after a restart and after the bucket collected that root.
--   remote_manifest_state.applying_*    the root an apply is taking in (epoch, SHA-256): set before its first batch,
--                                       cleared by the record of that root; nothing is published while it is set.
--
-- Idempotent and safe on upgraded installs: new nullable columns, a new table, a new index and trigger; nothing existing
-- changes. Existing snapshots get their uid at the vault's next publish; existing vaults have no base copy until their
-- next recorded root, and until then a cold start merges as before (on the bucket's head).

ALTER TABLE recovery_snapshot ADD COLUMN IF NOT EXISTS uid UUID DEFAULT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_recovery_snapshot_uid ON recovery_snapshot (vault_id, uid) WHERE uid IS NOT NULL;
DROP TRIGGER IF EXISTS vh_uid_immutable ON recovery_snapshot;
CREATE TRIGGER vh_uid_immutable BEFORE UPDATE OF uid ON recovery_snapshot FOR EACH ROW
    EXECUTE FUNCTION vh_uid_immutable('uid');

ALTER TABLE remote_manifest_state ADD COLUMN IF NOT EXISTS base_root BYTEA DEFAULT NULL;
ALTER TABLE remote_manifest_state ADD COLUMN IF NOT EXISTS applying_epoch BIGINT DEFAULT NULL;
ALTER TABLE remote_manifest_state ADD COLUMN IF NOT EXISTS applying_root_sha256 TEXT DEFAULT NULL;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'remote_manifest_state'::regclass
                     AND conname = 'remote_manifest_state_applying_check') THEN
        ALTER TABLE remote_manifest_state ADD CONSTRAINT remote_manifest_state_applying_check
            CHECK ((applying_epoch IS NULL) = (applying_root_sha256 IS NULL) AND
                   (applying_epoch IS NULL OR (applying_epoch >= 1 AND applying_root_sha256 ~ '^[0-9a-f]{64}$')));
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS remote_manifest_base
(
    vault_id      INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    sid           TEXT        NOT NULL,
    object_sha256 TEXT        NOT NULL CHECK (object_sha256 ~ '^[0-9a-f]{64}$'),
    bytes         BYTEA       NOT NULL,
    stored_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (vault_id, sid)
);
