-- Bucket layout migration path_v0 -> opaque_v1 (#373, design/encryption/01-provider-blind-storage.md §6, consolidated
-- scope of 2026-11-06): an encrypting S3/R2 vault's path-keyed legacy objects are re-sealed as VHF1 objects o/<uid>,
-- verified by actual decryption, the vault is cut over, and the old path-keyed objects are deleted only by an operator
-- after a waiting period, by explicit version id, never while a protection lock, Object Lock retention or legal hold
-- holds them. Operator-started per vault (`vh vault migrate-layout`); nothing here runs on upgrade.
--
--   vault_layout_migration       one row per vault that was asked to migrate: its state, the waiting period, the
--                                cost estimate and the usage, and when each step happened. A vault whose migration
--                                failed (state 'failed') is still path_v0 and nothing of it was deleted.
--   vault_layout_migration_item  the inventory: every legacy object version, delete marker and the old index manifest
--                                the bucket listed (kind version | marker | index), each file's current content when
--                                it is uploaded from its local copy (current), and every pending backlog generation
--                                (backlog). The legacy rows are the only list cleanup may delete from. The legacy key
--                                of a version whose file no row names any more stays here, so its history keeps its
--                                path (db::query::sync::ObjectIdentity::pathOfUid).
--
-- Additive and idempotent: two new tables, safe on upgraded installs. No existing row changes.

CREATE TABLE IF NOT EXISTS vault_layout_migration
(
    vault_id             INTEGER     PRIMARY KEY REFERENCES vault (id) ON DELETE CASCADE,
    from_layout          TEXT        NOT NULL DEFAULT 'path_v0' CHECK (from_layout = 'path_v0'),
    to_layout            TEXT        NOT NULL DEFAULT 'opaque_v1' CHECK (to_layout = 'opaque_v1'),
    state                TEXT        NOT NULL CHECK (state IN ('copying', 'verifying', 'failed', 'cut_over', 'cleanup',
                                                               'cleanup_blocked', 'complete')),
    started_by           INTEGER     REFERENCES users (id) ON DELETE SET NULL,
    started_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    accept_unpriced      BOOLEAN     NOT NULL DEFAULT FALSE,
    versioned            BOOLEAN     DEFAULT NULL,   -- the inventory came from ListObjectVersions (version ids)
    wait_days            INTEGER     NOT NULL CHECK (wait_days BETWEEN 1 AND 365),
    attempts             INTEGER     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    verified_at          TIMESTAMPTZ DEFAULT NULL,
    cutover_at           TIMESTAMPTZ DEFAULT NULL,
    cleanup_after        TIMESTAMPTZ DEFAULT NULL,
    manifest_verified_at TIMESTAMPTZ DEFAULT NULL,
    cleanup_confirmed_at TIMESTAMPTZ DEFAULT NULL,
    cleanup_confirmed_by INTEGER     REFERENCES users (id) ON DELETE SET NULL,
    cleanup_run_at       TIMESTAMPTZ DEFAULT NULL,
    completed_at         TIMESTAMPTZ DEFAULT NULL,
    estimate             JSONB       DEFAULT NULL,
    usage                JSONB       DEFAULT NULL,
    last_error           TEXT        DEFAULT NULL,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK ((state IN ('copying', 'verifying', 'failed')) = (cutover_at IS NULL))
);

CREATE TABLE IF NOT EXISTS vault_layout_migration_item
(
    id                   BIGSERIAL   PRIMARY KEY,
    vault_id             INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    kind                 TEXT        NOT NULL CHECK (kind IN ('version', 'marker', 'index', 'current', 'backlog')),
    legacy_key           TEXT        DEFAULT NULL,
    legacy_version_id    TEXT        DEFAULT NULL,   -- NULL: an unversioned listing (no version ids)
    legacy_etag          TEXT        DEFAULT NULL,
    legacy_size          BIGINT      DEFAULT NULL,
    legacy_last_modified TIMESTAMPTZ DEFAULT NULL,
    legacy_storage_class TEXT        DEFAULT NULL,
    legacy_latest        BOOLEAN     NOT NULL DEFAULT FALSE,
    seq                  INTEGER     NOT NULL DEFAULT 0,  -- order within the object: oldest first, current content last
    file_id              INTEGER     DEFAULT NULL,       -- the live file whose current content this item is
    generation_id        BIGINT      DEFAULT NULL,       -- file_versions.id of a backlog item
    object_uid           UUID        DEFAULT NULL,       -- the o/<uid> the item was re-sealed into
    source_generation    TEXT        DEFAULT NULL,
    key_version          INTEGER     DEFAULT NULL,
    plaintext_bytes      BIGINT      DEFAULT NULL,
    content_hash         TEXT        DEFAULT NULL,
    target_version_id    TEXT        DEFAULT NULL,
    target_etag          TEXT        DEFAULT NULL,
    target_generation    TEXT        DEFAULT NULL,
    target_size          BIGINT      DEFAULT NULL,
    state                TEXT        NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'verified', 'superseded', 'skipped', 'failed')),
    reason               TEXT        DEFAULT NULL,
    error                TEXT        DEFAULT NULL,
    cleanup_state        TEXT        DEFAULT NULL CHECK (cleanup_state IS NULL OR cleanup_state IN ('deleted', 'blocked')),
    cleanup_reason       TEXT        DEFAULT NULL,
    retain_until         TIMESTAMPTZ DEFAULT NULL,
    cleanup_attempts     INTEGER     NOT NULL DEFAULT 0 CHECK (cleanup_attempts >= 0),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK ((kind IN ('version', 'marker', 'index')) = (legacy_key IS NOT NULL)),
    CHECK (cleanup_state IS NULL OR kind IN ('version', 'marker', 'index'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_layout_migration_item_legacy
    ON vault_layout_migration_item (vault_id, legacy_key, coalesce(legacy_version_id, ''))
    WHERE legacy_key IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_layout_migration_item_current
    ON vault_layout_migration_item (vault_id, file_id) WHERE kind = 'current';
CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_layout_migration_item_backlog
    ON vault_layout_migration_item (vault_id, generation_id) WHERE kind = 'backlog';
CREATE INDEX IF NOT EXISTS idx_vault_layout_migration_item_uid
    ON vault_layout_migration_item (vault_id, object_uid);
