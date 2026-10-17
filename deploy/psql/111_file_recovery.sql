-- File recovery: local snapshots and provider-native object versioning.
--
--   vault_recovery_policy       a vault's recovery preference (off | local_snapshots | provider_versioning), its
--                               snapshot quota, its versioning cost alert threshold, and the opt-in local versioning
--                               harness with its retention. No row = off, local versioning off.
--   recovery_blob               one immutable sealed generation of file content held locally (AES-256-GCM, the IV and
--                               key version it was sealed with). Snapshots of an unchanged file share a blob.
--   recovery_snapshot           an explicit, user-created recovery point of one file or one directory tree.
--   file_versions               (existing, previously unused) one retained file generation: a snapshot member or a
--                               version local versioning kept on a content change, which is also the vault's ordered
--                               upstream backlog while unsent. Its file_id cascade is replaced by SET NULL: retained
--                               generations outlive the live file.
--   upstream_bucket.versioning_* / noncurrent_retention_*
--                               what Vaulthalla knows and decided about a bucket's provider versioning. Versioning is
--                               bucket-scoped and lives with the bucket identity, never with a vault preference.
--   upstream_object_version     metadata of provider object versions and delete markers (never bodies): written by
--                               this daemon's own PUT/COPY (origin 'vaulthalla') or seen in a listing ('observed').
--   vault_upstream_usage_daily  local, per-vault operational counters that cost estimates are computed from. Nothing
--                               here is ever sent anywhere.
--   recovery_plan               a restore plan (items, conflicts, cost) a person accepted or may accept; restores are
--                               resumable from it.
--
-- A trigger keeps retired vault keys while recoverable data still needs them.
--
-- Idempotent and safe on upgraded installs: new tables, additive columns, guarded constraint changes. No existing data
-- changes meaning: every vault starts with no policy row (off).

CREATE TABLE IF NOT EXISTS vault_recovery_policy
(
    vault_id             INTEGER PRIMARY KEY REFERENCES vault (id) ON DELETE CASCADE,
    mode                 TEXT NOT NULL DEFAULT 'off'
        CHECK (mode IN ('off', 'local_snapshots', 'provider_versioning')),
    snapshot_quota_bytes BIGINT DEFAULT NULL CHECK (snapshot_quota_bytes IS NULL OR snapshot_quota_bytes >= 0),
    cost_alert_monthly   NUMERIC(20, 8) DEFAULT NULL CHECK (cost_alert_monthly IS NULL OR cost_alert_monthly >= 0),
    cost_alert_currency  TEXT DEFAULT NULL,
    -- Local versioning: an opt-in harness, independent of the mode above, that keeps the prior sealed generation of a
    -- file on every content change and queues unsent generations as the vault's upstream backlog.
    local_versioning     BOOLEAN NOT NULL DEFAULT FALSE,
    version_keep_last    INTEGER DEFAULT NULL CHECK (version_keep_last IS NULL OR version_keep_last BETWEEN 1 AND 10000),
    version_max_age_days INTEGER DEFAULT NULL CHECK (version_max_age_days IS NULL OR version_max_age_days BETWEEN 1 AND 36500),
    version_quota_bytes  BIGINT DEFAULT NULL CHECK (version_quota_bytes IS NULL OR version_quota_bytes >= 0),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by           INTEGER REFERENCES users (id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS recovery_blob
(
    id              BIGSERIAL PRIMARY KEY,
    vault_id        INTEGER NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    storage_name    TEXT NOT NULL UNIQUE CHECK (storage_name ~ '^[a-z0-9]{32}$'),
    encryption_iv   TEXT NOT NULL DEFAULT '',
    key_version     INTEGER NOT NULL DEFAULT 0,
    cipher_bytes    BIGINT NOT NULL CHECK (cipher_bytes >= 0),
    plaintext_bytes BIGINT NOT NULL CHECK (plaintext_bytes >= 0),
    content_hash    TEXT DEFAULT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Same IV + key version = the same sealed bytes (a copy keeps both; every write draws a fresh IV).
CREATE UNIQUE INDEX IF NOT EXISTS uq_recovery_blob_generation
    ON recovery_blob (vault_id, encryption_iv, key_version) WHERE encryption_iv <> '';
CREATE INDEX IF NOT EXISTS idx_recovery_blob_vault_key ON recovery_blob (vault_id, key_version);

CREATE TABLE IF NOT EXISTS recovery_snapshot
(
    id                  BIGSERIAL PRIMARY KEY,
    vault_id            INTEGER NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    name                TEXT DEFAULT NULL CHECK (name IS NULL OR length(name) BETWEEN 1 AND 200),
    root_path           TEXT NOT NULL CHECK (root_path LIKE '/%'),
    root_type           TEXT NOT NULL CHECK (root_type IN ('file', 'directory')),
    root_entry_id       INTEGER DEFAULT NULL,
    state               TEXT NOT NULL DEFAULT 'creating' CHECK (state IN ('creating', 'ready', 'deleting', 'failed')),
    file_count          INTEGER NOT NULL DEFAULT 0,
    directory_count     INTEGER NOT NULL DEFAULT 0,
    plaintext_bytes     BIGINT NOT NULL DEFAULT 0,
    empty_directories   TEXT[] NOT NULL DEFAULT '{}',
    skipped             JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at        TIMESTAMPTZ DEFAULT NULL,
    created_by          INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_by_name     TEXT DEFAULT NULL,
    error               TEXT DEFAULT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_recovery_snapshot_name
    ON recovery_snapshot (vault_id, name) WHERE name IS NOT NULL AND state <> 'deleting';
CREATE INDEX IF NOT EXISTS idx_recovery_snapshot_vault ON recovery_snapshot (vault_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_recovery_snapshot_root ON recovery_snapshot (vault_id, root_path text_pattern_ops);

-- file_versions becomes one retained file generation: a snapshot member (origin 'snapshot', snapshot_id set) or a
-- generation local versioning kept when the file's content changed (origin 'version'). The row describes the retained
-- content: it was the file's content from source_updated_at until created_at.
ALTER TABLE file_versions ADD COLUMN IF NOT EXISTS vault_id INTEGER REFERENCES vault (id) ON DELETE CASCADE;
ALTER TABLE file_versions ADD COLUMN IF NOT EXISTS snapshot_id BIGINT REFERENCES recovery_snapshot (id) ON DELETE CASCADE;
ALTER TABLE file_versions ADD COLUMN IF NOT EXISTS blob_id BIGINT REFERENCES recovery_blob (id);
ALTER TABLE file_versions ADD COLUMN IF NOT EXISTS rel_path TEXT DEFAULT NULL;
ALTER TABLE file_versions ADD COLUMN IF NOT EXISTS mode INTEGER DEFAULT NULL;
ALTER TABLE file_versions ADD COLUMN IF NOT EXISTS source_updated_at TIMESTAMPTZ DEFAULT NULL;
ALTER TABLE file_versions ADD COLUMN IF NOT EXISTS origin TEXT NOT NULL DEFAULT 'snapshot';
ALTER TABLE file_versions ADD COLUMN IF NOT EXISTS reason TEXT DEFAULT NULL;
-- Upstream backlog of a local version: 'none' (local vault, or not to be sent), 'pending' (to be replayed upstream in
-- version_number order), 'sent' (the provider holds it: upstream_version_id), 'skipped' (superseded without replay
-- because the bucket keeps no history).
ALTER TABLE file_versions ADD COLUMN IF NOT EXISTS upstream_state TEXT NOT NULL DEFAULT 'none';
ALTER TABLE file_versions ADD COLUMN IF NOT EXISTS upstream_key TEXT DEFAULT NULL;
ALTER TABLE file_versions ADD COLUMN IF NOT EXISTS upstream_version_id TEXT DEFAULT NULL;
ALTER TABLE file_versions ADD COLUMN IF NOT EXISTS upstream_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE file_versions ADD COLUMN IF NOT EXISTS upstream_error TEXT DEFAULT NULL;
ALTER TABLE file_versions ADD COLUMN IF NOT EXISTS upstream_sent_at TIMESTAMPTZ DEFAULT NULL;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'file_versions_origin_check') THEN
        ALTER TABLE file_versions ADD CONSTRAINT file_versions_origin_check
            CHECK (origin IN ('snapshot', 'version'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'file_versions_reason_check') THEN
        ALTER TABLE file_versions ADD CONSTRAINT file_versions_reason_check
            CHECK (reason IS NULL OR reason IN ('overwrite', 'truncate', 'delete', 'download', 'restore', 'conflict'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'file_versions_upstream_state_check') THEN
        ALTER TABLE file_versions ADD CONSTRAINT file_versions_upstream_state_check
            CHECK (upstream_state IN ('none', 'pending', 'sent', 'skipped'));
    END IF;
END $$;

-- A live file's deletion must never take its retained generations with it (it used to CASCADE).
DO $$
DECLARE
    con RECORD;
BEGIN
    FOR con IN
        SELECT c.conname
        FROM pg_constraint c
        JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
        WHERE c.conrelid = 'file_versions'::regclass
          AND c.contype = 'f'
          AND a.attname = 'file_id'
          AND c.confdeltype <> 'n'
    LOOP
        EXECUTE format('ALTER TABLE file_versions DROP CONSTRAINT %I', con.conname);
    END LOOP;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey)
        WHERE c.conrelid = 'file_versions'::regclass
          AND c.contype = 'f'
          AND a.attname = 'file_id'
    ) THEN
        ALTER TABLE file_versions
            ADD CONSTRAINT file_versions_file_id_fkey
            FOREIGN KEY (file_id) REFERENCES files (fs_entry_id) ON DELETE SET NULL;
    END IF;
END $$;

ALTER TABLE file_versions ALTER COLUMN file_id DROP NOT NULL;
ALTER TABLE file_versions ALTER COLUMN content_hash DROP NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_file_versions_snapshot_path
    ON file_versions (snapshot_id, rel_path) WHERE snapshot_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_file_versions_vault_path
    ON file_versions (vault_id, path text_pattern_ops) WHERE vault_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_file_versions_blob ON file_versions (blob_id) WHERE blob_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_file_versions_file ON file_versions (file_id, version_number DESC) WHERE file_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_file_versions_backlog
    ON file_versions (vault_id, file_id, version_number) WHERE upstream_state = 'pending';

-- Provider versioning state, per bucket identity.
ALTER TABLE upstream_bucket ADD COLUMN IF NOT EXISTS versioning_status TEXT DEFAULT NULL;
ALTER TABLE upstream_bucket ADD COLUMN IF NOT EXISTS versioning_checked_at TIMESTAMPTZ DEFAULT NULL;
ALTER TABLE upstream_bucket ADD COLUMN IF NOT EXISTS versioning_enabled_at TIMESTAMPTZ DEFAULT NULL;
ALTER TABLE upstream_bucket ADD COLUMN IF NOT EXISTS versioning_enabled_by INTEGER REFERENCES users (id) ON DELETE SET NULL;
ALTER TABLE upstream_bucket ADD COLUMN IF NOT EXISTS versioning_enabled_by_vaulthalla BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE upstream_bucket ADD COLUMN IF NOT EXISTS versioning_settles_at TIMESTAMPTZ DEFAULT NULL;
ALTER TABLE upstream_bucket ADD COLUMN IF NOT EXISTS versioning_mfa_delete BOOLEAN DEFAULT NULL;
ALTER TABLE upstream_bucket ADD COLUMN IF NOT EXISTS object_lock_enabled BOOLEAN DEFAULT NULL;
ALTER TABLE upstream_bucket ADD COLUMN IF NOT EXISTS noncurrent_retention_mode TEXT NOT NULL DEFAULT 'unset';
ALTER TABLE upstream_bucket ADD COLUMN IF NOT EXISTS noncurrent_retention_days INTEGER DEFAULT NULL;
ALTER TABLE upstream_bucket ADD COLUMN IF NOT EXISTS noncurrent_retention_set_at TIMESTAMPTZ DEFAULT NULL;
ALTER TABLE upstream_bucket ADD COLUMN IF NOT EXISTS noncurrent_retention_set_by INTEGER REFERENCES users (id) ON DELETE SET NULL;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'upstream_bucket_versioning_status_check') THEN
        ALTER TABLE upstream_bucket ADD CONSTRAINT upstream_bucket_versioning_status_check
            CHECK (versioning_status IS NULL OR versioning_status IN ('unversioned', 'enabled', 'suspended', 'unknown'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'upstream_bucket_noncurrent_retention_check') THEN
        ALTER TABLE upstream_bucket ADD CONSTRAINT upstream_bucket_noncurrent_retention_check
            CHECK ((noncurrent_retention_mode = 'days' AND noncurrent_retention_days BETWEEN 1 AND 36500)
                OR (noncurrent_retention_mode IN ('unset', 'indefinite') AND noncurrent_retention_days IS NULL));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS upstream_object_version
(
    id                  BIGSERIAL PRIMARY KEY,
    vault_id            INTEGER NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    object_key          TEXT NOT NULL,
    version_id          TEXT NOT NULL,
    is_delete_marker    BOOLEAN NOT NULL DEFAULT FALSE,
    is_latest           BOOLEAN NOT NULL DEFAULT FALSE,
    etag                TEXT DEFAULT NULL,
    size_bytes          BIGINT DEFAULT NULL,
    storage_class       TEXT DEFAULT NULL,
    last_modified       TIMESTAMPTZ DEFAULT NULL,
    origin              TEXT NOT NULL CHECK (origin IN ('vaulthalla', 'observed')),
    encrypted           BOOLEAN DEFAULT NULL,
    encryption_iv       TEXT DEFAULT NULL,
    key_version         INTEGER DEFAULT NULL,
    content_hash        TEXT DEFAULT NULL,
    plaintext_bytes     BIGINT DEFAULT NULL,
    became_noncurrent_at TIMESTAMPTZ DEFAULT NULL,
    gone_at             TIMESTAMPTZ DEFAULT NULL,
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (vault_id, object_key, version_id)
);

CREATE INDEX IF NOT EXISTS idx_upstream_object_version_key
    ON upstream_object_version (vault_id, object_key text_pattern_ops, last_modified DESC);
CREATE INDEX IF NOT EXISTS idx_upstream_object_version_noncurrent
    ON upstream_object_version (vault_id, became_noncurrent_at) WHERE gone_at IS NULL AND NOT is_latest;
CREATE INDEX IF NOT EXISTS idx_upstream_object_version_key_version
    ON upstream_object_version (vault_id, key_version) WHERE gone_at IS NULL;

CREATE TABLE IF NOT EXISTS vault_upstream_usage_daily
(
    vault_id                 INTEGER NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    day                      DATE NOT NULL,
    list_requests            BIGINT NOT NULL DEFAULT 0,
    head_requests            BIGINT NOT NULL DEFAULT 0,
    get_requests             BIGINT NOT NULL DEFAULT 0,
    put_requests             BIGINT NOT NULL DEFAULT 0,
    copy_requests            BIGINT NOT NULL DEFAULT 0,
    delete_requests          BIGINT NOT NULL DEFAULT 0,
    multipart_uploads        BIGINT NOT NULL DEFAULT 0,
    multipart_parts          BIGINT NOT NULL DEFAULT 0,
    uploaded_bytes           BIGINT NOT NULL DEFAULT 0,
    downloaded_bytes         BIGINT NOT NULL DEFAULT 0,
    first_put_objects        BIGINT NOT NULL DEFAULT 0,
    first_put_bytes          BIGINT NOT NULL DEFAULT 0,
    overwrite_objects        BIGINT NOT NULL DEFAULT 0,
    overwritten_bytes        BIGINT NOT NULL DEFAULT 0,
    deleted_objects          BIGINT NOT NULL DEFAULT 0,
    deleted_bytes            BIGINT NOT NULL DEFAULT 0,
    version_list_requests    BIGINT NOT NULL DEFAULT 0,
    version_restore_requests BIGINT NOT NULL DEFAULT 0,
    version_restore_bytes    BIGINT NOT NULL DEFAULT 0,
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (vault_id, day)
);

CREATE TABLE IF NOT EXISTS recovery_plan
(
    id           BIGSERIAL PRIMARY KEY,
    vault_id     INTEGER NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    token        TEXT NOT NULL,
    source       JSONB NOT NULL,
    destination  TEXT DEFAULT NULL,
    items        JSONB NOT NULL DEFAULT '[]'::jsonb,
    summary      JSONB NOT NULL DEFAULT '{}'::jsonb,
    state        TEXT NOT NULL DEFAULT 'planned'
        CHECK (state IN ('planned', 'running', 'done', 'partial', 'failed', 'expired')),
    result       JSONB DEFAULT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at   TIMESTAMPTZ NOT NULL,
    started_at   TIMESTAMPTZ DEFAULT NULL,
    completed_at TIMESTAMPTZ DEFAULT NULL,
    created_by   INTEGER REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_recovery_plan_vault ON recovery_plan (vault_id, created_at DESC);

-- A retired key may only go while nothing recoverable was sealed with it. A vault's own deletion (cascade) still
-- removes its keys: the vault row is already gone when the cascade reaches vault_keys_trashed.
CREATE OR REPLACE FUNCTION recovery_guard_retired_vault_key() RETURNS trigger AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM vault WHERE id = OLD.vault_id)
       AND (EXISTS (SELECT 1 FROM recovery_blob WHERE vault_id = OLD.vault_id AND key_version = OLD.version)
            OR EXISTS (SELECT 1 FROM upstream_object_version
                       WHERE vault_id = OLD.vault_id AND key_version = OLD.version AND gone_at IS NULL)) THEN
        RAISE EXCEPTION 'vault % key version % is still needed by recoverable data', OLD.vault_id, OLD.version
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    RETURN OLD;
END
$$ LANGUAGE plpgsql;

DO $$
BEGIN
    CREATE TRIGGER recovery_guard_retired_vault_key
        BEFORE DELETE ON vault_keys_trashed
        FOR EACH ROW
        EXECUTE FUNCTION recovery_guard_retired_vault_key();
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;
