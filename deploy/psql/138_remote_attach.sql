-- Attaching a remote to a local vault (design/storage/attach-remote.md): an existing local vault becomes an
-- encrypted, opaque_v1, bucket-backed vault in place, keeping its id, keys, RBAC, shares and files. Operator-started
-- per vault (`vh vault remote attach`); nothing here runs on upgrade, and a vault without a row is never touched.
--
--   vault_remote_attach       one row per vault that was asked to attach a remote: the bucket it reserves, the
--                             bucket's probed write capability (spec 06 §7), the state, the cost estimate and usage,
--                             and when each step happened. Until `cutover` the vault is still local and untouched: a
--                             `failed` attach resumes when it is started again, an `aborted` one deleted exactly what
--                             its items list.
--   vault_remote_attach_item  everything the attach wrote to the bucket: each file's content object (o/<uid>), each
--                             recovery envelope (.vaulthalla/key/<kid>) and the manifest's objects (layout hint,
--                             segments, root), with the provider's ETag and version id. These rows are the only list
--                             an abort and the orphan cleanup may delete from, always by version id where the bucket
--                             keeps versions.
--   vault_key_envelope.envelope
--                             a local vault has no bucket to hold its recovery recipients' KEV1 envelopes, so their
--                             bytes are kept here (ciphertext to the customer's own recipient key; nothing here opens
--                             without the recipient's seed). An attach copies them into the bucket, and the cutover
--                             clears the column: from then on the bucket is where they live, as for any S3 vault.
--
-- Additive and idempotent: two new tables and one nullable column, safe on upgraded installs. No existing row changes.

CREATE TABLE IF NOT EXISTS vault_remote_attach
(
    vault_id           INTEGER     PRIMARY KEY REFERENCES vault (id) ON DELETE CASCADE,
    origin             TEXT        NOT NULL DEFAULT 'byos' CHECK (origin IN ('byos', 'cloud')),
    api_key_id         INTEGER     REFERENCES api_keys (id) ON DELETE SET NULL,
    bucket             TEXT        NOT NULL CHECK (bucket <> ''),
    storage_tier_id    TEXT        DEFAULT NULL,
    manifest_publish   TEXT        DEFAULT NULL,
    bucket_probe       JSONB       DEFAULT NULL,
    versioned          BOOLEAN     DEFAULT NULL,   -- listings and deletes go by version id (ListObjectVersions)
    state              TEXT        NOT NULL CHECK (state IN ('preparing', 'uploading', 'catching_up', 'verifying',
                                                             'cutover', 'done', 'failed', 'aborted')),
    started_by         INTEGER     REFERENCES users (id) ON DELETE SET NULL,
    started_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    accept_unpriced    BOOLEAN     NOT NULL DEFAULT FALSE,
    attempts           INTEGER     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    passes             INTEGER     NOT NULL DEFAULT 0 CHECK (passes >= 0),
    verified_at        TIMESTAMPTZ DEFAULT NULL,
    cutover_at         TIMESTAMPTZ DEFAULT NULL,
    done_at            TIMESTAMPTZ DEFAULT NULL,
    aborted_at         TIMESTAMPTZ DEFAULT NULL,
    abort_requested_at TIMESTAMPTZ DEFAULT NULL,
    abort_requested_by INTEGER     REFERENCES users (id) ON DELETE SET NULL,
    rotation_queued_at TIMESTAMPTZ DEFAULT NULL,   -- a key rotation asked for meanwhile: started once the attach ends
    estimate           JSONB       DEFAULT NULL,
    usage              JSONB       DEFAULT NULL,
    manifest           JSONB       DEFAULT NULL,   -- the root the verification published (epoch, hash, ETag, sids, version)
    first_pass         JSONB       DEFAULT NULL,   -- the first sync pass after the cutover
    last_error         TEXT        DEFAULT NULL,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT vault_remote_attach_publish CHECK (manifest_publish IS NULL
                                                  OR (manifest_publish IN ('conditional', 'version_log')
                                                      AND bucket_probe IS NOT NULL)),
    CONSTRAINT vault_remote_attach_cutover CHECK ((state IN ('cutover', 'done')) = (cutover_at IS NOT NULL)),
    CONSTRAINT vault_remote_attach_done CHECK ((state = 'done') = (done_at IS NOT NULL)),
    CONSTRAINT vault_remote_attach_aborted CHECK ((state = 'aborted') = (aborted_at IS NOT NULL))
);

-- The reservation (precondition 4): one attach per (key, bucket) while it can still write there. After the cutover the
-- s3 row's own UNIQUE (api_key_id, bucket) holds the bucket.
CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_remote_attach_reservation
    ON vault_remote_attach (api_key_id, bucket) WHERE state NOT IN ('aborted', 'done');

CREATE TABLE IF NOT EXISTS vault_remote_attach_item
(
    id              BIGSERIAL   PRIMARY KEY,
    vault_id        INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    kind            TEXT        NOT NULL CHECK (kind IN ('content', 'envelope', 'metadata', 'orphan')),
    file_id         INTEGER     DEFAULT NULL,       -- the live file whose content this object is (content, orphan)
    object_key      TEXT        NOT NULL CHECK (object_key <> ''),
    generation      TEXT        DEFAULT NULL,       -- the generation of the bytes sent (files.encryption_iv form)
    key_version     INTEGER     DEFAULT NULL,
    plaintext_bytes BIGINT      DEFAULT NULL,
    content_hash    TEXT        DEFAULT NULL,
    size            BIGINT      DEFAULT NULL,       -- bytes stored in the bucket
    etag            TEXT        DEFAULT NULL,
    version_id      TEXT        DEFAULT NULL,       -- NULL: the bucket keeps no versions
    state           TEXT        NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'sent', 'verified', 'stale', 'deleted', 'failed')),
    error           TEXT        DEFAULT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK ((kind IN ('content', 'orphan')) = (file_id IS NOT NULL))
);

-- One current content item per file (a re-sent file's earlier version stays as its own `stale` row until it is deleted).
CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_remote_attach_item_file
    ON vault_remote_attach_item (vault_id, file_id) WHERE kind = 'content' AND state IN ('pending', 'sent', 'verified', 'failed');
CREATE INDEX IF NOT EXISTS idx_vault_remote_attach_item_key
    ON vault_remote_attach_item (vault_id, object_key);

ALTER TABLE vault_key_envelope ADD COLUMN IF NOT EXISTS envelope BYTEA DEFAULT NULL;
