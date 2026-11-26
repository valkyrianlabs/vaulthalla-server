-- File contents a mirror has not received yet (server mirror phase 2, wave 2; design/peers/mirror.md "Contents", "As
-- built: sealed contents"; db::query::mirror::PendingContents, mirror::contents). On the mirror server of a mirrored
-- vault (mirror_vault.role = 'mirror'), a file whose row exists but whose sealed bytes have not arrived yet has one
-- row here: the generation, key version, plaintext size and BLAKE2b content hash of the sealed bytes it expects (the
-- core's values, copied from the log), the modification time the backing file gets when it is linked into place, a
-- priority, the attempts made, the last error, and whether it is still waiting or has failed (three failed attempts
-- stop the retries until someone asks for them again). The row goes once the bytes are verified and linked into
-- place, in the same transaction that checks it still expects exactly that generation.
--
-- A side table on purpose: files and its triggers (the change journal, the replication log) and the FUSE hot path are
-- untouched, and nothing here references files (no foreign key, so no trigger is added to it). A row whose file is gone
-- or now names another generation is dropped as superseded when it is next looked at. Nothing writes rows yet but
-- tests and the internal API: the log applier (a later piece) will mark files as expected.
--
-- Idempotent and safe on upgraded installs: a new table and its index only.

CREATE TABLE IF NOT EXISTS mirror_content_pending
(
    vault_id        INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    object_uid      UUID        NOT NULL,
    generation      TEXT        NOT NULL,                   -- files.encryption_iv form ('' for an empty plain file)
    key_version     INTEGER     NOT NULL CHECK (key_version >= 0),
    size_bytes      BIGINT      NOT NULL CHECK (size_bytes >= 0),   -- the plaintext size (files.size_bytes)
    content_hash    TEXT        NOT NULL,                   -- BLAKE2b over the sealed bytes, hex (files.content_hash)
    mtime_us        BIGINT      NOT NULL,                   -- the backing file's modification time, microseconds
    priority        SMALLINT    NOT NULL DEFAULT 0,         -- higher first
    queued          BIGSERIAL,                              -- then the order the file was first expected in
    state           TEXT        NOT NULL DEFAULT 'waiting' CHECK (state IN ('waiting', 'failed')),
    attempts        INTEGER     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error      TEXT,
    expected_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_attempt_at TIMESTAMPTZ,
    PRIMARY KEY (vault_id, object_uid)
);

-- What is outstanding for a vault, in the order it is fetched.
CREATE INDEX IF NOT EXISTS mirror_content_pending_order
    ON mirror_content_pending (vault_id, state, priority DESC, queued);
