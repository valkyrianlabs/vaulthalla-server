-- Resumable HTTP uploads (docs/reference/transfer-protocol.md §3, capability http.upload.resumable).
--
--   upload_session        one row per POST /upload/sessions: who owns it (a user, or one share session), the vault,
--                         and when it was created and last received a part (idle and maximum-age expiry).
--   upload_session_file   one row per file of a session: target path, size, precondition (reject / create-only /
--                         compare-and-swap on a content generation), the AES-256-GCM IV and key version the file is
--                         sealed with, its state, and how much of it is durably sealed in the spool
--                         (<backing>/.upload-spool/<upload id>/, ciphertext only, outside every vault).
--   upload_session_part   one row per stored part (offset, length) and the IV of its own spool encryption. A part
--                         row exists only once the part's bytes are durable.
--
-- Rows are deleted with their session (cancel, expiry); committed files are ordinary files rows by then.
--
-- Idempotent and safe on upgraded installs: new tables only; nothing existing changes.

CREATE TABLE IF NOT EXISTS upload_session
(
    id               TEXT        PRIMARY KEY CHECK (id ~ '^[0-9a-f-]{36}$'),
    mode             TEXT        NOT NULL CHECK (mode IN ('user', 'share')),
    user_id          INTEGER              REFERENCES users (id) ON DELETE CASCADE,
    share_session_id UUID                 REFERENCES share_session (id) ON DELETE CASCADE,
    vault_id         INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    state            TEXT        NOT NULL DEFAULT 'open'
        CHECK (state IN ('open', 'finalizing', 'complete', 'failed', 'cancelled')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK ((mode = 'user' AND user_id IS NOT NULL AND share_session_id IS NULL) OR
           (mode = 'share' AND share_session_id IS NOT NULL AND user_id IS NULL))
);

CREATE INDEX IF NOT EXISTS idx_upload_session_user ON upload_session (user_id);
CREATE INDEX IF NOT EXISTS idx_upload_session_activity ON upload_session (last_activity_at);

CREATE TABLE IF NOT EXISTS upload_session_file
(
    upload_id          TEXT    NOT NULL REFERENCES upload_session (id) ON DELETE CASCADE,
    file_id            TEXT    NOT NULL CHECK (file_id ~ '^[A-Za-z0-9_-]{1,96}$'),
    ordinal            INTEGER NOT NULL CHECK (ordinal >= 0),
    path               TEXT    NOT NULL,
    display_path       TEXT    NOT NULL,
    size_bytes         BIGINT  NOT NULL CHECK (size_bytes >= 0),
    mime_type          TEXT             DEFAULT NULL,
    precondition       TEXT    NOT NULL CHECK (precondition IN ('reject', 'create_only', 'if_match')),
    expected_source_id TEXT             DEFAULT NULL,
    encryption_iv      TEXT    NOT NULL DEFAULT '',
    key_version        INTEGER NOT NULL DEFAULT 0 CHECK (key_version >= 0),
    state              TEXT    NOT NULL DEFAULT 'receiving'
        CHECK (state IN ('receiving', 'sealing', 'committing', 'committed', 'failed')),
    sealed_bytes       BIGINT  NOT NULL DEFAULT 0 CHECK (sealed_bytes >= 0),
    error_code         TEXT             DEFAULT NULL,
    error_message      TEXT             DEFAULT NULL,
    error_etag         TEXT             DEFAULT NULL,
    entry_id           INTEGER          DEFAULT NULL,
    share_upload_id    UUID             DEFAULT NULL,
    share_parent_path  TEXT             DEFAULT NULL,
    PRIMARY KEY (upload_id, file_id),
    UNIQUE (upload_id, ordinal),
    CHECK (sealed_bytes <= size_bytes),
    CHECK ((precondition = 'if_match') = (expected_source_id IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS upload_session_part
(
    upload_id     TEXT        NOT NULL,
    file_id       TEXT        NOT NULL,
    offset_bytes  BIGINT      NOT NULL CHECK (offset_bytes >= 0),
    length_bytes  BIGINT      NOT NULL CHECK (length_bytes > 0),
    encryption_iv TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (upload_id, file_id, offset_bytes),
    FOREIGN KEY (upload_id, file_id) REFERENCES upload_session_file (upload_id, file_id) ON DELETE CASCADE
);

COMMENT ON TABLE upload_session IS
    'Resumable HTTP upload sessions (POST /upload/sessions). Spool: <backing>/.upload-spool/<id>/, ciphertext only.';
COMMENT ON TABLE upload_session_part IS
    'Durably stored parts of a resumable upload file; each part is its own AES-256-GCM message in the spool.';
