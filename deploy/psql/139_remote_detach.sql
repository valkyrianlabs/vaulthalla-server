-- Detaching a remote from a vault (design/storage/attach-remote.md, "The reverse"): an S3 vault becomes a local vault
-- in place, keeping its id, keys, RBAC, shares and files, with every file's current generation held and verified on
-- this host before the switch. Operator-started per vault (`vh vault remote detach`); nothing here runs on upgrade,
-- and a vault without a row is never touched. The bucket and everything in it are left in place: a detach never
-- writes to or deletes from it.
--
--   vault_remote_detach       one row per vault that was asked to detach its remote: the binding it had (API key and
--                             bucket, for the record), the state, the estimate, and when each step happened. Until
--                             `cutover` the vault is still an S3 vault and syncs as before: a `failed` detach resumes
--                             when it is started again, an `aborted` one changed nothing but the local copies it
--                             fetched (which stay, as any cached copy does).
--   vault_remote_detach_item  what the detach verified locally: each live file's content at its generation (fetched
--                             from the bucket when the file had no local copy), and each recovery envelope whose
--                             bytes it copied from the bucket into vault_key_envelope.envelope. The cutover refuses
--                             while a live file has no verified item at its current generation, or while an envelope
--                             row has no bytes in the database: a local vault keeps its envelopes there (migration 138),
--                             so none is ever left behind in a bucket the vault no longer uses.
--
-- Additive and idempotent: two new tables, safe on upgraded installs. No existing row changes.

CREATE TABLE IF NOT EXISTS vault_remote_detach
(
    vault_id           INTEGER     PRIMARY KEY REFERENCES vault (id) ON DELETE CASCADE,
    api_key_id         INTEGER     REFERENCES api_keys (id) ON DELETE SET NULL,
    bucket             TEXT        NOT NULL CHECK (bucket <> ''),
    state              TEXT        NOT NULL CHECK (state IN ('preparing', 'hydrating', 'verifying', 'cutover', 'done',
                                                             'failed', 'aborted')),
    started_by         INTEGER     REFERENCES users (id) ON DELETE SET NULL,
    started_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    attempts           INTEGER     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    passes             INTEGER     NOT NULL DEFAULT 0 CHECK (passes >= 0),
    verified_at        TIMESTAMPTZ DEFAULT NULL,
    cutover_at         TIMESTAMPTZ DEFAULT NULL,
    done_at            TIMESTAMPTZ DEFAULT NULL,
    aborted_at         TIMESTAMPTZ DEFAULT NULL,
    abort_requested_at TIMESTAMPTZ DEFAULT NULL,
    abort_requested_by INTEGER     REFERENCES users (id) ON DELETE SET NULL,
    estimate           JSONB       DEFAULT NULL,   -- files and bytes to fetch, envelopes to copy, history left in the bucket
    last_error         TEXT        DEFAULT NULL,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT vault_remote_detach_cutover CHECK ((state IN ('cutover', 'done')) = (cutover_at IS NOT NULL)),
    CONSTRAINT vault_remote_detach_done CHECK ((state = 'done') = (done_at IS NOT NULL)),
    CONSTRAINT vault_remote_detach_aborted CHECK ((state = 'aborted') = (aborted_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS vault_remote_detach_item
(
    id              BIGSERIAL   PRIMARY KEY,
    vault_id        INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    kind            TEXT        NOT NULL CHECK (kind IN ('content', 'envelope')),
    file_id         INTEGER     DEFAULT NULL,       -- content: the live file
    kid             TEXT        DEFAULT NULL,       -- envelope: the KEV1 envelope's name (vault_key_envelope.kid)
    generation      TEXT        DEFAULT NULL,       -- content: the generation verified (files.encryption_iv form)
    key_version     INTEGER     DEFAULT NULL,
    size            BIGINT      DEFAULT NULL,       -- sealed bytes on disk
    hydrated        BOOLEAN     NOT NULL DEFAULT FALSE,   -- the detach fetched it from the bucket
    state           TEXT        NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'verified', 'failed')),
    error           TEXT        DEFAULT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK ((kind = 'content') = (file_id IS NOT NULL)),
    CHECK ((kind = 'envelope') = (kid IS NOT NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_remote_detach_item_file
    ON vault_remote_detach_item (vault_id, file_id) WHERE kind = 'content';
CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_remote_detach_item_kid
    ON vault_remote_detach_item (vault_id, kid) WHERE kind = 'envelope';
