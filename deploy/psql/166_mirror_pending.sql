-- A change made on the mirror (server mirror phase 2, wave 4 piece B; design/peers/mirror.md "A change made on the
-- mirror", "When the core refuses", "As built: a change made on the mirror"; db::query::mirror::Pending,
-- mirror::submit). On the mirror, a person's change to a mirrored vault is applied at once and recorded as pending; it
-- is submitted to the core, which executes it as that person and logs it with the request id in `origin`; the mirror
-- confirms it when those groups come back, or reverts it to the core's state and keeps the person's version (a conflict
-- copy beside it, or a held change) when the core refuses.
--
--   mirror_pending     mirror: one row per change made here and not yet settled with the core, in submission order
--                      (id). `request_id` is the origin the core echoes; `entry_uid` the entry the change is on (a
--                      created entry's uid, chosen here before the change, so both servers give it the same one);
--                      `args` what the core needs to execute it, every entry named by uid; the generation it was based
--                      on and the new one (contents); the person as (this server's node id, users.id); `uids` every
--                      entry the change touched here (what it holds dirty). State: local (being applied here), pending
--                      (applied here, to be submitted), submitted (the core has it, no outcome yet), executed (the core
--                      did it: confirmed once `groups_applied` reaches `groups_expected`, the core's count of its
--                      groups).
--   mirror_dirty       mirror: an entry whose tables may differ from what the core last confirmed, because a pending
--                      change touched it, with that confirmed state (the state document of the last change the log
--                      applied to it, or of the tables when it was clean; NULL with kind 'none': no such entry). The
--                      applier keeps it current; a settled entry is brought back to it and the row goes.
--   mirror_held        mirror: the person's version of a change the core refused, never dropped (kind 'held': kept
--                      outside the vault's tree until the person discards it or someone with the right retries it), and
--                      the conflict copies made beside an entry the core had changed (kind 'conflict': a record of
--                      what was renamed, for the listing). The reason is the core's refusal code and text.
--   mirror_submission  core: each change a mirror submitted, by request id, with what the core did the first time
--                      (a repeated submit is answered from here, never executed twice): queued, running, executed with
--                      the number of groups it logged, or refused with the code. Kept 30 days after it finished (the
--                      log's own retention).
--
-- No foreign keys from mirror_pending or mirror_dirty to the entry tables (a pending change outlives the rows it touched:
-- a removal). Idempotent and safe on upgraded installs: new tables, and CREATE OR REPLACE of four functions of 160/164
-- (below); nothing is mirrored before this release.
--
-- An HTTP upload's staging file (`.upload-http-<id>.part`, staged through the FUSE mount on Linux: CLAUDE.md, the
-- upload coordinator, vh::fs::isUploadStagingName) is never content: snapshots and archives skip it, and from here on
-- the replication log does too. Its live entry has no state document (vh_mirror_entry_state, vh_mirror_tree_states: so
-- it is never logged, hashed, in the baseline or the scrub, or fetched), a trash row of one is not a trashed entry
-- (vh_mirror_track_trash), and a file renamed to such a name leaves the replicated tree with a delete
-- (vh_mirror_log_state). On a mirror the file is this server's scratch (mirror::submit::Scratch), never submitted.

CREATE TABLE IF NOT EXISTS mirror_pending
(
    id              BIGSERIAL PRIMARY KEY,
    vault_id        INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    request_id      TEXT        NOT NULL CHECK (request_id ~ '^[a-z0-9-]{8,64}$'),
    entry_uid       UUID        NOT NULL,
    op              TEXT        NOT NULL CHECK (op IN ('mkdir', 'move', 'rename', 'remove', 'copy', 'write', 'setattr')),
    args            JSONB       NOT NULL DEFAULT '{}'::jsonb,
    base_generation TEXT,
    new_generation  TEXT,
    actor_node      TEXT        NOT NULL CHECK (length(actor_node) BETWEEN 1 AND 64),
    actor_id        INTEGER     NOT NULL,
    uids            UUID[]      NOT NULL DEFAULT '{}',
    state           TEXT        NOT NULL DEFAULT 'local'
                                CHECK (state IN ('local', 'pending', 'submitted', 'executed')),
    groups_expected INTEGER CHECK (groups_expected >= 0),
    groups_applied  INTEGER     NOT NULL DEFAULT 0 CHECK (groups_applied >= 0),
    attempts        INTEGER     NOT NULL DEFAULT 0,
    last_error      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    submitted_at    TIMESTAMPTZ,
    executed_at     TIMESTAMPTZ,
    UNIQUE (vault_id, request_id)
);

CREATE INDEX IF NOT EXISTS mirror_pending_vault ON mirror_pending (vault_id, id);

CREATE TABLE IF NOT EXISTS mirror_dirty
(
    vault_id       INTEGER NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    entry_uid      UUID    NOT NULL,
    confirmed      JSONB,
    confirmed_kind TEXT    NOT NULL CHECK (confirmed_kind IN ('live', 'trashed', 'none')),
    PRIMARY KEY (vault_id, entry_uid),
    CHECK ((confirmed IS NULL) = (confirmed_kind = 'none'))
);

CREATE TABLE IF NOT EXISTS mirror_held
(
    id           BIGSERIAL PRIMARY KEY,
    vault_id     INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    kind         TEXT        NOT NULL CHECK (kind IN ('held', 'conflict')),
    request_id   TEXT        NOT NULL,
    op           TEXT        NOT NULL,
    entry_uid    UUID,
    args         JSONB       NOT NULL DEFAULT '{}'::jsonb,
    path         TEXT,
    copy_name    TEXT,
    actor_node   TEXT        NOT NULL,
    actor_id     INTEGER     NOT NULL,
    reason_code  TEXT        NOT NULL,
    reason       TEXT        NOT NULL,
    state        TEXT        NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'retried', 'discarded')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at  TIMESTAMPTZ,
    resolved_by  INTEGER
);

CREATE INDEX IF NOT EXISTS mirror_held_open ON mirror_held (vault_id, id) WHERE state = 'open';

CREATE TABLE IF NOT EXISTS mirror_submission
(
    vault_id    INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    request_id  TEXT        NOT NULL,
    peer_id     INTEGER     NOT NULL,
    seq         BIGSERIAL,
    payload     JSONB       NOT NULL,
    state       TEXT        NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'executed', 'refused')),
    groups      INTEGER,
    code        TEXT,
    error       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMPTZ,
    PRIMARY KEY (vault_id, request_id)
);

CREATE INDEX IF NOT EXISTS mirror_submission_queued ON mirror_submission (vault_id, seq) WHERE state IN ('queued', 'running');

-- ---------------------------------------------------------------------------------------------------- staging files

-- Whether a file named `name` is an HTTP upload's staging file (vh::fs::isUploadStagingName: the same rule).
CREATE OR REPLACE FUNCTION vh_mirror_upload_staging(name TEXT) RETURNS BOOLEAN AS $$
    SELECT name IS NOT NULL AND starts_with(name, '.upload-http-') AND right(name, 5) = '.part'
$$ LANGUAGE sql IMMUTABLE;

-- As 164's, and nothing for an upload's staging file.
CREATE OR REPLACE FUNCTION vh_mirror_entry_state(entry INTEGER) RETURNS JSONB AS $$
#variable_conflict use_column
BEGIN
    RETURN (
        SELECT jsonb_strip_nulls(jsonb_build_object(
                   'v', 1,
                   'uid', COALESCE(f.object_uid, d.uid, s.uid),
                   'type', CASE WHEN f.fs_entry_id IS NOT NULL THEN 'file'
                                WHEN d.fs_entry_id IS NOT NULL THEN 'directory'
                                ELSE 'symlink' END,
                   'parent', CASE WHEN pe.path = '/' THEN (SELECT v.uid FROM vault v WHERE v.id = e.vault_id)
                                  ELSE p.uid END,
                   'name', e.name,
                   'mode', e.mode,
                   'hidden', COALESCE(e.is_hidden, FALSE),
                   'owner_uid', e.owner_uid,
                   'owner_gid', e.group_gid,
                   'created_at', vh_mirror_micros(e.created_at),
                   'modified_at', CASE WHEN d.fs_entry_id IS NULL THEN vh_mirror_micros(e.updated_at) END,
                   'created_by', vh_mirror_account(e.created_by),
                   'modified_by', vh_mirror_account(e.last_modified_by),
                   'size', f.size_bytes,
                   'content_hash', f.content_hash,
                   'mime', f.mime_type,
                   'generation', f.encryption_iv,
                   'key_version', f.encrypted_with_key_version,
                   'content_format', f.content_format,
                   'target', s.target))
        FROM fs_entry e
        LEFT JOIN files f ON f.fs_entry_id = e.id
        LEFT JOIN directories d ON d.fs_entry_id = e.id
        LEFT JOIN symlinks s ON s.fs_entry_id = e.id
        LEFT JOIN fs_entry pe ON pe.id = e.parent_id
        LEFT JOIN directories p ON p.fs_entry_id = e.parent_id
        WHERE e.id = entry AND e.path <> '/' AND COALESCE(f.fs_entry_id, d.fs_entry_id, s.fs_entry_id) IS NOT NULL
          AND NOT (f.fs_entry_id IS NOT NULL AND vh_mirror_upload_staging(e.name))
    );
END;
$$ LANGUAGE plpgsql STABLE;

-- As 164's, without upload staging files (live, or a trash row of one).
CREATE OR REPLACE FUNCTION vh_mirror_tree_states(vault INTEGER)
RETURNS TABLE (entry_uid UUID, trashed BOOLEAN, depth INTEGER, state JSONB) AS $$
    WITH node AS (SELECT node_id FROM device_node WHERE singleton),
    live AS (
        SELECT jsonb_strip_nulls(jsonb_build_object(
                   'v', 1,
                   'uid', COALESCE(f.object_uid, d.uid, s.uid),
                   'type', CASE WHEN f.fs_entry_id IS NOT NULL THEN 'file'
                                WHEN d.fs_entry_id IS NOT NULL THEN 'directory'
                                ELSE 'symlink' END,
                   'parent', CASE WHEN pe.path = '/' THEN v.uid ELSE p.uid END,
                   'name', e.name,
                   'mode', e.mode,
                   'hidden', COALESCE(e.is_hidden, FALSE),
                   'owner_uid', e.owner_uid,
                   'owner_gid', e.group_gid,
                   'created_at', vh_mirror_micros(e.created_at),
                   'modified_at', CASE WHEN d.fs_entry_id IS NULL THEN vh_mirror_micros(e.updated_at) END,
                   'created_by', CASE WHEN cu.id IS NULL THEN NULL
                                      WHEN cu.remote THEN jsonb_build_object('node', cu.home_node, 'id', cu.home_id)
                                      ELSE jsonb_build_object('node', (SELECT node_id FROM node), 'id', cu.id) END,
                   'modified_by', CASE WHEN mu.id IS NULL THEN NULL
                                       WHEN mu.remote THEN jsonb_build_object('node', mu.home_node, 'id', mu.home_id)
                                       ELSE jsonb_build_object('node', (SELECT node_id FROM node), 'id', mu.id) END,
                   'size', f.size_bytes,
                   'content_hash', f.content_hash,
                   'mime', f.mime_type,
                   'generation', f.encryption_iv,
                   'key_version', f.encrypted_with_key_version,
                   'content_format', f.content_format,
                   'target', s.target)) AS s,
               length(e.path) - length(replace(e.path, '/', '')) AS depth
        FROM fs_entry e
        JOIN vault v ON v.id = e.vault_id
        LEFT JOIN files f ON f.fs_entry_id = e.id
        LEFT JOIN directories d ON d.fs_entry_id = e.id
        LEFT JOIN symlinks s ON s.fs_entry_id = e.id
        LEFT JOIN fs_entry pe ON pe.id = e.parent_id
        LEFT JOIN directories p ON p.fs_entry_id = e.parent_id
        LEFT JOIN users cu ON cu.id = e.created_by
        LEFT JOIN users mu ON mu.id = e.last_modified_by
        WHERE e.vault_id = vault AND e.path <> '/' AND COALESCE(f.fs_entry_id, d.fs_entry_id, s.fs_entry_id) IS NOT NULL
          AND NOT (f.fs_entry_id IS NOT NULL AND vh_mirror_upload_staging(e.name))
    )
    SELECT (l.s ->> 'uid')::uuid, FALSE, l.depth, l.s FROM live l
    UNION ALL
    SELECT t.object_uid, TRUE, 0,
           jsonb_strip_nulls(jsonb_build_object(
               'v', 1, 'uid', t.object_uid, 'type', 'file', 'size', t.size_bytes,
               'trashed', jsonb_build_object(
                   'path', t.path, 'at', vh_mirror_micros(t.trashed_at),
                   'by', CASE WHEN tu.id IS NULL THEN NULL
                              WHEN tu.remote THEN jsonb_build_object('node', tu.home_node, 'id', tu.home_id)
                              ELSE jsonb_build_object('node', (SELECT node_id FROM node), 'id', tu.id) END)))
    FROM (SELECT DISTINCT ON (ft.object_uid) ft.* FROM files_trashed ft
          WHERE ft.vault_id = vault AND ft.deleted_at IS NULL AND ft.object_uid IS NOT NULL
          ORDER BY ft.object_uid, ft.id DESC) t
    LEFT JOIN users tu ON tu.id = t.trashed_by
    WHERE NOT EXISTS (SELECT 1 FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id
                      WHERE f.object_uid = t.object_uid AND e.vault_id = vault)
      AND NOT vh_mirror_upload_staging(regexp_replace(t.path, '^.*/', ''))
$$ LANGUAGE sql STABLE;

-- As 160's, and a file renamed to an upload's staging name: it leaves the replicated tree (its delete).
CREATE OR REPLACE FUNCTION vh_mirror_log_state(vault INTEGER, t BIGINT, entry INTEGER, op TEXT, actor INTEGER)
RETURNS VOID AS $$
DECLARE
    s    JSONB;
    h    BYTEA;
    prev BYTEA;
    uid  UUID;
BEGIN
    PERFORM 1 FROM fs_entry WHERE id = entry FOR NO KEY UPDATE;
    s := vh_mirror_entry_state(entry);
    IF s IS NULL THEN
        SELECT f.object_uid INTO uid FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id
        WHERE f.fs_entry_id = entry AND vh_mirror_upload_staging(e.name);
        IF uid IS NOT NULL THEN
            DELETE FROM mirror_entry_hash WHERE vault_id = vault AND entry_uid = uid RETURNING entry_hash INTO prev;
            IF prev IS NOT NULL THEN
                PERFORM vh_mirror_append(vault, t, 'delete', jsonb_build_object('v', 1, 'uid', uid, 'type', 'file'),
                                         NULL, prev, actor);
            END IF;
        END IF;
        RETURN;
    END IF;
    uid := (s ->> 'uid')::uuid;
    h := vh_mirror_state_hash(s);
    SELECT entry_hash INTO prev FROM mirror_entry_hash WHERE vault_id = vault AND entry_uid = uid FOR UPDATE;
    IF prev IS NOT NULL AND prev = h THEN
        RETURN;
    END IF;
    INSERT INTO mirror_entry_hash (vault_id, entry_uid, entry_hash) VALUES (vault, uid, h)
    ON CONFLICT (vault_id, entry_uid) DO UPDATE SET entry_hash = EXCLUDED.entry_hash;
    PERFORM vh_mirror_append(vault, t, CASE WHEN prev IS NULL THEN 'upsert' ELSE op END, s, h, prev, actor);
END;
$$ LANGUAGE plpgsql;

-- As 160's, and a trash row of an upload's staging file is not a trashed entry.
CREATE OR REPLACE FUNCTION vh_mirror_track_trash() RETURNS TRIGGER AS $$
DECLARE
    t         BIGINT;
    vault     INTEGER;
    was       BOOLEAN := FALSE;
    is_now    BOOLEAN := FALSE;
    s         JSONB;
    h         BYTEA;
    prev      BYTEA;
    folded    BIGINT;
    who       JSONB;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM mirror_vault WHERE role = 'core') THEN
        RETURN NULL;
    END IF;
    IF TG_OP <> 'INSERT' THEN
        was := OLD.deleted_at IS NULL AND OLD.object_uid IS NOT NULL
               AND NOT vh_mirror_upload_staging(regexp_replace(OLD.path, '^.*/', ''));
    END IF;
    IF TG_OP <> 'DELETE' THEN
        is_now := NEW.deleted_at IS NULL AND NEW.object_uid IS NOT NULL
                  AND NOT vh_mirror_upload_staging(regexp_replace(NEW.path, '^.*/', ''));
    END IF;
    vault := CASE WHEN TG_OP = 'DELETE' THEN OLD.vault_id ELSE NEW.vault_id END;
    SELECT m.term INTO t FROM mirror_vault m WHERE m.vault_id = vault AND m.role = 'core';
    IF t IS NOT NULL THEN
        t := vh_mirror_core_term(vault);
    END IF;
    IF t IS NULL THEN
        RETURN NULL;
    END IF;

    -- The old trashed entry ends (or is renamed to another uid).
    IF was AND (NOT is_now OR OLD.object_uid IS DISTINCT FROM NEW.object_uid OR OLD.vault_id IS DISTINCT FROM NEW.vault_id) THEN
        IF EXISTS (SELECT 1 FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id
                   WHERE f.object_uid = OLD.object_uid AND e.vault_id = OLD.vault_id) THEN
            UPDATE vault_replication_log SET op = 'restore'
            WHERE id = (SELECT l.id FROM vault_replication_log l
                        WHERE l.vault_id = OLD.vault_id AND l.txid = txid_current() AND l.entry_uid = OLD.object_uid
                          AND l.seq IS NULL AND l.op IN ('upsert', 'move')
                        ORDER BY l.id DESC LIMIT 1);
        ELSE
            DELETE FROM mirror_entry_hash WHERE vault_id = OLD.vault_id AND entry_uid = OLD.object_uid
            RETURNING entry_hash INTO prev;
            IF prev IS NOT NULL THEN
                PERFORM vh_mirror_append(OLD.vault_id, t, 'purge',
                                         vh_mirror_trash_state(OLD.object_uid, OLD.size_bytes, OLD.path, OLD.trashed_at,
                                                               OLD.trashed_by),
                                         NULL, prev, NULL);
            END IF;
        END IF;
        was := FALSE;
    END IF;

    IF NOT is_now THEN
        RETURN NULL;
    END IF;
    s := vh_mirror_trash_state(NEW.object_uid, NEW.size_bytes, NEW.path, NEW.trashed_at, NEW.trashed_by);
    h := vh_mirror_state_hash(s);
    IF NOT was THEN
        SELECT l.id INTO folded FROM vault_replication_log l
        WHERE l.vault_id = NEW.vault_id AND l.txid = txid_current() AND l.entry_uid = NEW.object_uid AND l.seq IS NULL
          AND l.op = 'delete'
        ORDER BY l.id DESC LIMIT 1;
        IF folded IS NOT NULL THEN
            who := vh_mirror_account(COALESCE(NULLIF(current_setting('vh.actor', true), '')::integer, NEW.trashed_by));
            UPDATE vault_replication_log
            SET op = 'trash', state = s, entry_hash = h, parent_uid = NULL, name = NULL,
                actor_node = who ->> 'node', actor_id = (who ->> 'id')::integer
            WHERE id = folded;
            INSERT INTO mirror_entry_hash (vault_id, entry_uid, entry_hash) VALUES (NEW.vault_id, NEW.object_uid, h)
            ON CONFLICT (vault_id, entry_uid) DO UPDATE SET entry_hash = EXCLUDED.entry_hash;
            RETURN NULL;
        END IF;
    END IF;
    SELECT entry_hash INTO prev FROM mirror_entry_hash WHERE vault_id = NEW.vault_id AND entry_uid = NEW.object_uid
    FOR UPDATE;
    IF prev IS NOT NULL AND prev = h THEN
        RETURN NULL;
    END IF;
    INSERT INTO mirror_entry_hash (vault_id, entry_uid, entry_hash) VALUES (NEW.vault_id, NEW.object_uid, h)
    ON CONFLICT (vault_id, entry_uid) DO UPDATE SET entry_hash = EXCLUDED.entry_hash;
    PERFORM vh_mirror_append(NEW.vault_id, t, 'trash', s, h, prev, NEW.trashed_by);
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;
