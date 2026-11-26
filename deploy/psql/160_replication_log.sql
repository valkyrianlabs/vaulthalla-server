-- The replication log of a mirrored vault (server mirror phase 2, piece 1; design/peers/mirror.md "The replication
-- log", "Parity", "Moving the core"; db::query::mirror, mirror::Sequencer). On the core server of a mirrored vault,
-- triggers record every change to the vault's tree in the mutation's own transaction, self-contained and named by
-- permanent ids, so that the mirror can apply the core's changes in the core's order. Nothing makes a vault mirrored
-- yet (no command, no peer protocol): until a mirror_vault row says so, every trigger here returns at once.
--
--   mirror_vault          one row per mirrored vault on this server: the linked server (peer), this server's role
--                         (core | mirror | orphaned), the term, the last sequence numbered (core) or applied (mirror),
--                         the position the mirror acknowledged, how far retention has pruned, the running digest and
--                         its entry count, the state (live | paused | diverged). A core row switches the log on.
--   mirror_entry_hash     the entry hash of every entry of a core vault as the log last recorded it (live entries and
--                         trashed files, by uid): the `prev_hash` of the next change, and what makes a statement that
--                         touches two tables of one entry (fs_entry and files) log one exact before/after pair.
--   vault_replication_log one row per change. `seq` is NULL until the sequencer numbers it; `txid` (txid_current())
--                         groups the rows of one transaction; (vault_id, term, seq) is unique and gap-free among
--                         numbered rows. `state` is the entry as the change left it (vh_mirror_entry_state,
--                         vh_mirror_trash_state, vh_mirror_vault_state, vh_mirror_key_state), `entry_hash` the hash of
--                         that state (NULL for a removal) and `prev_hash` the hash of the state it replaced (NULL for
--                         a creation). Accounts are (home node, id there): this server's node id and users.id for a
--                         local account, home_node and home_id for a remote one (design/peers/identity.md).
--
-- Ops: upsert (created or changed in place), move (an existing entry's parent or name changed), trash (a file moved
-- to the trash: one row, the delete of its live entry folded in), restore (a trashed file live again under its uid),
-- purge (a trashed file gone for good), delete (a live entry removed without the trash), vault (the vault's settings:
-- name, description, quota, owner, the sync and recovery policies), key (a key version's public facts: version, key
-- check, attestation; never key material). `history` is reserved for file versions (phase 3).
--
-- Not replicated: a folder's modification time (the totals statements stamp it on every change below it; the mirror's
-- own totals do the same), directory totals, path (derived from parent and name), inode, alias, is_system, the vault
-- root itself, the entries of a soft-deleted vault, trashed files without an object uid (opaque_v1 rows from before
-- 125, which the manifest leaves out too). Transactions that set vh.mirror_apply = 'on' (SET LOCAL; the mirror
-- applying a core's group, built later) write no rows and change no entry hash.
--
-- Serialising: a change to an entry's type row (files, symlinks) takes the entry's fs_entry row lock before it reads
-- the state, so two transactions that change different tables of one entry log in lock order and each sees the
-- other's committed half. The sequencer numbers whole groups, in the order of each group's last row (a transaction
-- that waited for another's lock wrote its last row after the other committed), under the mirror_vault row lock.
--
-- The entry hash (core/include/mirror/Hash.hpp, which carries the test vector) is SHA-256 over the canonical encoding
-- of exactly the replicated fields of the state document: the line "vh.mirror.entry/1", then one line per field of
-- vh_mirror_state_hash's list, in that order, `<field>=<UTF-8 byte length>:<value>` or `<field>=-` when absent. The
-- digest of a vault is the per-lane sum, modulo 2^64, of its entry hashes read as four big-endian 64-bit words.
--
-- Idempotent and safe on upgraded installs: new tables, functions and triggers only (triggers dropped and recreated).
-- Nothing existing changes and no row is written until a vault is mirrored.

-- ---------------------------------------------------------------------------------------------------- tables

CREATE TABLE IF NOT EXISTS mirror_vault
(
    vault_id       INTEGER PRIMARY KEY REFERENCES vault (id) ON DELETE CASCADE,
    peer_id        INTEGER     NOT NULL REFERENCES peer (id),
    role           TEXT        NOT NULL CHECK (role IN ('core', 'mirror', 'orphaned')),
    term           BIGINT      NOT NULL DEFAULT 1 CHECK (term >= 1),
    last_seq       BIGINT      NOT NULL DEFAULT 0 CHECK (last_seq >= 0),
    acked_term     BIGINT,
    acked_seq      BIGINT,
    pruned_term    BIGINT      NOT NULL DEFAULT 0 CHECK (pruned_term >= 0),
    pruned_seq     BIGINT      NOT NULL DEFAULT 0 CHECK (pruned_seq >= 0),
    digest         BYTEA       NOT NULL DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(digest) = 32),
    digest_entries BIGINT      NOT NULL DEFAULT 0,
    state          TEXT        NOT NULL DEFAULT 'live' CHECK (state IN ('live', 'paused', 'diverged')),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    numbered_at    TIMESTAMPTZ,
    acked_at       TIMESTAMPTZ,
    CHECK ((acked_term IS NULL) = (acked_seq IS NULL))
);

CREATE INDEX IF NOT EXISTS mirror_vault_core ON mirror_vault (vault_id) WHERE role = 'core';

-- No foreign keys (every logged change would take a share lock on the vault's mirror_vault row): rows of a vault
-- that is no longer mirrored are removed with its mirror_vault row (MirrorVaults::remove) or by the Janitor.
CREATE TABLE IF NOT EXISTS mirror_entry_hash
(
    vault_id   INTEGER NOT NULL,
    entry_uid  UUID    NOT NULL,
    entry_hash BYTEA   NOT NULL CHECK (octet_length(entry_hash) = 32),
    PRIMARY KEY (vault_id, entry_uid)
);

CREATE TABLE IF NOT EXISTS vault_replication_log
(
    id         BIGSERIAL PRIMARY KEY,
    vault_id   INTEGER     NOT NULL,
    term       BIGINT      NOT NULL,
    seq        BIGINT,
    txid       BIGINT      NOT NULL,
    op         TEXT        NOT NULL CHECK (op IN ('upsert', 'move', 'trash', 'restore', 'purge', 'delete', 'vault',
                                                  'key', 'history')),
    entry_uid  UUID,
    entry_type TEXT CHECK (entry_type IN ('file', 'directory', 'symlink')),
    parent_uid UUID,
    name       TEXT,
    state      JSONB       NOT NULL,
    entry_hash BYTEA CHECK (octet_length(entry_hash) = 32),
    prev_hash  BYTEA CHECK (octet_length(prev_hash) = 32),
    actor_node TEXT,
    actor_id   INTEGER,
    origin     TEXT,
    logged_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS vault_replication_log_position ON vault_replication_log (vault_id, term, seq)
    WHERE seq IS NOT NULL;
-- The sequencer's work list, and the trash and restore folding (a transaction's pending rows for one entry).
CREATE INDEX IF NOT EXISTS vault_replication_log_pending ON vault_replication_log (vault_id, txid, entry_uid)
    WHERE seq IS NULL;

-- ---------------------------------------------------------------------------------------------------- state

-- The builders are plpgsql, not SQL functions: a trigger calls them once per change, and plpgsql keeps their plans
-- where a non-inlined SQL function is planned again on every call (three times the cost on the seal path).

-- STABLE and not STRICT like EXTRACT itself, so that it is inlined where it is used.
CREATE OR REPLACE FUNCTION vh_mirror_micros(ts TIMESTAMPTZ) RETURNS BIGINT AS $$
    SELECT (EXTRACT(EPOCH FROM ts) * 1000000)::bigint
$$ LANGUAGE sql STABLE;

-- An account as every server names it: {node, id}, its home server's node id and its integer id there.
CREATE OR REPLACE FUNCTION vh_mirror_account(account INTEGER) RETURNS JSONB AS $$
#variable_conflict use_column
BEGIN
    RETURN (
        SELECT CASE WHEN u.remote THEN jsonb_build_object('node', u.home_node, 'id', u.home_id)
                    ELSE jsonb_build_object('node', (SELECT node_id FROM device_node WHERE singleton), 'id', u.id) END
        FROM users u
        WHERE u.id = account
    );
END;
$$ LANGUAGE plpgsql STABLE;

-- A live entry as the tables hold it now; NULL for the vault root and for an entry in no type table.
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
                   'parent', p.uid,
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
        LEFT JOIN directories p ON p.fs_entry_id = e.parent_id
        WHERE e.id = entry AND e.path <> '/' AND COALESCE(f.fs_entry_id, d.fs_entry_id, s.fs_entry_id) IS NOT NULL
    );
END;
$$ LANGUAGE plpgsql STABLE;

-- A trashed file: what files_trashed holds of it.
CREATE OR REPLACE FUNCTION vh_mirror_trash_state(uid UUID, size BIGINT, path TEXT, trashed_at TIMESTAMPTZ,
                                                 trashed_by INTEGER) RETURNS JSONB AS $$
#variable_conflict use_column
BEGIN
    RETURN (
        SELECT jsonb_strip_nulls(jsonb_build_object(
                   'v', 1, 'uid', uid, 'type', 'file', 'size', size,
                   'trashed', jsonb_build_object('path', path, 'at', vh_mirror_micros(trashed_at),
                                                 'by', vh_mirror_account(trashed_by))))
    );
END;
$$ LANGUAGE plpgsql STABLE;

-- The vault's replicated settings.
CREATE OR REPLACE FUNCTION vh_mirror_vault_state(vault INTEGER) RETURNS JSONB AS $$
#variable_conflict use_column
BEGIN
    RETURN (
        SELECT jsonb_strip_nulls(jsonb_build_object(
                   'v', 1, 'uid', v.uid, 'name', v.name, 'description', v.description, 'quota', v.quota,
                   'owner', vh_mirror_account(v.owner_id), 'deleted', v.deleted_at IS NOT NULL,
                   'sync', (SELECT jsonb_build_object('interval', s.interval, 'enabled', s.enabled)
                                   || COALESCE((SELECT to_jsonb(r) - 'sync_id' FROM rsync r WHERE r.sync_id = s.id), '{}')
                                   || COALESCE((SELECT to_jsonb(f) - 'sync_id' FROM fsync f WHERE f.sync_id = s.id), '{}')
                            FROM sync s WHERE s.vault_id = v.id ORDER BY s.id LIMIT 1),
                   'recovery', (SELECT to_jsonb(p) - ARRAY['vault_id', 'updated_at', 'updated_by']
                                FROM vault_recovery_policy p WHERE p.vault_id = v.id)))
        FROM vault v
        WHERE v.id = vault
    );
END;
$$ LANGUAGE plpgsql STABLE;

-- A key version's public facts: never the key, its wrapping or the master version.
CREATE OR REPLACE FUNCTION vh_mirror_key_state(version INTEGER, key_check TEXT, attestation BYTEA,
                                               attestation_key INTEGER, created_at TIMESTAMPTZ) RETURNS JSONB AS $$
#variable_conflict use_column
BEGIN
    RETURN (
        SELECT jsonb_strip_nulls(jsonb_build_object(
                   'v', 1, 'version', version, 'key_check', key_check,
                   'attestation', translate(encode(attestation, 'base64'), E'\n', ''),
                   'attestation_key', (SELECT translate(encode(k.public_key, 'base64'), E'\n', '')
                                       FROM key_attestation_keys k WHERE k.id = attestation_key),
                   'created_at', vh_mirror_micros(created_at)))
    );
END;
$$ LANGUAGE plpgsql STABLE;

-- ---------------------------------------------------------------------------------------------------- hash, digest

-- One line of the canonical encoding: `<field>=<UTF-8 byte length>:<value>` or `<field>=-`.
CREATE OR REPLACE FUNCTION vh_mirror_field(field TEXT, value TEXT) RETURNS TEXT AS $$
    SELECT field || '=' || COALESCE(octet_length(value)::text || ':' || value, '-') || E'\n'
$$ LANGUAGE sql IMMUTABLE;

-- SHA-256 of the canonical encoding of the replicated fields, in this order (mirror::entryHash computes the same; keep
-- the list in step with mirror::kEntryHashFields). One expression, neither STRICT nor IMMUTABLE (convert_to is
-- STABLE), so that the planner inlines it into the triggers: not inlined, it was planned again on every call.
CREATE OR REPLACE FUNCTION vh_mirror_state_hash(state JSONB) RETURNS BYTEA AS $$
    SELECT sha256(convert_to(
               'vh.mirror.entry/1' || E'\n' ||
               vh_mirror_field('v', state #>> '{v}') ||
               vh_mirror_field('uid', state #>> '{uid}') ||
               vh_mirror_field('type', state #>> '{type}') ||
               vh_mirror_field('parent', state #>> '{parent}') ||
               vh_mirror_field('name', state #>> '{name}') ||
               vh_mirror_field('mode', state #>> '{mode}') ||
               vh_mirror_field('hidden', state #>> '{hidden}') ||
               vh_mirror_field('owner_uid', state #>> '{owner_uid}') ||
               vh_mirror_field('owner_gid', state #>> '{owner_gid}') ||
               vh_mirror_field('created_at', state #>> '{created_at}') ||
               vh_mirror_field('modified_at', state #>> '{modified_at}') ||
               vh_mirror_field('created_by.node', state #>> '{created_by,node}') ||
               vh_mirror_field('created_by.id', state #>> '{created_by,id}') ||
               vh_mirror_field('modified_by.node', state #>> '{modified_by,node}') ||
               vh_mirror_field('modified_by.id', state #>> '{modified_by,id}') ||
               vh_mirror_field('size', state #>> '{size}') ||
               vh_mirror_field('content_hash', state #>> '{content_hash}') ||
               vh_mirror_field('mime', state #>> '{mime}') ||
               vh_mirror_field('generation', state #>> '{generation}') ||
               vh_mirror_field('key_version', state #>> '{key_version}') ||
               vh_mirror_field('content_format', state #>> '{content_format}') ||
               vh_mirror_field('target', state #>> '{target}') ||
               vh_mirror_field('trashed.path', state #>> '{trashed,path}') ||
               vh_mirror_field('trashed.at', state #>> '{trashed,at}') ||
               vh_mirror_field('trashed.by.node', state #>> '{trashed,by,node}') ||
               vh_mirror_field('trashed.by.id', state #>> '{trashed,by,id}'),
               'UTF8'))
$$ LANGUAGE sql STABLE;

-- Word k (0..3) of a 32-byte hash, big-endian, as an unsigned integer.
CREATE OR REPLACE FUNCTION vh_mirror_lane(h BYTEA, k INTEGER) RETURNS NUMERIC AS $$
    SELECT ('x' || encode(substring(h FROM 8 * k + 1 FOR 8), 'hex'))::bit(64)::bigint::numeric
           + CASE WHEN get_byte(h, 8 * k) >= 128 THEN 18446744073709551616 ELSE 0 END
$$ LANGUAGE sql IMMUTABLE STRICT;

CREATE OR REPLACE FUNCTION vh_mirror_digest_step(acc NUMERIC[], h BYTEA) RETURNS NUMERIC[] AS $$
    SELECT CASE WHEN h IS NULL THEN acc
                ELSE ARRAY[acc[1] + vh_mirror_lane(h, 0), acc[2] + vh_mirror_lane(h, 1),
                           acc[3] + vh_mirror_lane(h, 2), acc[4] + vh_mirror_lane(h, 3)] END
$$ LANGUAGE sql IMMUTABLE;

CREATE OR REPLACE FUNCTION vh_mirror_digest_final(acc NUMERIC[]) RETURNS BYTEA AS $$
    SELECT decode(string_agg(lpad(to_hex((CASE WHEN l.v >= 9223372036854775808 THEN l.v - 18446744073709551616
                                               ELSE l.v END)::bigint), 16, '0'), '' ORDER BY l.i), 'hex')
    FROM (SELECT i, acc[i] % 18446744073709551616 AS v FROM generate_series(1, 4) AS i) l
$$ LANGUAGE sql IMMUTABLE;

-- The digest of a set of entry hashes: SELECT vh_mirror_digest(entry_hash) FROM ...
CREATE OR REPLACE AGGREGATE vh_mirror_digest(BYTEA) (
    SFUNC = vh_mirror_digest_step,
    STYPE = NUMERIC[],
    FINALFUNC = vh_mirror_digest_final,
    INITCOND = '{0,0,0,0}'
);

-- Every entry of a vault with its hash, from the tables (the baseline when a vault becomes a core, and the scrub):
-- live entries, and each trashed file whose uid no live file of the vault holds (the newest trash row of a uid).
CREATE OR REPLACE FUNCTION vh_mirror_tree(vault INTEGER) RETURNS TABLE (entry_uid UUID, entry_hash BYTEA) AS $$
    SELECT (x.s ->> 'uid')::uuid, vh_mirror_state_hash(x.s)
    FROM (SELECT vh_mirror_entry_state(e.id) AS s FROM fs_entry e WHERE e.vault_id = vault AND e.path <> '/') x
    WHERE x.s IS NOT NULL
    UNION ALL
    SELECT t.object_uid, vh_mirror_state_hash(vh_mirror_trash_state(t.object_uid, t.size_bytes, t.path, t.trashed_at,
                                                                    t.trashed_by))
    FROM (SELECT DISTINCT ON (ft.object_uid) ft.* FROM files_trashed ft
          WHERE ft.vault_id = vault AND ft.deleted_at IS NULL AND ft.object_uid IS NOT NULL
          ORDER BY ft.object_uid, ft.id DESC) t
    WHERE NOT EXISTS (SELECT 1 FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id
                      WHERE f.object_uid = t.object_uid AND e.vault_id = vault)
$$ LANGUAGE sql STABLE;

-- ---------------------------------------------------------------------------------------------------- writers

-- The vault's term when this server is its core and the transaction's changes are its own; NULL otherwise. The
-- triggers look the vault up in mirror_vault themselves first (one cached plan), and call this only when it is a core.
CREATE OR REPLACE FUNCTION vh_mirror_core_term(vault INTEGER) RETURNS BIGINT AS $$
#variable_conflict use_column
BEGIN
    RETURN (
        SELECT m.term FROM mirror_vault m
        WHERE m.vault_id = vault AND m.role = 'core'
          AND COALESCE(current_setting('vh.mirror_apply', true), '') <> 'on'
          AND NOT EXISTS (SELECT 1 FROM vault v WHERE v.id = vault AND v.deleted_at IS NOT NULL)
    );
END;
$$ LANGUAGE plpgsql STABLE;

-- Appends one change. The actor is the transaction's vh.actor (users.id) when it set one, else `actor`.
CREATE OR REPLACE FUNCTION vh_mirror_append(vault INTEGER, t BIGINT, op TEXT, s JSONB, h BYTEA, prev BYTEA,
                                            actor INTEGER) RETURNS VOID AS $$
DECLARE
    who JSONB := vh_mirror_account(COALESCE(NULLIF(current_setting('vh.actor', true), '')::integer, actor));
BEGIN
    INSERT INTO vault_replication_log (vault_id, term, txid, op, entry_uid, entry_type, parent_uid, name, state,
                                       entry_hash, prev_hash, actor_node, actor_id, origin)
    VALUES (vault, t, txid_current(), op, (s ->> 'uid')::uuid,
            CASE WHEN op IN ('vault', 'key') THEN NULL ELSE s ->> 'type' END,
            (s ->> 'parent')::uuid, s ->> 'name', s, h, prev, who ->> 'node', (who ->> 'id')::integer,
            NULLIF(current_setting('vh.mirror_origin', true), ''));
END;
$$ LANGUAGE plpgsql;

-- A live entry's state after a change (upsert or move), once the entry's other writers are done with it; nothing when
-- the replicated state is what the log last recorded.
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

-- A live entry removed (its state read while its rows still exist). A file whose trash row this transaction wrote
-- first is part of that trash row's change.
CREATE OR REPLACE FUNCTION vh_mirror_log_delete(vault INTEGER, t BIGINT, entry INTEGER) RETURNS VOID AS $$
DECLARE
    s    JSONB;
    prev BYTEA;
    uid  UUID;
BEGIN
    s := vh_mirror_entry_state(entry);
    IF s IS NULL THEN
        RETURN;
    END IF;
    uid := (s ->> 'uid')::uuid;
    IF EXISTS (SELECT 1 FROM vault_replication_log
               WHERE vault_id = vault AND txid = txid_current() AND entry_uid = uid AND seq IS NULL AND op = 'trash') THEN
        RETURN;
    END IF;
    DELETE FROM mirror_entry_hash WHERE vault_id = vault AND entry_uid = uid RETURNING entry_hash INTO prev;
    PERFORM vh_mirror_append(vault, t, 'delete', s, NULL, prev, NULL);
END;
$$ LANGUAGE plpgsql;

-- files / directories / symlinks, AFTER INSERT and (files, symlinks) AFTER UPDATE of a replicated column.
CREATE OR REPLACE FUNCTION vh_mirror_track_typed() RETURNS TRIGGER AS $$
DECLARE
    vault INTEGER;
    actor INTEGER;
    t     BIGINT;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM mirror_vault WHERE role = 'core') THEN
        RETURN NULL;
    END IF;
    SELECT e.vault_id, CASE WHEN TG_OP = 'INSERT' THEN e.created_by ELSE e.last_modified_by END
    INTO vault, actor FROM fs_entry e WHERE e.id = NEW.fs_entry_id;
    SELECT m.term INTO t FROM mirror_vault m WHERE m.vault_id = vault AND m.role = 'core';
    IF t IS NOT NULL THEN
        t := vh_mirror_core_term(vault);
    END IF;
    IF t IS NOT NULL THEN
        PERFORM vh_mirror_log_state(vault, t, NEW.fs_entry_id, 'upsert', actor);
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- files / directories / symlinks, BEFORE DELETE: a type row deleted while its entry still exists (the trash
-- statement's own delete of the files row). Through the entry's cascade the entry is gone already and its delete was
-- logged by vh_mirror_track_entry_delete.
CREATE OR REPLACE FUNCTION vh_mirror_track_typed_delete() RETURNS TRIGGER AS $$
DECLARE
    vault INTEGER;
    t     BIGINT;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM mirror_vault WHERE role = 'core') THEN
        RETURN OLD;
    END IF;
    SELECT e.vault_id INTO vault FROM fs_entry e WHERE e.id = OLD.fs_entry_id AND e.path <> '/';
    SELECT m.term INTO t FROM mirror_vault m WHERE m.vault_id = vault AND m.role = 'core';
    IF t IS NOT NULL THEN
        t := vh_mirror_core_term(vault);
    END IF;
    IF t IS NOT NULL THEN
        PERFORM vh_mirror_log_delete(vault, t, OLD.fs_entry_id);
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

-- fs_entry, AFTER UPDATE of a replicated column (the WHEN clause below; it fires for every ancestor whose totals a
-- write moved, so the common path is one lookup of the entry's vault in mirror_vault).
CREATE OR REPLACE FUNCTION vh_mirror_track_entry() RETURNS TRIGGER AS $$
DECLARE
    t    BIGINT;
    s    JSONB;
    prev BYTEA;
BEGIN
    -- Moved to another vault (the server refuses that with EXDEV; psql by hand): it left the old one.
    IF OLD.vault_id IS DISTINCT FROM NEW.vault_id AND OLD.vault_id IS NOT NULL AND OLD.path <> '/' THEN
        SELECT m.term INTO t FROM mirror_vault m WHERE m.vault_id = OLD.vault_id AND m.role = 'core';
        IF t IS NOT NULL THEN
            t := vh_mirror_core_term(OLD.vault_id);
        END IF;
        s := vh_mirror_entry_state(NEW.id);
        IF t IS NOT NULL AND s IS NOT NULL THEN
            DELETE FROM mirror_entry_hash WHERE vault_id = OLD.vault_id AND entry_uid = (s ->> 'uid')::uuid
            RETURNING entry_hash INTO prev;
            PERFORM vh_mirror_append(OLD.vault_id, t, 'delete', s, NULL, prev, NULL);
        END IF;
    END IF;
    IF NEW.vault_id IS NULL OR NEW.path = '/' THEN
        RETURN NULL;
    END IF;
    SELECT m.term INTO t FROM mirror_vault m WHERE m.vault_id = NEW.vault_id AND m.role = 'core';
    IF t IS NOT NULL THEN
        t := vh_mirror_core_term(NEW.vault_id);
    END IF;
    IF t IS NULL THEN
        RETURN NULL;
    END IF;
    -- Only the modification time of a folder: the totals statements' stamp, not replicated.
    IF (OLD.vault_id, OLD.parent_id, OLD.name, OLD.mode, OLD.is_hidden, OLD.owner_uid, OLD.group_gid, OLD.created_at,
        OLD.created_by, OLD.last_modified_by) IS NOT DISTINCT FROM
       (NEW.vault_id, NEW.parent_id, NEW.name, NEW.mode, NEW.is_hidden, NEW.owner_uid, NEW.group_gid, NEW.created_at,
        NEW.created_by, NEW.last_modified_by)
       AND EXISTS (SELECT 1 FROM directories WHERE fs_entry_id = NEW.id) THEN
        RETURN NULL;
    END IF;
    PERFORM vh_mirror_log_state(NEW.vault_id, t, NEW.id,
                                CASE WHEN OLD.parent_id IS DISTINCT FROM NEW.parent_id OR OLD.name IS DISTINCT FROM NEW.name
                                     THEN 'move' ELSE 'upsert' END,
                                NEW.last_modified_by);
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- fs_entry, BEFORE DELETE (its type rows still exist; a cascade reaches each descendant the same way).
CREATE OR REPLACE FUNCTION vh_mirror_track_entry_delete() RETURNS TRIGGER AS $$
DECLARE
    t BIGINT;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM mirror_vault WHERE role = 'core') THEN
        RETURN OLD;
    END IF;
    IF OLD.vault_id IS NULL OR OLD.path = '/' THEN
        RETURN OLD;
    END IF;
    SELECT m.term INTO t FROM mirror_vault m WHERE m.vault_id = OLD.vault_id AND m.role = 'core';
    IF t IS NOT NULL THEN
        t := vh_mirror_core_term(OLD.vault_id);
    END IF;
    IF t IS NOT NULL THEN
        PERFORM vh_mirror_log_delete(OLD.vault_id, t, OLD.id);
    END IF;
    RETURN OLD;
END;
$$ LANGUAGE plpgsql;

-- files_trashed, AFTER INSERT, UPDATE of a replicated column, DELETE. A trash row is a trashed entry while it is not
-- purged (deleted_at NULL) and names its object uid.
--   new trashed entry:  the transaction's pending delete of the live file becomes the trash row (one change); without
--                       one (the trash row written first) a trash row of its own, and the live entry's delete later in
--                       the transaction is folded into it.
--   trashed entry ends: a restore when a live file of the vault holds its uid (the transaction's pending upsert of it
--                       becomes the restore), else a purge.
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
        was := OLD.deleted_at IS NULL AND OLD.object_uid IS NOT NULL;
    END IF;
    IF TG_OP <> 'DELETE' THEN
        is_now := NEW.deleted_at IS NULL AND NEW.object_uid IS NOT NULL;
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

-- vault (its settings), sync / fsync / rsync (the sync policy), vault_recovery_policy: the vault document.
CREATE OR REPLACE FUNCTION vh_mirror_track_vault() RETURNS TRIGGER AS $$
DECLARE
    vault INTEGER;
    t     BIGINT;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM mirror_vault WHERE role = 'core') THEN
        RETURN NULL;
    END IF;
    IF COALESCE(current_setting('vh.mirror_apply', true), '') = 'on' THEN
        RETURN NULL;
    END IF;
    IF TG_TABLE_NAME = 'vault' THEN
        -- Its soft deletion is the last change of a deleted vault that is logged.
        IF OLD.deleted_at IS NOT NULL THEN
            RETURN NULL;
        END IF;
        vault := NEW.id;
    ELSIF TG_TABLE_NAME IN ('fsync', 'rsync') THEN
        SELECT s.vault_id INTO vault FROM sync s
        WHERE s.id = CASE WHEN TG_OP = 'DELETE' THEN OLD.sync_id ELSE NEW.sync_id END;
    ELSE
        vault := CASE WHEN TG_OP = 'DELETE' THEN OLD.vault_id ELSE NEW.vault_id END;
    END IF;
    IF TG_TABLE_NAME = 'vault' THEN
        SELECT m.term INTO t FROM mirror_vault m WHERE m.vault_id = vault AND m.role = 'core';
    ELSE
        SELECT m.term INTO t FROM mirror_vault m WHERE m.vault_id = vault AND m.role = 'core';
        IF t IS NOT NULL THEN
            t := vh_mirror_core_term(vault);
        END IF;
    END IF;
    IF t IS NOT NULL THEN
        PERFORM vh_mirror_append(vault, t, 'vault', vh_mirror_vault_state(vault), NULL, NULL,
                                 CASE WHEN TG_OP <> 'DELETE' THEN (to_jsonb(NEW) ->> 'updated_by')::integer END);
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- vault_keys, AFTER INSERT and UPDATE of a version, its key check or its attestation: the key record.
CREATE OR REPLACE FUNCTION vh_mirror_track_key() RETURNS TRIGGER AS $$
DECLARE
    t BIGINT;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM mirror_vault WHERE role = 'core') THEN
        RETURN NULL;
    END IF;
    -- A rewrap under a new master, a timestamp: not a new public fact.
    IF TG_OP = 'UPDATE' AND
       jsonb_build_array(to_jsonb(OLD) -> 'version', to_jsonb(OLD) -> 'key_check', to_jsonb(OLD) -> 'attestation',
                         to_jsonb(OLD) -> 'attestation_key_id') =
       jsonb_build_array(to_jsonb(NEW) -> 'version', to_jsonb(NEW) -> 'key_check', to_jsonb(NEW) -> 'attestation',
                         to_jsonb(NEW) -> 'attestation_key_id') THEN
        RETURN NULL;
    END IF;
    SELECT m.term INTO t FROM mirror_vault m WHERE m.vault_id = NEW.vault_id AND m.role = 'core';
    IF t IS NOT NULL THEN
        t := vh_mirror_core_term(NEW.vault_id);
    END IF;
    IF t IS NOT NULL THEN
        PERFORM vh_mirror_append(NEW.vault_id, t, 'key',
                                 vh_mirror_key_state(NEW.version, NEW.key_check, NEW.attestation,
                                                     NEW.attestation_key_id, NEW.created_at),
                                 NULL, NULL, NULL);
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------------------------------- triggers

DROP TRIGGER IF EXISTS vh_mirror_track ON fs_entry;
DROP TRIGGER IF EXISTS vh_mirror_track_delete ON fs_entry;
CREATE TRIGGER vh_mirror_track AFTER UPDATE ON fs_entry FOR EACH ROW
    WHEN ((OLD.vault_id, OLD.parent_id, OLD.name, OLD.mode, OLD.is_hidden, OLD.owner_uid, OLD.group_gid, OLD.created_at,
           OLD.updated_at, OLD.created_by, OLD.last_modified_by) IS DISTINCT FROM
          (NEW.vault_id, NEW.parent_id, NEW.name, NEW.mode, NEW.is_hidden, NEW.owner_uid, NEW.group_gid, NEW.created_at,
           NEW.updated_at, NEW.created_by, NEW.last_modified_by))
    EXECUTE FUNCTION vh_mirror_track_entry();
CREATE TRIGGER vh_mirror_track_delete BEFORE DELETE ON fs_entry FOR EACH ROW
    EXECUTE FUNCTION vh_mirror_track_entry_delete();

DROP TRIGGER IF EXISTS vh_mirror_track ON files;
DROP TRIGGER IF EXISTS vh_mirror_track_update ON files;
DROP TRIGGER IF EXISTS vh_mirror_track_delete ON files;
CREATE TRIGGER vh_mirror_track AFTER INSERT ON files FOR EACH ROW
    EXECUTE FUNCTION vh_mirror_track_typed();
-- Content, and a key-version change (rotation re-seals: new generation and key version), which the journal skips.
-- (object_uid never changes: vh_uid_immutable. WHEN clauses name only columns as old as the table, so that an
-- upgrade test or a later migration can still drop a newer column.)
CREATE TRIGGER vh_mirror_track_update AFTER UPDATE ON files FOR EACH ROW
    WHEN ((OLD.size_bytes, OLD.mime_type, OLD.content_hash, OLD.encryption_iv, OLD.encrypted_with_key_version)
          IS DISTINCT FROM
          (NEW.size_bytes, NEW.mime_type, NEW.content_hash, NEW.encryption_iv, NEW.encrypted_with_key_version))
    EXECUTE FUNCTION vh_mirror_track_typed();
CREATE TRIGGER vh_mirror_track_delete BEFORE DELETE ON files FOR EACH ROW
    EXECUTE FUNCTION vh_mirror_track_typed_delete();

DROP TRIGGER IF EXISTS vh_mirror_track ON directories;
DROP TRIGGER IF EXISTS vh_mirror_track_delete ON directories;
CREATE TRIGGER vh_mirror_track AFTER INSERT ON directories FOR EACH ROW
    EXECUTE FUNCTION vh_mirror_track_typed();
CREATE TRIGGER vh_mirror_track_delete BEFORE DELETE ON directories FOR EACH ROW
    EXECUTE FUNCTION vh_mirror_track_typed_delete();

DROP TRIGGER IF EXISTS vh_mirror_track ON symlinks;
DROP TRIGGER IF EXISTS vh_mirror_track_update ON symlinks;
DROP TRIGGER IF EXISTS vh_mirror_track_delete ON symlinks;
CREATE TRIGGER vh_mirror_track AFTER INSERT ON symlinks FOR EACH ROW
    EXECUTE FUNCTION vh_mirror_track_typed();
CREATE TRIGGER vh_mirror_track_update AFTER UPDATE ON symlinks FOR EACH ROW
    WHEN (OLD.target IS DISTINCT FROM NEW.target)
    EXECUTE FUNCTION vh_mirror_track_typed();
CREATE TRIGGER vh_mirror_track_delete BEFORE DELETE ON symlinks FOR EACH ROW
    EXECUTE FUNCTION vh_mirror_track_typed_delete();

DROP TRIGGER IF EXISTS vh_mirror_track ON files_trashed;
DROP TRIGGER IF EXISTS vh_mirror_track_update ON files_trashed;
CREATE TRIGGER vh_mirror_track AFTER INSERT OR DELETE ON files_trashed FOR EACH ROW
    EXECUTE FUNCTION vh_mirror_track_trash();
CREATE TRIGGER vh_mirror_track_update AFTER UPDATE ON files_trashed FOR EACH ROW
    WHEN (OLD IS DISTINCT FROM NEW)
    EXECUTE FUNCTION vh_mirror_track_trash();

DROP TRIGGER IF EXISTS vh_mirror_track ON vault;
CREATE TRIGGER vh_mirror_track AFTER UPDATE ON vault FOR EACH ROW
    WHEN ((OLD.name, OLD.description, OLD.quota, OLD.owner_id, OLD.deleted_at) IS DISTINCT FROM
          (NEW.name, NEW.description, NEW.quota, NEW.owner_id, NEW.deleted_at))
    EXECUTE FUNCTION vh_mirror_track_vault();

DROP TRIGGER IF EXISTS vh_mirror_track ON sync;
DROP TRIGGER IF EXISTS vh_mirror_track_update ON sync;
CREATE TRIGGER vh_mirror_track AFTER INSERT OR DELETE ON sync FOR EACH ROW
    EXECUTE FUNCTION vh_mirror_track_vault();
-- Not last_sync_at / last_success_at: every pass writes them.
CREATE TRIGGER vh_mirror_track_update AFTER UPDATE ON sync FOR EACH ROW
    WHEN ((OLD.interval, OLD.enabled) IS DISTINCT FROM (NEW.interval, NEW.enabled))
    EXECUTE FUNCTION vh_mirror_track_vault();

DO $$
DECLARE
    tbl TEXT;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['fsync', 'rsync', 'vault_recovery_policy']
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS vh_mirror_track ON %I', tbl);
        EXECUTE format('DROP TRIGGER IF EXISTS vh_mirror_track_update ON %I', tbl);
        EXECUTE format('CREATE TRIGGER vh_mirror_track AFTER INSERT OR DELETE ON %I '
                       'FOR EACH ROW EXECUTE FUNCTION vh_mirror_track_vault()', tbl);
        EXECUTE format('CREATE TRIGGER vh_mirror_track_update AFTER UPDATE ON %I FOR EACH ROW '
                       'WHEN (OLD IS DISTINCT FROM NEW) EXECUTE FUNCTION vh_mirror_track_vault()', tbl);
    END LOOP;
END $$;

DROP TRIGGER IF EXISTS vh_mirror_track ON vault_keys;
DROP TRIGGER IF EXISTS vh_mirror_track_update ON vault_keys;
CREATE TRIGGER vh_mirror_track AFTER INSERT ON vault_keys FOR EACH ROW
    EXECUTE FUNCTION vh_mirror_track_key();
-- The function compares the key's public facts (a WHEN on key_check or attestation would pin those 113 columns).
CREATE TRIGGER vh_mirror_track_update AFTER UPDATE ON vault_keys FOR EACH ROW
    WHEN (OLD IS DISTINCT FROM NEW)
    EXECUTE FUNCTION vh_mirror_track_key();
