-- The first copy and following the core (server mirror phase 2, wave 3 piece B; design/peers/mirror.md "Starting a
-- mirror" steps 5 and 7, "Following the core", "As built: following the core"; db::query::mirror, mirror::follow,
-- mirror::apply). On the core: a per-vault baseline instead of a server-wide lock, the baseline kept readable until the
-- mirror has copied it, and the digest after every group. On the mirror: where the first copy and the log stand, and
-- why a vault stopped.
--
--   mirror_vault          role 'core' gains the state 'starting' (MirrorVaults::startCore is taking the baseline:
--                         a writer of that vault waits in its trigger for the baseline to finish, a writer of any other
--                         vault never waits), and the states 'expired' (the mirror's position fell out of the core's
--                         retention, or the core no longer holds the vault as its core) and 'stopped' (a reason the
--                         applier cannot go past: a key version this server does not hold). New columns:
--                           baseline_term, baseline_seq, baseline_digest, baseline_entries, baseline_rows,
--                           baseline_vault   core: the position the baseline was taken at, its digest, its entry count,
--                                            how many entries it serves, the vault's document then; mirror: what the
--                                            core said of its baseline in its first tree answer.
--                           copy_cursor      mirror: the last baseline entry applied (mirror_baseline.ord).
--                           copy_finished    mirror: the first copy is complete and matched the baseline's digest;
--                                            from then on last_seq is the last group applied.
--                           vault_state      mirror: the core's vault document as last applied (name, description,
--                                            quota, owner, the sync and recovery policies), recorded, never acted on.
--                           stop_reason, stop_detail, stopped_at
--                                            why the state is diverged, expired or stopped: a code, its details (for a
--                                            compare-and-set mismatch the entry and both hashes; never key material),
--                                            when. Cleared when the vault is live again.
--   mirror_baseline       core: every entry of the vault as of the baseline (the state document the log would have
--                         written for it, and its hash), numbered so that a folder always comes before what is under it
--                         and trashed files after every live entry. Served in pages by peer.mirror.tree; dropped when the
--                         mirror acknowledges (MirrorVaults::acknowledge) and by MirrorVaults::remove.
--   vault_replication_log digest_after, entries_after: on the last row of each group, the vault's digest once that
--                         group is applied (the sequencer writes them as it numbers), so the core can say what its digest
--                         was at any position the mirror acknowledges.
--
-- vh_mirror_entry_state: an entry directly under the vault's root names the vault's uid as its parent. The root folder
-- is not replicated and each server gives its own one a uid of its own; the vault's uid is the one both share.
--
-- Idempotent and safe on upgraded installs: new columns (NULL or defaulted), a new table, functions replaced, the two
-- CHECKs of mirror_vault widened once. Nothing is mirrored before this release, so no row changes meaning.

-- ---------------------------------------------------------------------------------------------------- mirror_vault

ALTER TABLE mirror_vault ADD COLUMN IF NOT EXISTS baseline_term BIGINT;
ALTER TABLE mirror_vault ADD COLUMN IF NOT EXISTS baseline_seq BIGINT;
ALTER TABLE mirror_vault ADD COLUMN IF NOT EXISTS baseline_digest BYTEA CHECK (octet_length(baseline_digest) = 32);
ALTER TABLE mirror_vault ADD COLUMN IF NOT EXISTS baseline_entries BIGINT;
ALTER TABLE mirror_vault ADD COLUMN IF NOT EXISTS baseline_rows BIGINT;
ALTER TABLE mirror_vault ADD COLUMN IF NOT EXISTS baseline_vault JSONB;
ALTER TABLE mirror_vault ADD COLUMN IF NOT EXISTS copy_cursor BIGINT NOT NULL DEFAULT 0;
ALTER TABLE mirror_vault ADD COLUMN IF NOT EXISTS copy_finished BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE mirror_vault ADD COLUMN IF NOT EXISTS vault_state JSONB;
ALTER TABLE mirror_vault ADD COLUMN IF NOT EXISTS stop_reason TEXT;
ALTER TABLE mirror_vault ADD COLUMN IF NOT EXISTS stop_detail JSONB;
ALTER TABLE mirror_vault ADD COLUMN IF NOT EXISTS stopped_at TIMESTAMPTZ;

-- 160's inline CHECK on state, whatever it was named, replaced once by one that knows starting, expired and stopped.
DO $$
DECLARE
    c RECORD;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'mirror_vault'::regclass AND contype = 'c' AND conname = 'mirror_vault_state_check'
                     AND pg_get_constraintdef(oid) LIKE '%''stopped''%') THEN
        FOR c IN SELECT conname FROM pg_constraint
                 WHERE conrelid = 'mirror_vault'::regclass AND contype = 'c'
                   AND pg_get_constraintdef(oid) LIKE '%state%' AND pg_get_constraintdef(oid) LIKE '%''diverged''%'
        LOOP
            EXECUTE format('ALTER TABLE mirror_vault DROP CONSTRAINT %I', c.conname);
        END LOOP;
        ALTER TABLE mirror_vault ADD CONSTRAINT mirror_vault_state_check
            CHECK (state IN ('starting', 'live', 'paused', 'diverged', 'expired', 'stopped'));
    END IF;
END
$$;

-- ---------------------------------------------------------------------------------------------------- the baseline

-- No foreign key to mirror_vault (MirrorVaults::remove and acknowledge drop the rows); the vault's own deletion
-- cascades.
CREATE TABLE IF NOT EXISTS mirror_baseline
(
    vault_id   INTEGER NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    ord        BIGINT  NOT NULL,
    entry_uid  UUID    NOT NULL,
    state      JSONB   NOT NULL,
    entry_hash BYTEA   NOT NULL CHECK (octet_length(entry_hash) = 32),
    PRIMARY KEY (vault_id, ord)
);

ALTER TABLE vault_replication_log ADD COLUMN IF NOT EXISTS digest_after BYTEA CHECK (octet_length(digest_after) = 32);
ALTER TABLE vault_replication_log ADD COLUMN IF NOT EXISTS entries_after BIGINT;

-- ---------------------------------------------------------------------------------------------------- state

-- As 160's, with the vault's uid as the parent of an entry directly under the vault's root.
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
    );
END;
$$ LANGUAGE plpgsql STABLE;

-- Every entry of a vault with its state document, from the tables: live entries (with their depth below the root),
-- and each trashed file whose uid no live file of the vault holds (the newest trash row of a uid). The baseline, and
-- through vh_mirror_tree the scrub, read the same set. Set-based: the documents are exactly vh_mirror_entry_state's and
-- vh_mirror_trash_state's (the same fields, accounts as vh_mirror_account names them), built in one join instead of a
-- function call per entry (100,000 entries: 23 s per call, a few seconds joined; MirrorReplicationLogDbTest checks the
-- scrub against the triggers' documents).
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
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION vh_mirror_tree(vault INTEGER) RETURNS TABLE (entry_uid UUID, entry_hash BYTEA) AS $$
    SELECT t.entry_uid, vh_mirror_state_hash(t.state) FROM vh_mirror_tree_states(vault) t
$$ LANGUAGE sql STABLE;

-- ---------------------------------------------------------------------------------------------------- writers

-- As 160's, and a vault whose baseline is being taken (state 'starting'): the change waits for the baseline's row
-- lock. Taken before the baseline locks the row, the change commits first and is in the baseline (it is not logged);
-- after the baseline committed, it is logged. VOLATILE: it locks, and it must see the baseline's commit once it has
-- waited for it.
CREATE OR REPLACE FUNCTION vh_mirror_core_term(vault INTEGER) RETURNS BIGINT AS $$
#variable_conflict use_column
DECLARE
    st TEXT;
BEGIN
    IF COALESCE(current_setting('vh.mirror_apply', true), '') = 'on' THEN
        RETURN NULL;
    END IF;
    SELECT m.state INTO st FROM mirror_vault m WHERE m.vault_id = vault AND m.role = 'core';
    IF st IS NULL THEN
        RETURN NULL;
    END IF;
    IF st = 'starting' THEN
        PERFORM 1 FROM mirror_vault m WHERE m.vault_id = vault FOR SHARE;
    END IF;
    RETURN (
        SELECT m.term FROM mirror_vault m
        WHERE m.vault_id = vault AND m.role = 'core' AND m.state <> 'starting'
          AND NOT EXISTS (SELECT 1 FROM vault v WHERE v.id = vault AND v.deleted_at IS NOT NULL)
    );
END;
$$ LANGUAGE plpgsql VOLATILE;
