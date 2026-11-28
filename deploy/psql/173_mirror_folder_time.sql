-- A folder's modification time on a mirror (server mirror: design/peers/mirror.md). A folder's time is left out of its
-- entry hash on purpose: it is the totals statements' stamp, moved by every write below the folder, and a change of it
-- alone writes no replication log row (vh_mirror_track_entry) and changes no digest. The state documents carried no
-- folder time either, so a mirror gave each folder the time it created it there, and `vh fs ls` and the console showed
-- the copy's own times where the core shows the real ones.
--
-- From here a folder's state document carries its time as `folder_modified_at`, a field outside the hash
-- (vh_mirror_state_hash and mirror::kEntryHashFields are unchanged): the applier gives the folder that time when it
-- creates or updates it from a state, and a first copy's pages keep the folder times they applied (the apply sets
-- vh.keep_folder_times, which the totals statements honour). The time still travels only with a row the log writes for
-- other reasons, or with a copy: a folder-time-only change on the core stays unlogged, so while following, the mirror's
-- own writes below a folder move its time as the core's did.
--
-- Idempotent and safe on upgraded installs: CREATE OR REPLACE of the two state functions of 166 with one more field;
-- no data, hashes or digests change.

-- As 166's, and a folder's modification time (outside the hash).
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
                   'folder_modified_at', CASE WHEN d.fs_entry_id IS NOT NULL THEN vh_mirror_micros(e.updated_at) END,
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

-- As 166's, and a folder's modification time (outside the hash).
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
                   'folder_modified_at', CASE WHEN d.fs_entry_id IS NOT NULL THEN vh_mirror_micros(e.updated_at) END,
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
