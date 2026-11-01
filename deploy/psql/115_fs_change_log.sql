-- Filesystem change journal (#259; db::query::fs::ChangeLog, ws fs.changes.list).
--
-- Sync clients (Vaulthalla Desktop's File Provider, later the web console) ask "what changed in this vault since
-- revision N" instead of re-listing folders. Every entry mutation logs one row in the same transaction, from every
-- write path (FUSE seal, uploads, ws mutations, sync, recovery, psql by hand): triggers on the entry tables write it,
-- so no code path can forget to, and nothing changes on the FUSE path but one insert.
--
--   fs_change_log       one row per change: kind (create, update, rename, move, delete), the entry's id, type,
--                       parent, name and vault path (old path and parent for rename/move), and when. `reset` rows
--                       are authorization changes that can change what someone sees in a vault (vault NULL: every
--                       vault; user NULL: everyone): a client whose cursor is older re-enumerates.
--   fs_change_revision  one row: rev is the last revision handed out, pruned_through the newest revision retention
--                       may have dropped (a cursor older than that is expired).
--
-- Revisions are commit order. Writers insert with revision NULL and take no lock; the daemon's sequencer
-- (ChangeLog::sequence, under fs_change_revision's row lock) numbers the committed pending rows in id order. A row
-- whose transaction commits later is numbered by a later pass, so a reader that has seen revision R never gets a row
-- below R afterwards. Two changes to one entry can't commit out of insertion order: the entry's row lock orders them.
--
-- Not journaled: directory totals and updated_at/last_modified_by/inode/alias/path-only updates (an ancestor's
-- rename rewrites descendants' paths, but their identity and parent stay), owner uid/gid, key rotation re-encryption
-- (IV and key version change together), the vault root itself, and entries of a vault being purged.
--
-- Idempotent: CREATE ... IF NOT EXISTS, CREATE OR REPLACE FUNCTION, triggers dropped and recreated.

CREATE TABLE IF NOT EXISTS fs_change_revision
(
    id             SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    rev            BIGINT   NOT NULL DEFAULT 0,
    pruned_through BIGINT   NOT NULL DEFAULT 0
);

INSERT INTO fs_change_revision (id, rev, pruned_through) VALUES (1, 0, 0) ON CONFLICT (id) DO NOTHING;

-- No foreign keys: rows outlive their entry (delete) and their vault until retention drops them.
CREATE TABLE IF NOT EXISTS fs_change_log
(
    id            BIGSERIAL PRIMARY KEY,
    revision      BIGINT,
    vault_id      INTEGER,
    entry_id      INTEGER,
    parent_id     INTEGER,
    kind          VARCHAR(8)  NOT NULL CHECK (kind IN ('create', 'update', 'rename', 'move', 'delete', 'reset')),
    entry_type    VARCHAR(9)  CHECK (entry_type IN ('file', 'directory', 'symlink')),
    name          TEXT,
    path          TEXT,
    old_parent_id INTEGER,
    old_path      TEXT,
    user_id       INTEGER,
    changed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_fs_change_log_revision ON fs_change_log (revision) WHERE revision IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_fs_change_log_vault_revision ON fs_change_log (vault_id, revision)
    WHERE revision IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_fs_change_log_pending ON fs_change_log (id) WHERE revision IS NULL;
CREATE INDEX IF NOT EXISTS idx_fs_change_log_resets ON fs_change_log (revision) WHERE kind = 'reset';

-- ---------------------------------------------------------------------------------------------------- entries

-- The entry's type, from the table that holds it (NULL while it is in none).
CREATE OR REPLACE FUNCTION vh_fs_change_entry_type(entry INTEGER) RETURNS TEXT AS $$
    SELECT CASE
               WHEN EXISTS (SELECT 1 FROM files WHERE fs_entry_id = entry) THEN 'file'
               WHEN EXISTS (SELECT 1 FROM directories WHERE fs_entry_id = entry) THEN 'directory'
               WHEN EXISTS (SELECT 1 FROM symlinks WHERE fs_entry_id = entry) THEN 'symlink'
           END
$$ LANGUAGE sql STABLE;

-- files / directories / symlinks: a new row makes the entry exist as that type (create); a content change of a file
-- or a symlink's new target is an update. TG_ARGV[0] is the type.
CREATE OR REPLACE FUNCTION vh_fs_change_track_typed() RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO fs_change_log (vault_id, entry_id, parent_id, kind, entry_type, name, path)
    SELECT e.vault_id, e.id, e.parent_id, CASE WHEN TG_OP = 'INSERT' THEN 'create' ELSE 'update' END, TG_ARGV[0],
           e.name, e.path
    FROM fs_entry e
    WHERE e.id = NEW.fs_entry_id AND e.vault_id IS NOT NULL AND e.path <> '/';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- fs_entry: a new parent or vault is a move, a new name a rename, a mode or hidden flag an update (the WHEN clause
-- below skips every other update without calling this). Deletes are logged before the row goes (BEFORE DELETE), while
-- its type rows still exist, unless the vault is being purged or is soft-deleted.
CREATE OR REPLACE FUNCTION vh_fs_change_track_entry() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.vault_id IS NOT NULL AND OLD.path <> '/' AND
           EXISTS (SELECT 1 FROM vault WHERE id = OLD.vault_id AND deleted_at IS NULL) THEN
            INSERT INTO fs_change_log (vault_id, entry_id, parent_id, kind, entry_type, name, path)
            -- No type row left: a file the trash statement (mark_file_trashed) took out of files first. Folders
            -- and symlinks lose theirs only through this delete's cascade, after this trigger.
            VALUES (OLD.vault_id, OLD.id, OLD.parent_id, 'delete', COALESCE(vh_fs_change_entry_type(OLD.id), 'file'),
                    OLD.name, OLD.path);
        END IF;
        RETURN OLD;
    END IF;

    IF NEW.vault_id IS NULL OR OLD.path = '/' OR NEW.path = '/' THEN
        RETURN NULL;
    END IF;
    INSERT INTO fs_change_log (vault_id, entry_id, parent_id, kind, entry_type, name, path, old_parent_id, old_path)
    VALUES (NEW.vault_id, NEW.id, NEW.parent_id,
            CASE
                WHEN OLD.parent_id IS DISTINCT FROM NEW.parent_id OR OLD.vault_id IS DISTINCT FROM NEW.vault_id
                    THEN 'move'
                WHEN OLD.name IS DISTINCT FROM NEW.name THEN 'rename'
                ELSE 'update'
            END,
            vh_fs_change_entry_type(NEW.id), NEW.name, NEW.path,
            CASE WHEN OLD.parent_id IS DISTINCT FROM NEW.parent_id OR OLD.name IS DISTINCT FROM NEW.name
                      OR OLD.vault_id IS DISTINCT FROM NEW.vault_id THEN OLD.parent_id END,
            CASE WHEN OLD.parent_id IS DISTINCT FROM NEW.parent_id OR OLD.name IS DISTINCT FROM NEW.name
                      OR OLD.vault_id IS DISTINCT FROM NEW.vault_id THEN OLD.path END);
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS vh_fs_change_track ON fs_entry;
DROP TRIGGER IF EXISTS vh_fs_change_track_delete ON fs_entry;
CREATE TRIGGER vh_fs_change_track AFTER UPDATE ON fs_entry FOR EACH ROW
    WHEN (OLD.vault_id IS DISTINCT FROM NEW.vault_id OR OLD.parent_id IS DISTINCT FROM NEW.parent_id OR
          OLD.name IS DISTINCT FROM NEW.name OR OLD.mode IS DISTINCT FROM NEW.mode OR
          OLD.is_hidden IS DISTINCT FROM NEW.is_hidden)
    EXECUTE FUNCTION vh_fs_change_track_entry();
CREATE TRIGGER vh_fs_change_track_delete BEFORE DELETE ON fs_entry FOR EACH ROW
    EXECUTE FUNCTION vh_fs_change_track_entry();

DROP TRIGGER IF EXISTS vh_fs_change_track ON files;
DROP TRIGGER IF EXISTS vh_fs_change_track_update ON files;
CREATE TRIGGER vh_fs_change_track AFTER INSERT ON files FOR EACH ROW
    EXECUTE FUNCTION vh_fs_change_track_typed('file');
-- Content: size, hash, type, or a new seal (IV) under the same key version. Key rotation re-encrypts under a new key
-- version without changing the plaintext, so it is not a change.
CREATE TRIGGER vh_fs_change_track_update AFTER UPDATE ON files FOR EACH ROW
    WHEN (OLD.size_bytes IS DISTINCT FROM NEW.size_bytes OR OLD.content_hash IS DISTINCT FROM NEW.content_hash OR
          OLD.mime_type IS DISTINCT FROM NEW.mime_type OR
          (OLD.encryption_iv IS DISTINCT FROM NEW.encryption_iv AND
           OLD.encrypted_with_key_version IS NOT DISTINCT FROM NEW.encrypted_with_key_version))
    EXECUTE FUNCTION vh_fs_change_track_typed('file');

DROP TRIGGER IF EXISTS vh_fs_change_track ON directories;
CREATE TRIGGER vh_fs_change_track AFTER INSERT ON directories FOR EACH ROW
    EXECUTE FUNCTION vh_fs_change_track_typed('directory');

DROP TRIGGER IF EXISTS vh_fs_change_track ON symlinks;
DROP TRIGGER IF EXISTS vh_fs_change_track_update ON symlinks;
CREATE TRIGGER vh_fs_change_track AFTER INSERT ON symlinks FOR EACH ROW
    EXECUTE FUNCTION vh_fs_change_track_typed('symlink');
CREATE TRIGGER vh_fs_change_track_update AFTER UPDATE ON symlinks FOR EACH ROW
    WHEN (OLD.target IS DISTINCT FROM NEW.target)
    EXECUTE FUNCTION vh_fs_change_track_typed('symlink');

-- ---------------------------------------------------------------------------------------------------- resets

CREATE OR REPLACE FUNCTION vh_fs_change_reset(vault INTEGER, account INTEGER) RETURNS VOID AS $$
    INSERT INTO fs_change_log (vault_id, user_id, kind) VALUES (vault, account, 'reset');
$$ LANGUAGE sql;

-- Authorization rows that decide filesystem Lookup in a vault: a vault role assignment (its vault; its user, or
-- everyone for a group), its overrides (the assignment's), a vault role template (every vault using it), a user's
-- global vault policy, group membership and admin role (that user, every vault), an admin role template (its
-- holders), and the vault's owner or deletion (the vault, everyone). A cascade from a deleted assignment finds no
-- assignment row; that delete is logged by the assignment.
CREATE OR REPLACE FUNCTION vh_fs_change_track_rbac() RETURNS TRIGGER AS $$
DECLARE
    rec RECORD;
BEGIN
    IF TG_TABLE_NAME = 'vault_role_assignments' THEN
        IF TG_OP <> 'INSERT' THEN
            PERFORM vh_fs_change_reset(OLD.vault_id, CASE WHEN OLD.subject_type = 'user' THEN OLD.subject_id END);
        END IF;
        IF TG_OP <> 'DELETE' THEN
            PERFORM vh_fs_change_reset(NEW.vault_id, CASE WHEN NEW.subject_type = 'user' THEN NEW.subject_id END);
        END IF;
    ELSIF TG_TABLE_NAME = 'vault_permission_overrides' THEN
        FOR rec IN
            SELECT DISTINCT vra.vault_id, CASE WHEN vra.subject_type = 'user' THEN vra.subject_id END AS account
            FROM vault_role_assignments vra
            WHERE vra.id IN (CASE WHEN TG_OP <> 'INSERT' THEN OLD.assignment_id END,
                             CASE WHEN TG_OP <> 'DELETE' THEN NEW.assignment_id END)
        LOOP
            PERFORM vh_fs_change_reset(rec.vault_id, rec.account);
        END LOOP;
    ELSIF TG_TABLE_NAME = 'vault_role' THEN
        FOR rec IN SELECT DISTINCT vault_id FROM vault_role_assignments WHERE role_id = NEW.id
        LOOP
            PERFORM vh_fs_change_reset(rec.vault_id, NULL);
        END LOOP;
    ELSIF TG_TABLE_NAME IN ('user_global_vault_policy', 'group_members', 'admin_role_assignments') THEN
        IF TG_OP <> 'INSERT' THEN PERFORM vh_fs_change_reset(NULL, OLD.user_id); END IF;
        IF TG_OP <> 'DELETE' THEN PERFORM vh_fs_change_reset(NULL, NEW.user_id); END IF;
    ELSIF TG_TABLE_NAME = 'admin_role' THEN
        FOR rec IN SELECT user_id FROM admin_role_assignments WHERE role_id = NEW.id
        LOOP
            PERFORM vh_fs_change_reset(NULL, rec.user_id);
        END LOOP;
    ELSIF TG_TABLE_NAME = 'vault' THEN
        PERFORM vh_fs_change_reset(NEW.id, NULL);
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['vault_role_assignments', 'vault_permission_overrides', 'user_global_vault_policy',
                             'group_members', 'admin_role_assignments']
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS vh_fs_change_track ON %I', t);
        EXECUTE format('CREATE TRIGGER vh_fs_change_track AFTER INSERT OR UPDATE OR DELETE ON %I '
                       'FOR EACH ROW EXECUTE FUNCTION vh_fs_change_track_rbac()', t);
    END LOOP;
    -- Template edits (a deleted template cascades to its assignments, which log themselves).
    FOREACH t IN ARRAY ARRAY['vault_role', 'admin_role']
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS vh_fs_change_track ON %I', t);
        EXECUTE format('CREATE TRIGGER vh_fs_change_track AFTER UPDATE ON %I '
                       'FOR EACH ROW EXECUTE FUNCTION vh_fs_change_track_rbac()', t);
    END LOOP;
END $$;

DROP TRIGGER IF EXISTS vh_fs_change_track ON vault;
CREATE TRIGGER vh_fs_change_track AFTER UPDATE ON vault FOR EACH ROW
    WHEN (OLD.owner_id IS DISTINCT FROM NEW.owner_id OR OLD.deleted_at IS DISTINCT FROM NEW.deleted_at)
    EXECUTE FUNCTION vh_fs_change_track_rbac();
