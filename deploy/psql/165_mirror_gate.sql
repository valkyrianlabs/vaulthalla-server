-- The mirror is read-only: the database backstop (server mirror phase 2, wave 4 piece A; design/peers/mirror.md
-- "Strict mode: read-only while the link is down", "The gate", invariant 3). A vault this server holds as another
-- server's copy (its mirror_vault row's role is 'mirror' or 'orphaned') changes only through its core's log. Every write
-- surface refuses first (mirror::access::requireWritable, with a reason a person can act on); these triggers refuse
-- whatever a surface missed, psql by hand included. They surface as a generic error: the backstop, never the interface.
--
-- What is refused, on a held vault, unless the transaction set vh.mirror_apply = 'on' (the follower applying its core's
-- log, db::query::mirror::Log::markMirrorApply) or vh.mirror_local = 'on' (a change made on the mirror and accepted as
-- pending, wave 4 piece B; db::query::mirror alone sets either, tools/contracts/test_replication_log_contract.py):
--   fs_entry       an insert, a delete, and an update of a replicated column (the WHEN clause of migration 160's
--                  vh_mirror_track: vault, parent, name, mode, hidden flag, owner, group, created and modified time,
--                  creator, last modifier), except a folder's modification time alone (the totals statements stamp it
--                  on every change below it, the follower's after its commit too: not replicated, migration 160);
--   files          an insert, a delete, and an update of the content (size, MIME type, content hash, generation, key
--                  version: what migration 160 logs);
--   directories    an insert and a delete (their totals are derived, not replicated: never refused);
--   symlinks       an insert, a delete, and an update of the target;
--   files_trashed  an insert, a delete, and any update.
-- Never refused: the vault root (path '/': created with the vault, re-parented on a soft delete, never replicated), a
-- path-only, inode or alias rewrite (not replicated), and the rows of a vault being removed as a whole (its vault row is
-- gone: the cascade of storage::Manager::removeVault, which every removal of a copy goes through and which
-- mirror::start's ending rule and ops::vaults gate; a type row whose entry is already gone was refused or let through
-- with that entry). So creating the mirror's empty vault (MirrorStart::createMirrorVault: the vault, its root, then the
-- row) and removing a copy set no flag.
--
-- Cost (tools/dev/bench/replication_log_cost.sh): on a server holding no copy (every server today) one read of the
-- partial index below per row written, which is empty; a held copy elsewhere adds one indexed lookup of the row's vault
-- in mirror_vault. design/peers/mirror.md "As built: the gate" has the numbers.
--
-- Idempotent and safe on upgraded installs: functions and triggers only, and one index; no data changes.

CREATE INDEX IF NOT EXISTS mirror_vault_held_idx ON mirror_vault (vault_id) WHERE role IN ('mirror', 'orphaned');

-- The vault a held-copy check is about, or NULL when the change is let through without one. Raises for a refused change.
CREATE OR REPLACE FUNCTION vh_mirror_gate_refuse(vault INTEGER, what TEXT) RETURNS VOID AS $$
BEGIN
    IF vault IS NULL THEN
        RETURN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM mirror_vault m WHERE m.vault_id = vault AND m.role IN ('mirror', 'orphaned')) THEN
        RETURN;
    END IF;
    -- The vault removed as a whole: its row is gone already when the cascade reaches its entries.
    IF NOT EXISTS (SELECT 1 FROM vault v WHERE v.id = vault) THEN
        RETURN;
    END IF;
    RAISE EXCEPTION 'mirror_read_only: vault % is a copy of another server''s vault; % changes only through its core''s log',
        vault, what
        USING ERRCODE = 'P0001', HINT = 'design/peers/mirror.md "Strict mode": the write gate missed this path';
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION vh_mirror_gate() RETURNS TRIGGER AS $$
DECLARE
    vault INTEGER;
    other INTEGER;
BEGIN
    -- The common path: no copy is held here (every server today), or the change is the follower's or a pending one.
    IF NOT EXISTS (SELECT 1 FROM mirror_vault WHERE role IN ('mirror', 'orphaned')) THEN
        RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
    END IF;
    IF COALESCE(current_setting('vh.mirror_apply', true), '') = 'on'
       OR COALESCE(current_setting('vh.mirror_local', true), '') = 'on' THEN
        RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
    END IF;

    IF TG_TABLE_NAME = 'fs_entry' THEN
        IF TG_OP = 'DELETE' THEN
            IF OLD.path <> '/' THEN vault := OLD.vault_id; END IF;
        ELSIF TG_OP = 'INSERT' THEN
            IF NEW.path <> '/' THEN vault := NEW.vault_id; END IF;
        ELSE
            IF NEW.path <> '/' OR OLD.path <> '/' THEN
                -- A folder's modification time alone: the totals' stamp (not replicated).
                IF (OLD.vault_id, OLD.parent_id, OLD.name, OLD.mode, OLD.is_hidden, OLD.owner_uid, OLD.group_gid,
                    OLD.created_at, OLD.created_by, OLD.last_modified_by) IS NOT DISTINCT FROM
                   (NEW.vault_id, NEW.parent_id, NEW.name, NEW.mode, NEW.is_hidden, NEW.owner_uid, NEW.group_gid,
                    NEW.created_at, NEW.created_by, NEW.last_modified_by)
                   AND EXISTS (SELECT 1 FROM directories WHERE fs_entry_id = NEW.id) THEN
                    RETURN NEW;
                END IF;
                vault := NEW.vault_id;
                IF OLD.vault_id IS DISTINCT FROM NEW.vault_id THEN other := OLD.vault_id; END IF;
            END IF;
        END IF;
    ELSIF TG_TABLE_NAME = 'files_trashed' THEN
        vault := CASE WHEN TG_OP = 'DELETE' THEN OLD.vault_id ELSE NEW.vault_id END;
        IF TG_OP = 'UPDATE' AND OLD.vault_id IS DISTINCT FROM NEW.vault_id THEN other := OLD.vault_id; END IF;
    ELSE
        -- files, directories, symlinks: the entry's vault (none while the entry itself is being deleted: its own
        -- delete was judged).
        SELECT e.vault_id INTO vault FROM fs_entry e
        WHERE e.id = CASE WHEN TG_OP = 'DELETE' THEN OLD.fs_entry_id ELSE NEW.fs_entry_id END AND e.path <> '/';
    END IF;

    PERFORM vh_mirror_gate_refuse(vault, 'its ' || TG_TABLE_NAME);
    PERFORM vh_mirror_gate_refuse(other, 'its ' || TG_TABLE_NAME);
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS vh_mirror_gate ON fs_entry;
DROP TRIGGER IF EXISTS vh_mirror_gate_update ON fs_entry;
CREATE TRIGGER vh_mirror_gate BEFORE INSERT OR DELETE ON fs_entry FOR EACH ROW
    EXECUTE FUNCTION vh_mirror_gate();
CREATE TRIGGER vh_mirror_gate_update BEFORE UPDATE ON fs_entry FOR EACH ROW
    WHEN ((OLD.vault_id, OLD.parent_id, OLD.name, OLD.mode, OLD.is_hidden, OLD.owner_uid, OLD.group_gid, OLD.created_at,
           OLD.updated_at, OLD.created_by, OLD.last_modified_by) IS DISTINCT FROM
          (NEW.vault_id, NEW.parent_id, NEW.name, NEW.mode, NEW.is_hidden, NEW.owner_uid, NEW.group_gid, NEW.created_at,
           NEW.updated_at, NEW.created_by, NEW.last_modified_by))
    EXECUTE FUNCTION vh_mirror_gate();

DROP TRIGGER IF EXISTS vh_mirror_gate ON files;
DROP TRIGGER IF EXISTS vh_mirror_gate_update ON files;
CREATE TRIGGER vh_mirror_gate BEFORE INSERT OR DELETE ON files FOR EACH ROW
    EXECUTE FUNCTION vh_mirror_gate();
CREATE TRIGGER vh_mirror_gate_update BEFORE UPDATE ON files FOR EACH ROW
    WHEN ((OLD.size_bytes, OLD.mime_type, OLD.content_hash, OLD.encryption_iv, OLD.encrypted_with_key_version)
          IS DISTINCT FROM
          (NEW.size_bytes, NEW.mime_type, NEW.content_hash, NEW.encryption_iv, NEW.encrypted_with_key_version))
    EXECUTE FUNCTION vh_mirror_gate();

DROP TRIGGER IF EXISTS vh_mirror_gate ON directories;
CREATE TRIGGER vh_mirror_gate BEFORE INSERT OR DELETE ON directories FOR EACH ROW
    EXECUTE FUNCTION vh_mirror_gate();

DROP TRIGGER IF EXISTS vh_mirror_gate ON symlinks;
DROP TRIGGER IF EXISTS vh_mirror_gate_update ON symlinks;
CREATE TRIGGER vh_mirror_gate BEFORE INSERT OR DELETE ON symlinks FOR EACH ROW
    EXECUTE FUNCTION vh_mirror_gate();
CREATE TRIGGER vh_mirror_gate_update BEFORE UPDATE ON symlinks FOR EACH ROW
    WHEN (OLD.target IS DISTINCT FROM NEW.target)
    EXECUTE FUNCTION vh_mirror_gate();

DROP TRIGGER IF EXISTS vh_mirror_gate ON files_trashed;
DROP TRIGGER IF EXISTS vh_mirror_gate_update ON files_trashed;
CREATE TRIGGER vh_mirror_gate BEFORE INSERT OR DELETE ON files_trashed FOR EACH ROW
    EXECUTE FUNCTION vh_mirror_gate();
CREATE TRIGGER vh_mirror_gate_update BEFORE UPDATE ON files_trashed FOR EACH ROW
    WHEN (OLD IS DISTINCT FROM NEW)
    EXECUTE FUNCTION vh_mirror_gate();
