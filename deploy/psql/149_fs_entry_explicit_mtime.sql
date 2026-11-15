-- fs_entry.updated_at is a file's modification time. The generic set_updated_at() trigger stamped every update with
-- the current time, so a statement that sets the time on purpose lost it: the manifest applier writing another
-- writer's mtime, a sync download keeping the mtime the manifest gave the file (design/sync/manifest-applier.md, "As
-- built: the mirror drill"). Two writers of one vault then disagreed on every file the other changed and republished
-- each other's roots. The row's own trigger stamps the time only when the statement leaves updated_at as it was and
-- the transaction hasn't said it writes the times itself (set_config('vh.keep_mtime', 'on', true): the applier and a
-- dated download, so a value equal to the old one, or a column the statement doesn't set, is kept too).
--
-- Idempotent and safe on upgraded installs: replaces one trigger; no data changes.

CREATE OR REPLACE FUNCTION vh_fs_entry_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.updated_at IS NOT DISTINCT FROM OLD.updated_at
       AND coalesce(current_setting('vh.keep_mtime', true), '') <> 'on' THEN
        NEW.updated_at = CURRENT_TIMESTAMP;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS set_fs_entry_updated_at ON fs_entry;
CREATE TRIGGER set_fs_entry_updated_at
    BEFORE UPDATE ON fs_entry
    FOR EACH ROW
    EXECUTE FUNCTION vh_fs_entry_updated_at();
