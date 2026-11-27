-- Mirror every vault to a linked server (server mirror phase 2; design/peers/mirror.md "Starting a mirror"): a setting
-- per link on the core, beside 163's settings of the receiving side.
--
--   peer.mirror_vaults  this server, as core, offers the linked server every vault it owns that is not mirrored yet, and
--                       each new vault as it is created (default off; only a super admin here changes it, with the keys
--                       step-up, since every offer sends a vault's keys), who set it and when. An offer that ended since
--                       the setting was last turned on (declined, cancelled, expired, failed) is not made again.
--
--   the change journal's files trigger (migration 115)
--                       a key rotation's re-seal now records the new generation's sealed-bytes hash
--                       (files.content_hash, what a mirror checks the bytes it fetches against); it is still not a
--                       change (the plaintext is the same). The rotation's statement says so for its own transaction
--                       (vh.key_rotation), and the trigger skips that hash change alone.
--
-- Additive and idempotent: three new columns with defaults and one trigger replaced; nothing existing changes and a
-- second run changes nothing.

ALTER TABLE peer ADD COLUMN IF NOT EXISTS mirror_vaults BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE peer ADD COLUMN IF NOT EXISTS mirror_vaults_set_by INTEGER REFERENCES users (id) ON DELETE SET NULL;
ALTER TABLE peer ADD COLUMN IF NOT EXISTS mirror_vaults_set_at TIMESTAMPTZ;

DROP TRIGGER IF EXISTS vh_fs_change_track_update ON files;
CREATE TRIGGER vh_fs_change_track_update AFTER UPDATE ON files FOR EACH ROW
    WHEN (OLD.size_bytes IS DISTINCT FROM NEW.size_bytes OR OLD.mime_type IS DISTINCT FROM NEW.mime_type OR
          (OLD.content_hash IS DISTINCT FROM NEW.content_hash AND
           current_setting('vh.key_rotation', true) IS DISTINCT FROM 'on') OR
          (OLD.encryption_iv IS DISTINCT FROM NEW.encryption_iv AND
           OLD.encrypted_with_key_version IS NOT DISTINCT FROM NEW.encrypted_with_key_version))
    EXECUTE FUNCTION vh_fs_change_track_typed('file');
