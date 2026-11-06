-- Versioned vault_master rewrap (#352, design/sealing/master-secrets.md §6). Replaces the installation's vault master
-- without re-encrypting any file body: only the wraps of the vault keys change.
--
--   vault_master_state   one row: the vault master version every key row is wrapped under (`version`), the version
--                        being staged, and the recovery window after a switch (the previous version, until when).
--                        Version 1 is the sealed slot "vault_master"; version N > 1 is "vault_master.vN". Versions
--                        are never reused (`highest_version`). `discard_versions`: sealed slots to delete, recorded
--                        before they are deleted so a crash in between is finished by the next finalize.
--   master_version       on vault_keys, vault_keys_trashed and vault_deletion_key: the master version that wraps the
--                        row. Every row carries the current version; trigger vh_vault_master_guard refuses a write
--                        that declares another one.
--   *_next               the wrap under the version being staged (staging writes them in batches; the switch moves
--                        them into place).
--   *_prev               the wrap under the previous version, kept for the recovery window so a rollback needs only
--                        the previous master. Finalize clears them.
--
-- A row whose wrapped bytes change for any other reason (a key rotation, an import) loses its staged and retained
-- wraps: they wrapped the old bytes. Staging stages it again, and a rollback rewraps it.
--
-- Idempotent and safe on upgraded installs: a new table, nullable columns, master_version backfilled to 1 (the only
-- master there has been), and a trigger that changes nothing an existing write does.

CREATE TABLE IF NOT EXISTS vault_master_state
(
    id                 BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    version            INTEGER     NOT NULL DEFAULT 1 CHECK (version >= 1),
    highest_version    INTEGER     NOT NULL DEFAULT 1,
    staging_version    INTEGER              DEFAULT NULL,
    staging_started_at TIMESTAMPTZ          DEFAULT NULL,
    previous_version   INTEGER              DEFAULT NULL,
    switched_at        TIMESTAMPTZ          DEFAULT NULL,
    window_until       TIMESTAMPTZ          DEFAULT NULL,
    discard_versions   INTEGER[]   NOT NULL DEFAULT '{}',
    CHECK (highest_version >= version),
    CHECK (staging_version IS NULL OR (staging_version > version AND staging_version <= highest_version)),
    CHECK (previous_version IS NULL OR (previous_version <> version AND window_until IS NOT NULL)),
    CHECK (staging_version IS NULL OR previous_version IS NULL)
);

INSERT INTO vault_master_state (id) VALUES (TRUE) ON CONFLICT (id) DO NOTHING;

-- VOLATILE on purpose: called from the guard trigger after a write waited on the switch's table locks, it must see the
-- switch's commit, not the snapshot the statement started with.
CREATE OR REPLACE FUNCTION vh_vault_master_version() RETURNS INTEGER
    LANGUAGE sql VOLATILE AS
$$
SELECT COALESCE((SELECT version FROM vault_master_state WHERE id), 1)
$$;

ALTER TABLE vault_keys ADD COLUMN IF NOT EXISTS master_version INTEGER;
ALTER TABLE vault_keys ADD COLUMN IF NOT EXISTS encrypted_key_next BYTEA DEFAULT NULL;
ALTER TABLE vault_keys ADD COLUMN IF NOT EXISTS iv_next BYTEA DEFAULT NULL;
ALTER TABLE vault_keys ADD COLUMN IF NOT EXISTS master_version_next INTEGER DEFAULT NULL;
ALTER TABLE vault_keys ADD COLUMN IF NOT EXISTS encrypted_key_prev BYTEA DEFAULT NULL;
ALTER TABLE vault_keys ADD COLUMN IF NOT EXISTS iv_prev BYTEA DEFAULT NULL;
ALTER TABLE vault_keys ADD COLUMN IF NOT EXISTS master_version_prev INTEGER DEFAULT NULL;

ALTER TABLE vault_keys_trashed ADD COLUMN IF NOT EXISTS master_version INTEGER;
ALTER TABLE vault_keys_trashed ADD COLUMN IF NOT EXISTS encrypted_key_next BYTEA DEFAULT NULL;
ALTER TABLE vault_keys_trashed ADD COLUMN IF NOT EXISTS iv_next BYTEA DEFAULT NULL;
ALTER TABLE vault_keys_trashed ADD COLUMN IF NOT EXISTS master_version_next INTEGER DEFAULT NULL;
ALTER TABLE vault_keys_trashed ADD COLUMN IF NOT EXISTS encrypted_key_prev BYTEA DEFAULT NULL;
ALTER TABLE vault_keys_trashed ADD COLUMN IF NOT EXISTS iv_prev BYTEA DEFAULT NULL;
ALTER TABLE vault_keys_trashed ADD COLUMN IF NOT EXISTS master_version_prev INTEGER DEFAULT NULL;

ALTER TABLE vault_deletion_key ADD COLUMN IF NOT EXISTS master_version INTEGER;
ALTER TABLE vault_deletion_key ADD COLUMN IF NOT EXISTS encrypted_key_next BYTEA DEFAULT NULL;
ALTER TABLE vault_deletion_key ADD COLUMN IF NOT EXISTS iv_next BYTEA DEFAULT NULL;
ALTER TABLE vault_deletion_key ADD COLUMN IF NOT EXISTS master_version_next INTEGER DEFAULT NULL;
ALTER TABLE vault_deletion_key ADD COLUMN IF NOT EXISTS encrypted_key_prev BYTEA DEFAULT NULL;
ALTER TABLE vault_deletion_key ADD COLUMN IF NOT EXISTS iv_prev BYTEA DEFAULT NULL;
ALTER TABLE vault_deletion_key ADD COLUMN IF NOT EXISTS master_version_prev INTEGER DEFAULT NULL;

-- Before this migration there was one vault master: every existing row is wrapped by version 1. (A re-run finds no
-- NULL left.)
UPDATE vault_keys SET master_version = 1 WHERE master_version IS NULL;
UPDATE vault_keys_trashed SET master_version = 1 WHERE master_version IS NULL;
UPDATE vault_deletion_key SET master_version = 1 WHERE master_version IS NULL;

ALTER TABLE vault_keys ALTER COLUMN master_version SET DEFAULT vh_vault_master_version();
ALTER TABLE vault_keys ALTER COLUMN master_version SET NOT NULL;
ALTER TABLE vault_keys_trashed ALTER COLUMN master_version SET DEFAULT vh_vault_master_version();
ALTER TABLE vault_keys_trashed ALTER COLUMN master_version SET NOT NULL;
ALTER TABLE vault_deletion_key ALTER COLUMN master_version SET DEFAULT vh_vault_master_version();
ALTER TABLE vault_deletion_key ALTER COLUMN master_version SET NOT NULL;

-- Every write of a wrap declares the master it used, and it must be the current one: a writer that wrapped under a
-- master the switch just replaced fails instead of storing a row nothing would unwrap after the window. The rewrap's
-- own transactions (switch, rollback, finalize) set vh.vault_master_rewrap locally and are exempt.
CREATE OR REPLACE FUNCTION vh_vault_master_guard() RETURNS trigger
    LANGUAGE plpgsql AS
$$
DECLARE
    current_version INTEGER;
BEGIN
    IF current_setting('vh.vault_master_rewrap', true) = 'on' THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' AND NEW.encrypted_key IS NOT DISTINCT FROM OLD.encrypted_key
        AND NEW.iv IS NOT DISTINCT FROM OLD.iv AND NEW.master_version IS NOT DISTINCT FROM OLD.master_version THEN
        RETURN NEW;
    END IF;
    current_version := vh_vault_master_version();
    IF NEW.master_version IS DISTINCT FROM current_version THEN
        RAISE EXCEPTION 'vault key row %/% is wrapped under vault master version %, but the current version is %',
            NEW.vault_id, NEW.version, NEW.master_version, current_version
            USING ERRCODE = 'check_violation';
    END IF;
    -- The staged and retained wraps were of the old bytes.
    NEW.encrypted_key_next := NULL;
    NEW.iv_next := NULL;
    NEW.master_version_next := NULL;
    NEW.encrypted_key_prev := NULL;
    NEW.iv_prev := NULL;
    NEW.master_version_prev := NULL;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS vault_keys_master_guard ON vault_keys;
CREATE TRIGGER vault_keys_master_guard
    BEFORE INSERT OR UPDATE ON vault_keys
    FOR EACH ROW EXECUTE FUNCTION vh_vault_master_guard();

DROP TRIGGER IF EXISTS vault_keys_trashed_master_guard ON vault_keys_trashed;
CREATE TRIGGER vault_keys_trashed_master_guard
    BEFORE INSERT OR UPDATE ON vault_keys_trashed
    FOR EACH ROW EXECUTE FUNCTION vh_vault_master_guard();

DROP TRIGGER IF EXISTS vault_deletion_key_master_guard ON vault_deletion_key;
CREATE TRIGGER vault_deletion_key_master_guard
    BEFORE INSERT OR UPDATE ON vault_deletion_key
    FOR EACH ROW EXECUTE FUNCTION vh_vault_master_guard();
