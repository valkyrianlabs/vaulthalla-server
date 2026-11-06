-- The versioned master-secret registry for every slot that rotates (#353, design/sealing/master-secrets.md §6.5).
-- Migration 121 made vault_master versioned; this generalizes its state to the other data-wrapping masters (ak_master
-- for provider API keys, s3gw_master for S3 gateway credentials) and to the device-listener identity (device_tls).
--
--   master_secret_state   one row per slot, the shape vault_master_state had: the version every dependent row is
--                         wrapped under (`version`), the version being staged, the recovery window after a switch, the
--                         monotonic `highest_version`, and `discard_versions` (sealed slots to delete, recorded before
--                         they are deleted). Version 1 of a slot is its original sealed name; version N > 1 is
--                         "<slot>.vN". device_tls rotates by regeneration (no staging, no window): it uses only
--                         `version`, `highest_version` and `discard_versions`.
--   vault_master_state    moved into master_secret_state (slot 'vault_master') and dropped. vh_vault_master_version()
--                         reads the new table, so the vault key guard of 121 is unchanged.
--   api_keys              master_version (backfilled to 1) and staged (*_next) / retained (*_prev) wraps of both secrets
--                         ak_master wraps: the S3 secret and the optional provider token.
--   s3_gateway_credentials master_version (backfilled to 1) and staged / retained wraps of the credential secret.
--
-- The guard triggers refuse a row that declares a master other than the slot's current one, and drop a row's staged and
-- retained wraps when its wrapped bytes change for any other reason (a new secret, a new provider token). The rewrap's
-- own transactions set vh.master_rewrap to the slot they rewrap and are exempt for that slot only.
--
-- Idempotent and safe on upgraded installs: a new table filled from the old one (or with the defaults), nullable
-- columns, master_version backfilled to 1 (the only master there has been), and triggers that change nothing an
-- existing write does.

CREATE TABLE IF NOT EXISTS master_secret_state
(
    slot               TEXT PRIMARY KEY CHECK (slot IN ('vault_master', 'ak_master', 's3gw_master', 'device_tls')),
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
    CHECK (staging_version IS NULL OR previous_version IS NULL),
    CHECK (slot <> 'device_tls' OR (staging_version IS NULL AND previous_version IS NULL))
);

-- The vault master's state as 121 left it (a rotation may be staging or inside its window), then the old table goes.
DO
$$
    BEGIN
        IF to_regclass('public.vault_master_state') IS NOT NULL THEN
            INSERT INTO master_secret_state (slot, version, highest_version, staging_version, staging_started_at,
                                             previous_version, switched_at, window_until, discard_versions)
            SELECT 'vault_master', version, highest_version, staging_version, staging_started_at, previous_version,
                   switched_at, window_until, discard_versions
            FROM vault_master_state
            WHERE id
            ON CONFLICT (slot) DO NOTHING;
        END IF;
    END
$$;

INSERT INTO master_secret_state (slot)
VALUES ('vault_master'), ('ak_master'), ('s3gw_master'), ('device_tls')
ON CONFLICT (slot) DO NOTHING;

-- VOLATILE on purpose (as in 121): a guard trigger that waited on a switch's table locks must see its commit.
CREATE OR REPLACE FUNCTION vh_master_version(p_slot TEXT) RETURNS INTEGER
    LANGUAGE sql VOLATILE AS
$$
SELECT COALESCE((SELECT version FROM master_secret_state WHERE slot = p_slot), 1)
$$;

CREATE OR REPLACE FUNCTION vh_vault_master_version() RETURNS INTEGER
    LANGUAGE sql VOLATILE AS
$$
SELECT vh_master_version('vault_master')
$$;

DROP TABLE IF EXISTS vault_master_state;

-- The vault key guard of 121, exempting the rewrap by the slot it rewraps (vh.master_rewrap) instead of 121's
-- vault-only setting.
CREATE OR REPLACE FUNCTION vh_vault_master_guard() RETURNS trigger
    LANGUAGE plpgsql AS
$$
DECLARE
    current_version INTEGER;
BEGIN
    IF current_setting('vh.master_rewrap', true) = 'vault_master' THEN
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

-- ---- api_keys (ak_master) -------------------------------------------------------------------------------------------

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS master_version INTEGER;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS encrypted_secret_access_key_next BYTEA DEFAULT NULL;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS iv_next BYTEA DEFAULT NULL;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS encrypted_provider_token_next BYTEA DEFAULT NULL;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS provider_token_iv_next BYTEA DEFAULT NULL;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS master_version_next INTEGER DEFAULT NULL;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS encrypted_secret_access_key_prev BYTEA DEFAULT NULL;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS iv_prev BYTEA DEFAULT NULL;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS encrypted_provider_token_prev BYTEA DEFAULT NULL;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS provider_token_iv_prev BYTEA DEFAULT NULL;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS master_version_prev INTEGER DEFAULT NULL;

UPDATE api_keys SET master_version = 1 WHERE master_version IS NULL;
ALTER TABLE api_keys ALTER COLUMN master_version SET DEFAULT vh_master_version('ak_master');
ALTER TABLE api_keys ALTER COLUMN master_version SET NOT NULL;

CREATE OR REPLACE FUNCTION vh_api_keys_master_guard() RETURNS trigger
    LANGUAGE plpgsql AS
$$
DECLARE
    current_version INTEGER;
BEGIN
    IF current_setting('vh.master_rewrap', true) = 'ak_master' THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE'
        AND NEW.encrypted_secret_access_key IS NOT DISTINCT FROM OLD.encrypted_secret_access_key
        AND NEW.iv IS NOT DISTINCT FROM OLD.iv
        AND NEW.encrypted_provider_token IS NOT DISTINCT FROM OLD.encrypted_provider_token
        AND NEW.provider_token_iv IS NOT DISTINCT FROM OLD.provider_token_iv
        AND NEW.master_version IS NOT DISTINCT FROM OLD.master_version THEN
        RETURN NEW;
    END IF;
    current_version := vh_master_version('ak_master');
    IF NEW.master_version IS DISTINCT FROM current_version THEN
        RAISE EXCEPTION 'API key % is wrapped under API key master version %, but the current version is %',
            NEW.id, NEW.master_version, current_version
            USING ERRCODE = 'check_violation';
    END IF;
    NEW.encrypted_secret_access_key_next := NULL;
    NEW.iv_next := NULL;
    NEW.encrypted_provider_token_next := NULL;
    NEW.provider_token_iv_next := NULL;
    NEW.master_version_next := NULL;
    NEW.encrypted_secret_access_key_prev := NULL;
    NEW.iv_prev := NULL;
    NEW.encrypted_provider_token_prev := NULL;
    NEW.provider_token_iv_prev := NULL;
    NEW.master_version_prev := NULL;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS api_keys_master_guard ON api_keys;
CREATE TRIGGER api_keys_master_guard
    BEFORE INSERT OR UPDATE ON api_keys
    FOR EACH ROW EXECUTE FUNCTION vh_api_keys_master_guard();

-- ---- s3_gateway_credentials (s3gw_master) ---------------------------------------------------------------------------

ALTER TABLE s3_gateway_credentials ADD COLUMN IF NOT EXISTS master_version INTEGER;
ALTER TABLE s3_gateway_credentials ADD COLUMN IF NOT EXISTS encrypted_secret_access_key_next BYTEA DEFAULT NULL;
ALTER TABLE s3_gateway_credentials ADD COLUMN IF NOT EXISTS iv_next BYTEA DEFAULT NULL;
ALTER TABLE s3_gateway_credentials ADD COLUMN IF NOT EXISTS master_version_next INTEGER DEFAULT NULL;
ALTER TABLE s3_gateway_credentials ADD COLUMN IF NOT EXISTS encrypted_secret_access_key_prev BYTEA DEFAULT NULL;
ALTER TABLE s3_gateway_credentials ADD COLUMN IF NOT EXISTS iv_prev BYTEA DEFAULT NULL;
ALTER TABLE s3_gateway_credentials ADD COLUMN IF NOT EXISTS master_version_prev INTEGER DEFAULT NULL;

UPDATE s3_gateway_credentials SET master_version = 1 WHERE master_version IS NULL;
ALTER TABLE s3_gateway_credentials ALTER COLUMN master_version SET DEFAULT vh_master_version('s3gw_master');
ALTER TABLE s3_gateway_credentials ALTER COLUMN master_version SET NOT NULL;

CREATE OR REPLACE FUNCTION vh_s3_gateway_master_guard() RETURNS trigger
    LANGUAGE plpgsql AS
$$
DECLARE
    current_version INTEGER;
BEGIN
    IF current_setting('vh.master_rewrap', true) = 's3gw_master' THEN
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE'
        AND NEW.encrypted_secret_access_key IS NOT DISTINCT FROM OLD.encrypted_secret_access_key
        AND NEW.iv IS NOT DISTINCT FROM OLD.iv
        AND NEW.master_version IS NOT DISTINCT FROM OLD.master_version THEN
        RETURN NEW;
    END IF;
    current_version := vh_master_version('s3gw_master');
    IF NEW.master_version IS DISTINCT FROM current_version THEN
        RAISE EXCEPTION 'S3 gateway credential % is wrapped under S3 gateway master version %, but the current version is %',
            NEW.id, NEW.master_version, current_version
            USING ERRCODE = 'check_violation';
    END IF;
    NEW.encrypted_secret_access_key_next := NULL;
    NEW.iv_next := NULL;
    NEW.master_version_next := NULL;
    NEW.encrypted_secret_access_key_prev := NULL;
    NEW.iv_prev := NULL;
    NEW.master_version_prev := NULL;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS s3_gateway_credentials_master_guard ON s3_gateway_credentials;
CREATE TRIGGER s3_gateway_credentials_master_guard
    BEFORE INSERT OR UPDATE ON s3_gateway_credentials
    FOR EACH ROW EXECUTE FUNCTION vh_s3_gateway_master_guard();
