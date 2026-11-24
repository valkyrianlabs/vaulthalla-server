-- S3 gateway upstream profiles: what a gateway CreateBucket creates.
--
-- Until now a CreateBucket through the gateway always made a local vault. An upstream profile names an upstream
-- API key and the settings of the S3 vault a CreateBucket makes over it: whether objects are encrypted upstream, the
-- sync strategy and conflict policy, and a prefix for the upstream bucket's name. The upstream bucket is created
-- through the provider (or adopted when it exists and is empty), never taken over while it holds objects.
--
--   s3_gateway_upstream_profile   one row per profile. `name` is a region-shaped code ("vl-b2"): a client selects the
--                                 profile per request with CreateBucketConfiguration.LocationConstraint or by signing
--                                 with it as the region, so it is immutable and never "local". The API key is a
--                                 reference; its secret stays in api_keys. ON DELETE RESTRICT: removing the key
--                                 would silently turn the profile's credentials back into local-vault creators.
--   s3_gateway_credentials        upstream_profile_id: the profile this credential's CreateBucket uses.
--                                 upstream_server_default: use the server's default profile
--                                 (s3_gateway.default_upstream_profile in config.yaml) instead; off unless set, so a
--                                 server default never changes what existing credentials create. Neither set: a
--                                 local vault, as before. upstream_reapply: whether a later change of the profile's
--                                 sync settings is re-applied to the buckets this credential created (NULL = the
--                                 server's s3_gateway.reapply_upstream_profile_changes).
--   s3_gateway_credential_upstream_profile
--                                 the profiles a credential may select per request (LocationConstraint or signing
--                                 region), besides its own. Without a row a request cannot name that profile, so a
--                                 key is bounded in which upstream accounts it can create buckets on.
--   s3_gateway_bucket             created_by_credential_id / upstream_profile_id: which credential and profile a
--                                 gateway CreateBucket made the bucket with (NULL for every other bucket). A bucket
--                                 follows the profile it was created from; both are SET NULL when their row goes.
--
-- Additive and idempotent: new tables, nullable or defaulted columns.

CREATE TABLE IF NOT EXISTS s3_gateway_upstream_profile
(
    id               SERIAL PRIMARY KEY,
    name             TEXT        NOT NULL UNIQUE
        CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$' AND name <> 'local'),
    api_key_id       INTEGER     NOT NULL REFERENCES api_keys (id) ON DELETE RESTRICT,
    encrypt_upstream BOOLEAN     NOT NULL DEFAULT TRUE,
    sync_strategy    TEXT        NOT NULL CHECK (sync_strategy IN ('cache', 'sync', 'mirror')),
    conflict_policy  TEXT        NOT NULL CHECK (conflict_policy IN ('keep_local', 'keep_remote', 'keep_newest', 'ask')),
    bucket_prefix    TEXT        NOT NULL DEFAULT ''
        CHECK (bucket_prefix = '' OR bucket_prefix ~ '^[a-z0-9][a-z0-9.-]{0,31}$'),
    description      TEXT,
    created_by       INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_s3_gateway_upstream_profile_api_key
    ON s3_gateway_upstream_profile (api_key_id);

DROP TRIGGER IF EXISTS trg_set_updated_at_s3_gateway_upstream_profile
    ON s3_gateway_upstream_profile;
CREATE TRIGGER trg_set_updated_at_s3_gateway_upstream_profile
    BEFORE UPDATE ON s3_gateway_upstream_profile
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();

ALTER TABLE s3_gateway_credentials
    ADD COLUMN IF NOT EXISTS upstream_profile_id INTEGER
        REFERENCES s3_gateway_upstream_profile (id) ON DELETE RESTRICT,
    ADD COLUMN IF NOT EXISTS upstream_server_default BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS upstream_reapply BOOLEAN DEFAULT NULL;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 's3_gateway_credentials_one_upstream_source') THEN
        ALTER TABLE s3_gateway_credentials
            ADD CONSTRAINT s3_gateway_credentials_one_upstream_source
                CHECK (NOT (upstream_profile_id IS NOT NULL AND upstream_server_default));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_s3_gateway_credentials_upstream_profile
    ON s3_gateway_credentials (upstream_profile_id) WHERE upstream_profile_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS s3_gateway_credential_upstream_profile
(
    credential_id INTEGER     NOT NULL REFERENCES s3_gateway_credentials (id) ON DELETE CASCADE,
    profile_id    INTEGER     NOT NULL REFERENCES s3_gateway_upstream_profile (id) ON DELETE RESTRICT,
    created_by    INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (credential_id, profile_id)
);

CREATE INDEX IF NOT EXISTS idx_s3_gateway_credential_upstream_profile_profile
    ON s3_gateway_credential_upstream_profile (profile_id);

ALTER TABLE s3_gateway_bucket
    ADD COLUMN IF NOT EXISTS created_by_credential_id INTEGER
        REFERENCES s3_gateway_credentials (id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS upstream_profile_id INTEGER
        REFERENCES s3_gateway_upstream_profile (id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_s3_gateway_bucket_upstream_profile
    ON s3_gateway_bucket (upstream_profile_id) WHERE upstream_profile_id IS NOT NULL;
