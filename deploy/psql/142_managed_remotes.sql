-- Managed remotes (design/cloud/managed-remotes.md): a server linked to an account with a storage entitlement keeps its
-- vaults in buckets the account's service provisions, one bucket per vault. The server still holds every vault key and
-- encrypts; the service never receives a key or anything unwrapped. Nothing here runs, or contacts anything, unless the
-- server is linked and a super admin confirmed the account's recovery key (migration 141).
--
--   api_keys.origin, .cloud_access
--                         who issued a bucket key: `customer` (every key so far) or `cloud` (a managed bucket's key,
--                         delivered sealed to this server and owned by the vault's owner). A cloud key is read-only to
--                         people (ops::api_keys refuses to edit or remove it); cloud_access is what the service lets it
--                         do (`full`, or `read_delete` while the account is restricted), set exactly when origin is
--                         cloud. Ejection turns a cloud key into a customer key in place.
--   vault_cloud_storage   one row per vault the managed-storage service considered: its switch (on, off, offered: a
--                         vault that existed when storage became available waits for a person; declined), its state
--                         (unregistered, registered, waiting, keyed, attaching, active, detaching, off, moved, ejected,
--                         ended, failed), the bucket as the service reported it, the key this server holds for it, the
--                         content retention last acknowledged, and the step's retry bookkeeping. BYOS vaults get no row.
--   cloud_storage_account the account's storage entitlement as last fetched (one row; deleted with the link): state,
--                         quota, usage, access, ejection, the billing summary, and this server's settings: whether new
--                         vaults are switched on by default, when storage was first seen available on this link, and
--                         whether the offer for vaults that existed then is open.
--   admin_role.cloud_permissions
--                         the admin module `cloud` (bit 0 view, 1 storage: switches, offers, rotation, the default;
--                         2 billing). Built-in roles get view; super admins hold everything.
--   vault_remote_detach.mode, .lost; vault_remote_detach_item state `lost`
--                         a detach `in_place` makes a vault local without any request to its bucket (the bucket is gone
--                         or no longer this server's): files held here are verified and kept, files held only in the
--                         bucket are listed as lost (path and size, in `lost`) and leave the catalog, and recovery
--                         envelopes only the bucket held are wrapped again into the database before the switch.
--
-- Additive and idempotent: new columns with defaults, new tables, one widened CHECK. Safe on upgraded installs; no
-- existing row changes meaning (every existing key is `customer`, every existing detach `hydrate`).

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS origin TEXT NOT NULL DEFAULT 'customer'
    CHECK (origin IN ('customer', 'cloud'));
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS cloud_access TEXT DEFAULT NULL
    CHECK (cloud_access IS NULL OR cloud_access IN ('full', 'read_delete'));
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'api_keys_cloud_access_origin_check') THEN
        ALTER TABLE api_keys ADD CONSTRAINT api_keys_cloud_access_origin_check
            CHECK ((origin = 'cloud') = (cloud_access IS NOT NULL));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS vault_cloud_storage
(
    vault_id        INTEGER     PRIMARY KEY REFERENCES vault (id) ON DELETE CASCADE,
    vault_uid       TEXT        NOT NULL CHECK (vault_uid ~ '^[0-9a-hjkmnp-tv-z]{26}$'),
    switch          TEXT        NOT NULL CHECK (switch IN ('on', 'off', 'offered', 'declined')),
    switch_by       TEXT        NOT NULL CHECK (switch_by <> ''),
    switch_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    state           TEXT        NOT NULL DEFAULT 'unregistered'
        CHECK (state IN ('unregistered', 'registered', 'waiting', 'keyed', 'attaching', 'active', 'detaching', 'off',
                         'moved', 'ejected', 'ended', 'failed')),
    reason          TEXT        DEFAULT NULL CHECK (reason IS NULL OR length(reason) <= 200),
    bucket          TEXT        DEFAULT NULL,
    bucket_id       TEXT        DEFAULT NULL,
    s3_endpoint     TEXT        DEFAULT NULL,
    region          TEXT        DEFAULT NULL,
    api_key_id      INTEGER     REFERENCES api_keys (id) ON DELETE SET NULL,
    key_id          TEXT        DEFAULT NULL,       -- the provider's key id of the key this server holds
    key_state       TEXT        NOT NULL DEFAULT 'none' CHECK (key_state IN ('none', 'issued', 'active', 'superseded')),
    key_access      TEXT        DEFAULT NULL CHECK (key_access IS NULL OR key_access IN ('full', 'read_delete')),
    retention_days  INTEGER     DEFAULT NULL CHECK (retention_days IS NULL OR retention_days BETWEEN 1 AND 36500),
    retention_sent  INTEGER     DEFAULT NULL CHECK (retention_sent IS NULL OR retention_sent BETWEEN 1 AND 36500),
    label_generation INTEGER    DEFAULT NULL,       -- the account key generation the sealed label was sent for
    enrolled_version INTEGER    DEFAULT NULL,       -- the key version the last automatic enrollment covered
    enroll_behind_since TIMESTAMPTZ DEFAULT NULL,   -- an automatic enrollment has been due (and failing) since
    attempts        INTEGER     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at TIMESTAMPTZ DEFAULT NULL,
    last_error      TEXT        DEFAULT NULL,
    registered_at   TIMESTAMPTZ DEFAULT NULL,
    ready_at        TIMESTAMPTZ DEFAULT NULL,
    active_at       TIMESTAMPTZ DEFAULT NULL,
    moved_at        TIMESTAMPTZ DEFAULT NULL,
    ejected_at      TIMESTAMPTZ DEFAULT NULL,
    ended_at        TIMESTAMPTZ DEFAULT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cloud_storage_account
(
    singleton              BOOLEAN     PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    state                  TEXT        DEFAULT NULL,   -- active | past_due | restricted | suspended | ended | null (none)
    plan                   TEXT        DEFAULT NULL,
    quota_bytes            BIGINT      DEFAULT NULL CHECK (quota_bytes IS NULL OR quota_bytes >= 0),
    storage_access         TEXT        DEFAULT NULL CHECK (storage_access IS NULL OR
                                                           storage_access IN ('full', 'read_delete', 'none')),
    cause                  TEXT        DEFAULT NULL,
    used_bytes             BIGINT      DEFAULT NULL,
    usage_day              TEXT        DEFAULT NULL,
    account_key_confirmed  BOOLEAN     DEFAULT NULL,   -- the cloud's word: the account key's offline copy is confirmed
    provider               TEXT        DEFAULT NULL,
    ejection               JSONB       DEFAULT NULL,
    billing                JSONB       DEFAULT NULL,   -- state_since, next {state, at}, deletion_at, current_period_end
    fetched_at             TIMESTAMPTZ DEFAULT NULL,
    fetch_error            TEXT        DEFAULT NULL,
    new_vaults             BOOLEAN     NOT NULL DEFAULT TRUE,
    enabled_at             TIMESTAMPTZ DEFAULT NULL,   -- storage first seen available on this link
    offer_open             BOOLEAN     NOT NULL DEFAULT FALSE,
    fast_until             TIMESTAMPTZ DEFAULT NULL,   -- poll every few seconds until then (after a billing handoff)
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- The admin module `cloud` (rbac/permission/admin/Cloud.hpp). The column is new, so the block runs once per database.
-- Built-in roles are seeded from core only on a fresh database; on an upgraded one the roles that watch the server get
-- view, as a fresh install seeds them (admin, auditor, platform_operator); super_admin gets every bit.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'admin_role'
          AND column_name = 'cloud_permissions'
    ) THEN
        ALTER TABLE admin_role
            ADD COLUMN cloud_permissions BIT(8) NOT NULL DEFAULT B'00000000';

        UPDATE admin_role SET cloud_permissions = B'00000111' WHERE name = 'super_admin';
        UPDATE admin_role SET cloud_permissions = B'00000001' WHERE name IN ('admin', 'auditor', 'platform_operator');
    END IF;
END $$;

INSERT INTO permission (name, description, category, bit_position)
VALUES ('admin.cloud.view', 'Allows viewing the server''s link and its managed storage.', 'admin', 0),
       ('admin.cloud.storage', 'Allows switching managed storage on or off per vault, answering the offer, rotating '
                               'bucket keys and setting the default for new vaults.', 'admin', 1),
       ('admin.cloud.billing', 'Allows opening the account''s billing pages.', 'admin', 2)
ON CONFLICT DO NOTHING;

ALTER TABLE vault_remote_detach ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'hydrate'
    CHECK (mode IN ('hydrate', 'in_place'));
ALTER TABLE vault_remote_detach ADD COLUMN IF NOT EXISTS lost JSONB DEFAULT NULL;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'vault_remote_detach_item_state_check') THEN
        ALTER TABLE vault_remote_detach_item DROP CONSTRAINT vault_remote_detach_item_state_check;
    END IF;
    ALTER TABLE vault_remote_detach_item ADD CONSTRAINT vault_remote_detach_item_state_check
        CHECK (state IN ('pending', 'verified', 'failed', 'lost'));
END $$;
