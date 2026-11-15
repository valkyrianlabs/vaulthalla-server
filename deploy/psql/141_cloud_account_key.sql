-- The account recovery key on a linked server (design/cloud/key-manager.md, work items 2, 3 and 6): what this server
-- verified and pinned of its vaulthalla.cloud account's recovery key, the account's signed recovery policy it
-- accepted, and which recovery grants rest on them. Nothing here exists until a super admin links the server, and
-- nothing in it is secret: public keys, signed statements and their fingerprints.
--
--   cloud_link.deployment_id, .account_public_id
--                         what the link claim and GET /v1/installation report (the cloud's account-model.md): the
--                         deployment this server is, and the account's public id that every key statement and
--                         recovery policy names. Filled at the next check for a server linked before this migration.
--   cloud_link.key_checked_at, .key_check, .key_check_detail, .offline_copy_at
--                         the last background check of GET /v1/keys/account (when, its outcome, why it failed) and the
--                         date the cloud records for an offline copy of the current key generation. Display only.
--   cloud_account_key     one row per key generation seen for an account: the statement and its signatures as served,
--                         the fingerprint computed here, and its state:
--                           pending     verified, waiting for a super admin to confirm its fingerprint (the first pin)
--                           pinned      confirmed by a person (confirmed_by user:<id> via cli|device) or reached from
--                                       the pin through a signed rotation (chain:<previous generation>); at most one
--                                       per account, and the only state anything is wrapped to
--                           superseded  a pin a later generation replaced
--                           refused     a replacement (not signed by the pin) waiting for a person's confirmation
--                         The pinned row also holds the policy floor: the highest recovery policy this server accepted
--                         (sequence, SHA-256, its bytes and signature). Every row carries an HMAC-SHA-256 over all
--                         its other columns under a key sealed to this host (KeyProvider slot `cloud_account_pin`):
--                         a database writer can't swap the pinned key or lower the floor without failing the check
--                         that every wrap and every policy makes first.
--   vault_recovery_grant.account_key_generation
--                         set on the grant of the pinned account key (the generation it was pinned at): before an
--                         envelope is written to it, its public key must be that MAC-verified pinned generation's.
--   vault_recovery_grant.account_policy_sequence
--                         set on a grant the account's signed recovery policy added (the sequence that added it); the
--                         policy alone adds and revokes such grants.
--   cloud_account_policy_vault
--                         the policy sequence each covered vault last applied (`vh cloud key status`).
--
-- Additive and idempotent: new nullable columns and new tables, safe on upgraded installs. No existing row changes.

ALTER TABLE cloud_link ADD COLUMN IF NOT EXISTS deployment_id TEXT DEFAULT NULL
    CHECK (deployment_id ~ '^[0-9a-hjkmnp-tv-z]{26}$');
ALTER TABLE cloud_link ADD COLUMN IF NOT EXISTS account_public_id TEXT DEFAULT NULL
    CHECK (account_public_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$');
ALTER TABLE cloud_link ADD COLUMN IF NOT EXISTS key_checked_at TIMESTAMPTZ DEFAULT NULL;
ALTER TABLE cloud_link ADD COLUMN IF NOT EXISTS key_check TEXT DEFAULT NULL;
ALTER TABLE cloud_link ADD COLUMN IF NOT EXISTS key_check_detail TEXT DEFAULT NULL;
ALTER TABLE cloud_link ADD COLUMN IF NOT EXISTS offline_copy_at TIMESTAMPTZ DEFAULT NULL;

CREATE TABLE IF NOT EXISTS cloud_account_key
(
    account_public_id  TEXT        NOT NULL
        CHECK (account_public_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),
    generation         INTEGER     NOT NULL CHECK (generation >= 1),
    fingerprint        TEXT        NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{4}(-[0-9a-f]{4}){7}$'),
    x25519_public      BYTEA       NOT NULL CHECK (octet_length(x25519_public) = 32),
    ed25519_public     BYTEA       NOT NULL CHECK (octet_length(ed25519_public) = 32),
    statement          TEXT        NOT NULL,
    signature          BYTEA       NOT NULL CHECK (octet_length(signature) = 64),
    previous_signature BYTEA       DEFAULT NULL CHECK (octet_length(previous_signature) = 64),
    link               TEXT        NOT NULL CHECK (link IN ('initial', 'rotation', 'replacement')),
    state              TEXT        NOT NULL CHECK (state IN ('pending', 'pinned', 'superseded', 'refused')),
    confirmed_by       TEXT        DEFAULT NULL,
    confirmed_at       TIMESTAMPTZ DEFAULT NULL,
    policy_sequence    INTEGER     NOT NULL DEFAULT 0 CHECK (policy_sequence >= 0),
    policy_sha256      BYTEA       DEFAULT NULL CHECK (octet_length(policy_sha256) = 32),
    policy             TEXT        DEFAULT NULL,
    policy_signature   BYTEA       DEFAULT NULL CHECK (octet_length(policy_signature) = 64),
    stored_at          TIMESTAMPTZ NOT NULL,
    mac                BYTEA       NOT NULL CHECK (octet_length(mac) = 32),
    PRIMARY KEY (account_public_id, generation),
    CONSTRAINT cloud_account_key_confirmed CHECK (
        (state IN ('pinned', 'superseded')) = (confirmed_by IS NOT NULL AND confirmed_at IS NOT NULL)),
    CONSTRAINT cloud_account_key_policy CHECK (
        (policy_sequence = 0) = (policy IS NULL) AND (policy IS NULL) = (policy_sha256 IS NULL) AND
        (policy IS NULL) = (policy_signature IS NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_cloud_account_key_one_pin
    ON cloud_account_key (account_public_id) WHERE state = 'pinned';

ALTER TABLE vault_recovery_grant ADD COLUMN IF NOT EXISTS account_key_generation INTEGER DEFAULT NULL
    CHECK (account_key_generation >= 1);
ALTER TABLE vault_recovery_grant ADD COLUMN IF NOT EXISTS account_policy_sequence INTEGER DEFAULT NULL
    CHECK (account_policy_sequence >= 1);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'vault_recovery_grant_account_managed') THEN
        ALTER TABLE vault_recovery_grant ADD CONSTRAINT vault_recovery_grant_account_managed
            CHECK (account_key_generation IS NULL OR account_policy_sequence IS NULL);
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS cloud_account_policy_vault
(
    vault_id          INTEGER     PRIMARY KEY REFERENCES vault (id) ON DELETE CASCADE,
    account_public_id TEXT        NOT NULL,
    sequence          INTEGER     NOT NULL CHECK (sequence >= 1),
    applied_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
