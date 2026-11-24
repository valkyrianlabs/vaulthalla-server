-- Vault read grants (ops/ReadGrants.hpp; `vh vault read-grant`).
--
-- A read grant hands a backup orchestrator everything a disaster-recovery tool needs to read one vault: a read-only
-- S3 gateway credential for the vault, and a read-only key limited to the vault's upstream bucket, minted with the
-- upstream account key Vaulthalla already holds (Backblaze B2 first). Both travel in one JSON document that the daemon
-- returns only as an OpenPGP message encrypted to pinned recipients. Plaintext secrets are never stored here.
--
--   read_grant_recipient        an OpenPGP public key pinned by its full fingerprint (the privileged, human step).
--                               Removing one only stops new grants to it (removed_at); at most one live row per
--                               fingerprint.
--   vault_read_grant            one grant: the vault, the gateway credential it created (by id and access key id), the
--                               upstream key it created (by the provider's key id, never the secret), who issued it and
--                               when, and its state:
--                                 issuing                created, not finished yet (a crash leaves it here; revoke
--                                                        deletes whatever it recorded)
--                                 active                 delivered
--                                 revocation_incomplete  revoke deleted the gateway credential but the provider
--                                                        refused or failed to delete the upstream key: retry
--                                 revoked                both halves are gone
--                               ciphertext is the armored OpenPGP message as it was returned (useless without the
--                               recipient's secret key).
--   vault_read_grant_recipient  the recipients a grant was encrypted to (one or two).
--   vault.sync.action.read_grants
--                               new vault permission, bit 3 of the sync action set (bit 11 of sync_permissions).
--                               Granted to nobody here: no built-in role carries it.
--
-- A deleted vault, API key, user or gateway credential leaves the grant row (SET NULL) so its upstream key can still be
-- found and revoked. Additive and idempotent.

CREATE TABLE IF NOT EXISTS read_grant_recipient
(
    id             SERIAL PRIMARY KEY,
    fingerprint    CHAR(40)    NOT NULL CHECK (fingerprint ~ '^[0-9A-F]{40}$'),
    label          TEXT,
    user_ids       TEXT        NOT NULL DEFAULT '',   -- the key's user IDs, one per line, as the key states them
    algorithm      TEXT        NOT NULL,
    key_created_at TIMESTAMPTZ,
    key_expires_at TIMESTAMPTZ,
    public_key     TEXT        NOT NULL,              -- ASCII-armored OpenPGP public key, exactly as pinned
    source         TEXT        NOT NULL CHECK (source IN ('input', 'keyserver')),
    source_url     TEXT,
    pinned_by      INTEGER REFERENCES users (id) ON DELETE SET NULL,
    pinned_by_name TEXT        NOT NULL,
    pinned_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    removed_at     TIMESTAMPTZ,
    removed_by     TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_read_grant_recipient_live
    ON read_grant_recipient (fingerprint)
    WHERE removed_at IS NULL;

CREATE TABLE IF NOT EXISTS vault_read_grant
(
    id                    SERIAL PRIMARY KEY,
    grant_id              TEXT        NOT NULL UNIQUE CHECK (grant_id ~ '^[0-9a-z]{26}$'),
    vault_id              INTEGER REFERENCES vault (id) ON DELETE SET NULL,
    vault_name            TEXT        NOT NULL,
    state                 TEXT        NOT NULL DEFAULT 'issuing'
        CHECK (state IN ('issuing', 'active', 'revocation_incomplete', 'revoked')),
    gateway_only          BOOLEAN     NOT NULL DEFAULT FALSE,
    gateway_credential_id INTEGER REFERENCES s3_gateway_credentials (id) ON DELETE SET NULL,
    gateway_access_key    TEXT,
    gateway_bucket        TEXT,
    api_key_id            INTEGER REFERENCES api_keys (id) ON DELETE SET NULL,
    upstream_provider     TEXT,
    upstream_endpoint     TEXT,
    upstream_region       TEXT,
    upstream_bucket       TEXT,
    upstream_key_id       TEXT,   -- the provider's id of the read-only key; its secret is never stored
    upstream_key_name     TEXT,
    issued_by             INTEGER REFERENCES users (id) ON DELETE SET NULL,
    issued_by_name        TEXT        NOT NULL,
    issued_at             TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at            TIMESTAMPTZ,
    revoked_by            TEXT,
    revocation_error      TEXT,
    ciphertext            TEXT,   -- the armored OpenPGP message the grant was returned as
    CHECK ((state = 'revoked') = (revoked_at IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_vault_read_grant_vault_live
    ON vault_read_grant (vault_id)
    WHERE state <> 'revoked';

CREATE INDEX IF NOT EXISTS idx_vault_read_grant_api_key_live
    ON vault_read_grant (api_key_id)
    WHERE state <> 'revoked';

CREATE TABLE IF NOT EXISTS vault_read_grant_recipient
(
    grant_row_id INTEGER  NOT NULL REFERENCES vault_read_grant (id) ON DELETE CASCADE,
    recipient_id INTEGER  NOT NULL REFERENCES read_grant_recipient (id) ON DELETE RESTRICT,
    fingerprint  CHAR(40) NOT NULL,
    PRIMARY KEY (grant_row_id, recipient_id)
);

-- The permission catalog (permissions.list) is seeded from core only on a fresh database; list the new permission on
-- upgraded ones too (bit position as the fresh seed writes it: sync action set at offset 8, bit 3).
INSERT INTO permission (name, description, category, bit_position)
VALUES ('vault.sync.action.read_grants',
        'Allows the user to issue, list and revoke vault read grants: read-only S3 gateway and upstream credentials, delivered only encrypted to a pinned OpenPGP recipient.',
        'vault', 11)
ON CONFLICT DO NOTHING;
