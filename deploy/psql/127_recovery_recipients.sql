-- Recovery recipients and KEV1 key envelopes (#370, WS3-b; design/encryption/03-metadata-recovery.md §5).
--
--   vault_recovery_grant  one recovery recipient enrolled on a vault: an independently revocable grant (§5.7) of the
--                         vault's key versions to a customer-held public key. Only the public key ever reaches the
--                         server; the matching recovery seed stays on the customer's device. Class 'customer' is the
--                         only class implemented (custody amendment, #344): the CHECK refuses any other, so no code
--                         path can record a custodian or threshold grant without a reviewed migration. Suite 1
--                         (X25519) is the only suite recovery recipients use. Revoking keeps the row (the manifest
--                         root lists it with revoked_at): it stops new envelopes, never access already granted.
--   vault_key_envelope    which KEV1 envelopes (`.vaulthalla/key/<kid>` in the vault's bucket) exist for which grant
--                         and key version, so a rotation, an enrollment or the sync pass writes only the missing ones
--                         and the manifest root names them (keys[].envelopes).
--
-- Idempotent and safe on upgraded installs: two new tables, nothing existing changes.

CREATE TABLE IF NOT EXISTS vault_recovery_grant
(
    vault_id      INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    grant_id      TEXT        PRIMARY KEY CHECK (grant_id ~ '^[0-9a-hjkmnp-tv-z]{26}$'),
    recipient_id  TEXT        NOT NULL CHECK (recipient_id ~ '^[0-9a-f]{64}$'),
    public_key    BYTEA       NOT NULL,
    suite         SMALLINT    NOT NULL,
    class         TEXT        NOT NULL DEFAULT 'customer',
    label         TEXT,
    added_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    authorized_by TEXT        NOT NULL,
    revoked_at    TIMESTAMPTZ,
    revoked_by    TEXT,
    CONSTRAINT vault_recovery_grant_customer_only CHECK (class = 'customer'),
    CONSTRAINT vault_recovery_grant_suite CHECK (suite = 1 AND octet_length(public_key) = 32),
    CONSTRAINT vault_recovery_grant_revocation CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);

-- One active grant per recipient key and vault (a revoked one may be enrolled again as a new grant).
CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_recovery_grant_active
    ON vault_recovery_grant (vault_id, recipient_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS vault_key_envelope
(
    vault_id    INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    grant_id    TEXT        NOT NULL REFERENCES vault_recovery_grant (grant_id) ON DELETE CASCADE,
    key_version INTEGER     NOT NULL CHECK (key_version >= 1),
    kid         TEXT        NOT NULL CHECK (kid ~ '^[0-9a-hjkmnp-tv-z]{26}$'),
    written_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (vault_id, grant_id, key_version)
);
