-- Vaulthalla Cloud link (plan step 6 of valkyrianlabs/vaulthalla-cloud; design/cloud/server-link.md): whether this server is
-- linked to a vaulthalla.cloud account, as one row. Linking is never required, and nothing here exists until a super
-- admin runs `vh cloud link`.
--
--   pending   a link request is open: the cloud's request id, until the account holder approves it on vaulthalla.cloud
--   linked    approved: the cloud's installation id and account id
--
-- The identity key itself is sealed to this host (KeyProvider slot `cloud_identity`), never stored here; the row
-- holds its public key, which the cloud has too. `vh cloud unlink` deletes the row and the sealed key.
--
-- Idempotent and safe on upgraded installs: one new table, nothing existing changes.

CREATE TABLE IF NOT EXISTS cloud_link
(
    singleton          BOOLEAN     PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    endpoint           TEXT        NOT NULL,
    status             TEXT        NOT NULL CHECK (status IN ('pending', 'linked')),
    public_key         BYTEA       NOT NULL CHECK (octet_length(public_key) = 32),
    name               TEXT        NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    request_id         TEXT,
    request_expires_at TIMESTAMPTZ,
    installation_id    TEXT        CHECK (installation_id ~ '^[0-9a-hjkmnp-tv-z]{26}$'),
    account_id         BIGINT,
    requested_by       TEXT        NOT NULL,
    requested_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    linked_at          TIMESTAMPTZ,
    CONSTRAINT cloud_link_state CHECK (
        (status = 'pending' AND request_id IS NOT NULL AND installation_id IS NULL AND linked_at IS NULL) OR
        (status = 'linked' AND installation_id IS NOT NULL AND account_id IS NOT NULL AND linked_at IS NOT NULL))
);
