-- Paired devices (Vaulthalla Desktop) for the daemon's mutual-TLS device listener.
--
--   devices      one row per approved device key. A device acts as its user (user_id) with that user's RBAC; the
--                connection authenticates by the SHA-256 of its certificate's SubjectPublicKeyInfo (lowercase hex),
--                which is also the device id the protocol uses. A key rotation moves the old hash to
--                previous_spki_sha256 until the first handshake with the new one. Revocation is final: the row stays
--                (with revoked_at) so the key can never be approved again.
--   device_node  the node identity a paired Desktop records (one row, created on first use).
--
-- Pairing windows and requests are not stored: they live 10 minutes at most in the daemon's memory, carry nonces
-- that never need to touch disk, and a restart only makes a Desktop start pairing over.
--
-- Idempotent and safe on upgraded installs: new tables only; nothing existing changes.

CREATE TABLE IF NOT EXISTS devices
(
    id                   SERIAL PRIMARY KEY,
    user_id              INTEGER     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name                 TEXT        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
    platform             TEXT        NOT NULL CHECK (char_length(platform) BETWEEN 1 AND 32),
    app_version          TEXT        NOT NULL DEFAULT '' CHECK (char_length(app_version) <= 64),
    spki_sha256          TEXT        NOT NULL UNIQUE CHECK (spki_sha256 ~ '^[0-9a-f]{64}$'),
    previous_spki_sha256 TEXT                 DEFAULT NULL
        CHECK (previous_spki_sha256 IS NULL OR previous_spki_sha256 ~ '^[0-9a-f]{64}$'),
    approved_by          INTEGER              REFERENCES users (id) ON DELETE SET NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at         TIMESTAMPTZ          DEFAULT NULL,
    last_ip              TEXT                 DEFAULT NULL,
    revoked_at           TIMESTAMPTZ          DEFAULT NULL
);

CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices (user_id);

-- A key is current for one device at most, and previous for one device at most.
CREATE UNIQUE INDEX IF NOT EXISTS uq_devices_previous_spki
    ON devices (previous_spki_sha256) WHERE previous_spki_sha256 IS NOT NULL;

CREATE TABLE IF NOT EXISTS device_node
(
    singleton  BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    node_id    TEXT        NOT NULL CHECK (char_length(node_id) BETWEEN 1 AND 64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
