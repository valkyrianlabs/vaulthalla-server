-- Device approval keys (#361, MFA design note docs/dev/mfa-design.md sections 6.2 and 9; decision D6).
--
--   device_approval_keys  one P-256 approval key per paired device (Vaulthalla Desktop keeps it in the Secure Enclave,
--                         apart from the mTLS key, and every signature needs Touch ID or the Mac password). The public
--                         key only: its SubjectPublicKeyInfo (DER, 91 bytes) and that DER's SHA-256 in lowercase hex.
--                         registered_via says how a person approved it: with the pairing request it came in
--                         ('pairing'), or later through an approval in the web console ('console_approval').
--                         revoked_at is set with the device's revocation; a revoked key never approves anything again,
--                         and its hash stays unique, so it can't be registered a second time.
--
-- Challenges and console approval requests are not stored: they live minutes in the daemon's memory, and a restart
-- only makes a device ask again.
--
-- Additive and idempotent: one new table, safe on upgraded installs. No existing row changes; a device paired before
-- this release has no approval key until it registers one.

CREATE TABLE IF NOT EXISTS device_approval_keys
(
    device_id       INTEGER PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    public_key_spki BYTEA       NOT NULL CHECK (octet_length(public_key_spki) = 91),
    spki_sha256     TEXT        NOT NULL UNIQUE CHECK (spki_sha256 ~ '^[0-9a-f]{64}$'),
    registered_via  TEXT        NOT NULL CHECK (registered_via IN ('pairing', 'console_approval')),
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at      TIMESTAMPTZ
);
