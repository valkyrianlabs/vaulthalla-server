-- MFA factor storage (#356, MFA design note docs/dev/mfa-design.md sections 4.1-4.3 and 9).
--
--   user_mfa               one row per account that has MFA state: the WebAuthn user handle (a random 32 bytes, never
--                          the numeric id or the name), the per-user "required" flag and the recovery cooldown
--   webauthn_credentials   passkeys and security keys (public keys only; nothing secret is stored)
--   totp_factors           RFC 6238 authenticator apps. The 20-byte seed is AES-256-GCM sealed under mfa_seal (an
--                          internal secret under the host master key) with AAD "vh/mfa/totp/v1" || user_id ||
--                          factor_uuid, so a row can't be moved to another account. last_step is the replay guard:
--                          a code is accepted only by a conditional UPDATE that raises it. confirmed_at stays NULL (the
--                          factor is unusable) until the first correct code, within 10 minutes of enrollment
--   recovery_code_batches  a batch of ten codes is inactive until acknowledged; acknowledging supersedes the previous
--                          one, and at most one acknowledged, unsuperseded batch exists per account
--   recovery_codes         one keyed BLAKE2b-256 hash per code (key mfa_pepper, domain "vh/mfa/recovery/v1" ||
--                          user_id), used once through a conditional UPDATE
--
-- MFA state stays out of users (and identities::UserState), so the identity revision triggers (108) are untouched.
-- Additive and idempotent: new tables and indexes only, safe on upgraded installs.

CREATE TABLE IF NOT EXISTS user_mfa (
    user_id                 INTEGER PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    webauthn_user_handle    BYTEA NOT NULL UNIQUE CHECK (octet_length(webauthn_user_handle) = 32),
    required                BOOLEAN NOT NULL DEFAULT FALSE,
    recovery_cooldown_until TIMESTAMPTZ,
    reset_at                TIMESTAMPTZ,
    reset_by                INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id                      SERIAL PRIMARY KEY,
    user_id                 INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id           BYTEA NOT NULL UNIQUE CHECK (octet_length(credential_id) BETWEEN 16 AND 1023),
    public_key_cose         BYTEA NOT NULL,
    cose_alg                SMALLINT NOT NULL CHECK (cose_alg IN (-8, -7, -257)),
    rp_id                   TEXT NOT NULL,
    aaguid                  UUID,
    sign_count              BIGINT NOT NULL DEFAULT 0,
    backup_eligible         BOOLEAN NOT NULL,
    backup_state            BOOLEAN NOT NULL,
    discoverable            BOOLEAN,
    transports              TEXT[] NOT NULL DEFAULT '{}',
    attestation_fmt         TEXT NOT NULL,
    label                   TEXT NOT NULL CHECK (char_length(label) BETWEEN 1 AND 64),
    created_during_recovery BOOLEAN NOT NULL DEFAULT FALSE,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at            TIMESTAMPTZ,
    suspended_at            TIMESTAMPTZ,
    suspended_reason        TEXT,
    disabled_at             TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user ON webauthn_credentials (user_id);

CREATE TABLE IF NOT EXISTS totp_factors (
    id                      SERIAL PRIMARY KEY,
    factor_uuid             UUID NOT NULL UNIQUE,
    user_id                 INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    label                   TEXT NOT NULL CHECK (char_length(label) BETWEEN 1 AND 64),
    secret_sealed           BYTEA NOT NULL,
    secret_iv               BYTEA NOT NULL CHECK (octet_length(secret_iv) = 12),
    last_step               BIGINT NOT NULL DEFAULT 0,
    confirmed_at            TIMESTAMPTZ,
    created_during_recovery BOOLEAN NOT NULL DEFAULT FALSE,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at            TIMESTAMPTZ,
    disabled_at             TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_totp_factors_user ON totp_factors (user_id);

CREATE TABLE IF NOT EXISTS recovery_code_batches (
    id              UUID PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ,
    superseded_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_recovery_code_batches_user ON recovery_code_batches (user_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_recovery_batch_active
    ON recovery_code_batches (user_id) WHERE acknowledged_at IS NOT NULL AND superseded_at IS NULL;

CREATE TABLE IF NOT EXISTS recovery_codes (
    id        SERIAL PRIMARY KEY,
    batch_id  UUID NOT NULL REFERENCES recovery_code_batches (id) ON DELETE CASCADE,
    user_id   INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(code_hash) = 32),
    used_at   TIMESTAMPTZ,
    used_ip   TEXT
);
CREATE INDEX IF NOT EXISTS idx_recovery_codes_batch ON recovery_codes (batch_id);
