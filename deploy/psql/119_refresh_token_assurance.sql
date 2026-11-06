-- Session assurance on refresh tokens (#354, MFA design note docs/dev/mfa-design.md section 5.3).
--
-- A refresh token row is written once, when its session is signed in, and records how that sign-in was proven:
--   aal        the authenticator assurance level, 1 (one factor: a password) or 2 (a second factor or a passkey)
--   amr        the methods used (RFC 8176 style): pwd, hwk / swk (device-bound / synced passkey), otp, rec
--   auth_time  when the person proved it (not when the token was last refreshed)
-- The refresh JWT carries no level: it is minted at the websocket handshake, before anyone signs in, so the stored
-- row is the authority and every use of the cookie reads it (and checks the MFA policy against it).
--
-- Additive and idempotent. Rows written before this migration were password sign-ins: they read as aal 1, amr {pwd},
-- with auth_time taken from issued_at.

ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS aal       SMALLINT NOT NULL DEFAULT 1 CHECK (aal IN (1, 2)),
    ADD COLUMN IF NOT EXISTS amr       TEXT[]   NOT NULL DEFAULT '{pwd}',
    ADD COLUMN IF NOT EXISTS auth_time TIMESTAMP;

UPDATE refresh_tokens SET auth_time = COALESCE(issued_at, NOW()) WHERE auth_time IS NULL;

ALTER TABLE refresh_tokens
    ALTER COLUMN auth_time SET DEFAULT NOW(),
    ALTER COLUMN auth_time SET NOT NULL;

-- The sessions list (auth.sessions.list) reads one user's live rows.
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_live ON refresh_tokens (user_id) WHERE revoked = FALSE;
