-- Idle sign-out for web-console sessions (#319).
--
-- last_activity_at is when the server last saw a person use this session: sign-in, or an auth.activity message the
-- console sends on real input (pointer, keyboard, scroll), never on background polling. The server writes NOW()
-- itself; no client-supplied time is stored. A human refresh token whose last activity is older than
-- services.connection_lifecycle_manager.idle_timeout_minutes is revoked the next time anything tries to use it, and
-- open sockets are closed by the lifecycle sweep. Existing tokens start their idle clock at upgrade time.

ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS last_activity_at TIMESTAMP NOT NULL DEFAULT NOW();
