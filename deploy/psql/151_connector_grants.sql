-- Remote connectors (design/core/mcp-remote-signin.md): a hosted AI client (Claude, ChatGPT) or a CLI on another
-- machine reaches this node's MCP tools with OAuth 2.1, within a scope a person chose.
--
--   connector_settings        the node's switch and policy, one row at most (absent = off). public_origin is the
--                             https origin the node is reached at; the resource is public_origin + '/mcp'. max_scope
--                             is the widest scope a grant may be given (write by default; decided 2026-11-22).
--                             client_hosts: when not empty, the only hosts a client-id metadata document may come
--                             from (empty = any https host, the default).
--   connector_clients         the clients the node knows: 'cimd' (a client-id metadata document the node fetched),
--                             'registered' (added by an operator) or 'dcr' (dynamic registration, off by default).
--   connector_grants          one row per approval: one user, one client, one exact redirect URI, one scope, until
--                             expires_at (at most 90 days) or revocation. revoked_at and revoked_reason are final.
--   connector_refresh_tokens  the grant's refresh tokens, by digest only (sha256 of 256 random bits, as for
--                             refresh_tokens.token_hash); rotated on every use (successor_id), so a used token
--                             presented again is reuse. Access tokens and authorization codes are never stored.
--
-- Additive and idempotent: new tables only.

CREATE TABLE IF NOT EXISTS connector_settings
(
    id            SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    enabled       BOOLEAN     NOT NULL DEFAULT FALSE,
    public_origin TEXT CHECK (public_origin IS NULL OR public_origin LIKE 'https://%'),
    max_scope     TEXT        NOT NULL DEFAULT 'write' CHECK (max_scope IN ('read', 'write', 'destructive')),
    dcr_enabled   BOOLEAN     NOT NULL DEFAULT FALSE,
    client_hosts  TEXT[]      NOT NULL DEFAULT '{}',
    changed_by    INTEGER REFERENCES users (id) ON DELETE SET NULL,
    changed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (NOT enabled OR public_origin IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS connector_clients
(
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id       TEXT        NOT NULL UNIQUE CHECK (client_id <> '' AND length(client_id) <= 512),
    kind            TEXT        NOT NULL CHECK (kind IN ('cimd', 'registered', 'dcr')),
    name            TEXT        NOT NULL CHECK (name <> '' AND length(name) <= 64),
    redirect_uris   TEXT[]      NOT NULL CHECK (cardinality(redirect_uris) BETWEEN 1 AND 16),
    document_sha256 TEXT,
    fetched_at      TIMESTAMPTZ,
    cache_until     TIMESTAMPTZ,
    created_by      INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ,
    disabled_at     TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS connector_grants
(
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        INTEGER     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_row     UUID        NOT NULL REFERENCES connector_clients (id) ON DELETE CASCADE,
    client_id      TEXT        NOT NULL,
    client_name    TEXT        NOT NULL,
    redirect_uri   TEXT        NOT NULL,
    scope          TEXT        NOT NULL CHECK (scope IN ('read', 'write', 'destructive')),
    resource       TEXT        NOT NULL,
    label          TEXT CHECK (label IS NULL OR length(label) <= 64),
    approved_via   TEXT        NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at     TIMESTAMPTZ NOT NULL,
    last_used_at   TIMESTAMPTZ,
    last_ip        TEXT,
    revoked_at     TIMESTAMPTZ,
    revoked_reason TEXT CHECK (revoked_reason IS NULL OR revoked_reason IN
                               ('manual', 'user_inactive', 'grantor_policy', 'refresh_reuse', 'code_reuse',
                                'switch_off', 'expired', 'client_removed', 'sessions_revoked', 'mfa_recovery')),
    revoked_by     INTEGER REFERENCES users (id) ON DELETE SET NULL,
    CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL)),
    CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS idx_connector_grants_user ON connector_grants (user_id);
CREATE INDEX IF NOT EXISTS idx_connector_grants_live ON connector_grants (expires_at) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS connector_refresh_tokens
(
    id           BIGSERIAL PRIMARY KEY,
    grant_id     UUID        NOT NULL REFERENCES connector_grants (id) ON DELETE CASCADE,
    token_digest TEXT        NOT NULL UNIQUE CHECK (token_digest LIKE 'sha256:%'),
    issued_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL,
    used_at      TIMESTAMPTZ,
    successor_id BIGINT REFERENCES connector_refresh_tokens (id) ON DELETE SET NULL,
    revoked_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_connector_refresh_tokens_grant ON connector_refresh_tokens (grant_id);
