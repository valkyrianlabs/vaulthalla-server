-- Upstream control plane (#237) and event-driven upstream sync (#96).
--
-- An upstream API key can now also administer its provider account (AWS S3, Cloudflare R2): list and create buckets,
-- adopt existing ones, manage Vaulthalla-owned lifecycle and event-notification rules, run the queues those events
-- arrive on, and clean up buckets Vaulthalla created. Authority is split by the new admin permission module
-- admin.upstream (view, configure, provision, protect, unprotect, destroy), never by extra cloud credentials.
--
--   api_keys.admin_*            the key is an administrative credential; probe results and the resolved account.
--   api_keys.*provider_token*   Cloudflare only: the account API token (bearer) R2 event notifications and Queues
--                               need, sealed with the same TPM-bound master key as the S3 secret.
--   upstream_bucket             what Vaulthalla knows about a bucket, keyed by (provider, account_ref, bucket), never
--                               by API key, so deleting and re-creating a key keeps its locks. Carries the hard
--                               protection lock and the provisioning state machine.
--   upstream_audit              append-only record of every control-plane mutation and refusal worth keeping.
--   upstream_event_channel      a queue Vaulthalla consumes (one per AWS account+region, one per R2 account).
--   upstream_event_subscription a vault's event rule on its bucket, routed to a channel.
--   upstream_event_inbox        durable, deduplicated events; written before the queue message is acknowledged.
--   upstream_write_intent       Vaulthalla's own pending PUT/DELETEs, so their notifications are not re-synced.
--
-- Idempotent and safe on upgraded installs: additive columns with defaults, new tables, guarded grants. Existing API
-- keys stay plain storage credentials (admin_enabled FALSE) and existing vaults are untouched.

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS admin_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS provider_account_id TEXT DEFAULT NULL;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS encrypted_provider_token BYTEA DEFAULT NULL;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS provider_token_iv BYTEA DEFAULT NULL;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS admin_capabilities JSONB DEFAULT NULL;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS admin_validated_at TIMESTAMPTZ DEFAULT NULL;

-- admin.upstream: bit 0 view, 1 configure, 2 provision, 3 protect, 4 unprotect, 5 destroy (LSB = bit 0; BIT strings
-- are written MSB first). Fresh installs seed the same grants from core (core/src/rbac/role/Admin.cpp).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'admin_role'
          AND column_name = 'upstream_permissions'
    ) THEN
        ALTER TABLE admin_role
            ADD COLUMN upstream_permissions BIT(8) NOT NULL DEFAULT B'00000000';

        UPDATE admin_role SET upstream_permissions = B'00111111' WHERE name = 'super_admin';
        UPDATE admin_role SET upstream_permissions = B'00001111' WHERE name IN ('admin', 'platform_operator');
        UPDATE admin_role SET upstream_permissions = B'00001001' WHERE name = 'security_admin';
        UPDATE admin_role SET upstream_permissions = B'00000001' WHERE name IN ('auditor', 'vault_admin');
    END IF;
END $$;

INSERT INTO permission (name, description, category, bit_position)
VALUES ('admin.upstream.view', 'Allows viewing upstream bucket inventory, bucket configuration, event status and the upstream audit log.', 'admin', 0),
       ('admin.upstream.configure', 'Allows enabling provider administration on API keys and managing lifecycle rules and event subscriptions.', 'admin', 1),
       ('admin.upstream.provision', 'Allows creating managed upstream buckets and adopting existing ones into vaults.', 'admin', 2),
       ('admin.upstream.protect', 'Allows protecting upstream buckets from every Vaulthalla operation.', 'admin', 3),
       ('admin.upstream.unprotect', 'Allows removing upstream bucket protection.', 'admin', 4),
       ('admin.upstream.destroy', 'Allows detaching managed buckets and deleting upstream buckets and their objects.', 'admin', 5)
ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS upstream_bucket
(
    id                     BIGSERIAL PRIMARY KEY,
    provider               TEXT NOT NULL,
    account_ref            TEXT NOT NULL,
    bucket                 TEXT NOT NULL,
    region                 TEXT DEFAULT NULL,
    ownership              TEXT NOT NULL DEFAULT 'unmanaged'
        CHECK (ownership IN ('managed', 'adopted', 'unmanaged')),
    provisioning_state     TEXT NOT NULL DEFAULT 'none'
        CHECK (provisioning_state IN ('none', 'creating', 'configuring', 'ready', 'failed', 'detached',
                                      'deleting', 'deleted')),
    created_by_vaulthalla  BOOLEAN NOT NULL DEFAULT FALSE,
    operation_token        TEXT DEFAULT NULL,
    vault_id               INTEGER REFERENCES vault (id) ON DELETE SET NULL,
    is_protected           BOOLEAN NOT NULL DEFAULT FALSE,
    protected_at           TIMESTAMPTZ DEFAULT NULL,
    protected_by           INTEGER REFERENCES users (id) ON DELETE SET NULL,
    protected_by_name      TEXT DEFAULT NULL,
    protection_reason      TEXT DEFAULT NULL,
    last_seen_api_key_id   INTEGER REFERENCES api_keys (id) ON DELETE SET NULL,
    discovered_at          TIMESTAMPTZ DEFAULT NULL,
    last_seen_at           TIMESTAMPTZ DEFAULT NULL,
    last_error             TEXT DEFAULT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (provider, account_ref, bucket)
);

CREATE INDEX IF NOT EXISTS idx_upstream_bucket_protected ON upstream_bucket (provider, bucket) WHERE is_protected;
CREATE INDEX IF NOT EXISTS idx_upstream_bucket_vault ON upstream_bucket (vault_id) WHERE vault_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS upstream_audit
(
    id          BIGSERIAL PRIMARY KEY,
    at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_id     INTEGER REFERENCES users (id) ON DELETE SET NULL,
    user_name   TEXT DEFAULT NULL,
    action      TEXT NOT NULL,
    provider    TEXT NOT NULL DEFAULT '',
    account_ref TEXT NOT NULL DEFAULT '',
    bucket      TEXT NOT NULL DEFAULT '',
    api_key_id  INTEGER REFERENCES api_keys (id) ON DELETE SET NULL,
    vault_id    INTEGER REFERENCES vault (id) ON DELETE SET NULL,
    outcome     TEXT NOT NULL CHECK (outcome IN ('ok', 'refused', 'failed', 'partial')),
    detail      JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_upstream_audit_bucket ON upstream_audit (provider, account_ref, bucket, at DESC);
CREATE INDEX IF NOT EXISTS idx_upstream_audit_at ON upstream_audit (at DESC);

CREATE TABLE IF NOT EXISTS upstream_event_channel
(
    id                    BIGSERIAL PRIMARY KEY,
    provider              TEXT NOT NULL,
    account_ref           TEXT NOT NULL,
    region                TEXT NOT NULL DEFAULT '',
    queue_name            TEXT NOT NULL,
    queue_ref             TEXT DEFAULT NULL,
    queue_arn             TEXT DEFAULT NULL,
    dlq_ref               TEXT DEFAULT NULL,
    dlq_arn               TEXT DEFAULT NULL,
    api_key_id            INTEGER REFERENCES api_keys (id) ON DELETE SET NULL,
    state                 TEXT NOT NULL DEFAULT 'provisioning'
        CHECK (state IN ('provisioning', 'active', 'degraded', 'failed', 'removed')),
    created_by_vaulthalla BOOLEAN NOT NULL DEFAULT FALSE,
    last_poll_at          TIMESTAMPTZ DEFAULT NULL,
    last_success_at       TIMESTAMPTZ DEFAULT NULL,
    last_message_at       TIMESTAMPTZ DEFAULT NULL,
    last_error            TEXT DEFAULT NULL,
    last_error_at         TIMESTAMPTZ DEFAULT NULL,
    consecutive_failures  INTEGER NOT NULL DEFAULT 0,
    backlog_estimate      BIGINT DEFAULT NULL,
    next_poll_at          TIMESTAMPTZ DEFAULT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (provider, account_ref, region, queue_name)
);

CREATE TABLE IF NOT EXISTS upstream_event_subscription
(
    id                 BIGSERIAL PRIMARY KEY,
    channel_id         BIGINT REFERENCES upstream_event_channel (id) ON DELETE SET NULL,
    upstream_bucket_id BIGINT NOT NULL REFERENCES upstream_bucket (id) ON DELETE CASCADE,
    vault_id           INTEGER REFERENCES vault (id) ON DELETE SET NULL,
    rule_ids           JSONB NOT NULL DEFAULT '[]'::jsonb,
    prefix             TEXT NOT NULL DEFAULT '',
    foreign_objects    TEXT NOT NULL DEFAULT 'import' CHECK (foreign_objects IN ('import', 'ignore')),
    state              TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'active', 'failed', 'removing', 'removed')),
    baseline_state     TEXT NOT NULL DEFAULT 'none' CHECK (baseline_state IN ('none', 'pending', 'running', 'done')),
    baseline_started_at TIMESTAMPTZ DEFAULT NULL,
    foreign_rules      INTEGER NOT NULL DEFAULT 0,
    last_error         TEXT DEFAULT NULL,
    activated_at       TIMESTAMPTZ DEFAULT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- One live subscription per vault; removed rows stay as history.
CREATE UNIQUE INDEX IF NOT EXISTS uq_upstream_event_subscription_live_vault
    ON upstream_event_subscription (vault_id) WHERE state <> 'removed' AND vault_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_upstream_event_subscription_channel ON upstream_event_subscription (channel_id);

CREATE TABLE IF NOT EXISTS upstream_event_inbox
(
    id              BIGSERIAL PRIMARY KEY,
    channel_id      BIGINT REFERENCES upstream_event_channel (id) ON DELETE SET NULL,
    subscription_id BIGINT REFERENCES upstream_event_subscription (id) ON DELETE SET NULL,
    vault_id        INTEGER REFERENCES vault (id) ON DELETE CASCADE,
    provider        TEXT NOT NULL,
    account_ref     TEXT NOT NULL,
    bucket          TEXT NOT NULL,
    object_key      TEXT NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('created', 'removed')),
    event_name      TEXT NOT NULL DEFAULT '',
    dedupe_key      TEXT NOT NULL,
    message_id      TEXT DEFAULT NULL,
    sequencer       TEXT DEFAULT NULL,
    version_id      TEXT DEFAULT NULL,
    etag            TEXT DEFAULT NULL,
    size_bytes      BIGINT DEFAULT NULL,
    event_time      TIMESTAMPTZ NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    state           TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'applied', 'done', 'skipped', 'failed')),
    origin          TEXT NOT NULL DEFAULT 'unknown' CHECK (origin IN ('external', 'self', 'unknown')),
    note            TEXT DEFAULT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ DEFAULT NULL,
    last_error      TEXT DEFAULT NULL,
    finished_at     TIMESTAMPTZ DEFAULT NULL,
    UNIQUE (provider, account_ref, bucket, dedupe_key)
);

CREATE INDEX IF NOT EXISTS idx_upstream_event_inbox_work
    ON upstream_event_inbox (vault_id, state, id) WHERE state IN ('pending', 'applied');
CREATE INDEX IF NOT EXISTS idx_upstream_event_inbox_finished
    ON upstream_event_inbox (finished_at) WHERE state IN ('done', 'skipped');
CREATE INDEX IF NOT EXISTS idx_upstream_event_inbox_key ON upstream_event_inbox (vault_id, object_key, id);

CREATE TABLE IF NOT EXISTS upstream_write_intent
(
    id            BIGSERIAL PRIMARY KEY,
    vault_id      INTEGER NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    object_key    TEXT NOT NULL,
    op            TEXT NOT NULL CHECK (op IN ('put', 'delete')),
    expected_size BIGINT DEFAULT NULL,
    recorded_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at    TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_upstream_write_intent_key ON upstream_write_intent (vault_id, object_key, op);
CREATE INDEX IF NOT EXISTS idx_upstream_write_intent_expiry ON upstream_write_intent (expires_at);

-- FX-3: event pipeline hardening.
--   inbox.event_time_ms           millisecond event time: R2 has no sequencer, and two events of one key within a
--                                 second must still apply in the order they happened.
--   write_intent.etag/completed_at our own write's ETag (when the request returned one) and when it finished: the
--                                 intent lives from completion, and a failed request removes it.
--   channel.continuity_*          the event stream may have lost messages (a delivery gap longer than the queue's
--                                 retention, events that reached the dead-letter queue): the index is no longer kept
--                                 fresh by events alone, and the next regular pass lists the bucket again.
--   channel.dlq_depth             messages in the channel's dead-letter queue at the last check.
ALTER TABLE upstream_event_inbox ADD COLUMN IF NOT EXISTS event_time_ms BIGINT DEFAULT NULL;
ALTER TABLE upstream_write_intent ADD COLUMN IF NOT EXISTS etag TEXT DEFAULT NULL;
ALTER TABLE upstream_write_intent ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ DEFAULT NULL;
ALTER TABLE upstream_event_channel ADD COLUMN IF NOT EXISTS continuity_broken_at TIMESTAMPTZ DEFAULT NULL;
ALTER TABLE upstream_event_channel ADD COLUMN IF NOT EXISTS continuity_note TEXT DEFAULT NULL;
ALTER TABLE upstream_event_channel ADD COLUMN IF NOT EXISTS dlq_depth BIGINT DEFAULT NULL;
