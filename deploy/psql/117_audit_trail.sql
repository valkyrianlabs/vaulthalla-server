-- Tamper-evident audit trail (#323).
--
-- audit_event is a hash chain: every row's hash covers its own fields and the previous row's hash
-- (core/include/audit/Chain.hpp has the exact byte layout), so editing, inserting or deleting a row breaks every hash
-- after it. The daemon periodically signs the chain head with this node's Ed25519 key (audit_head) and sends the
-- signed head to the audit log file and, when enabled, to syslog, so a copy exists outside this database.
--
-- Rows are append-only: a trigger refuses UPDATE and DELETE, except the retention purge
-- (vh_audit_purge_before), which first records the hash of the last row it removes in audit_checkpoint, so
-- verification can start from there.
--
-- What this does NOT stop: someone with database owner or superuser rights can drop the trigger and rewrite the
-- chain. The signed heads, and above all the copies forwarded off the host, are what make that detectable.

CREATE TABLE IF NOT EXISTS audit_event
(
    seq         BIGINT PRIMARY KEY,
    occurred_us BIGINT      NOT NULL,           -- microseconds since the Unix epoch (UTC)
    level       TEXT        NOT NULL,
    action      TEXT        NOT NULL,
    outcome     TEXT        NOT NULL,           -- success | failure | denied | info
    actor_id    INTEGER,                         -- users.id at the time; no FK, deleting a user keeps the history
    actor       TEXT        NOT NULL DEFAULT '',
    origin      TEXT        NOT NULL DEFAULT '', -- web | cli | device <id> | share | system ...
    vault_id    INTEGER,                         -- the vault acted on, when there is one (no FK: history outlives it)
    entry_id    BIGINT,                          -- the file or folder acted on, by id (never its name: #327)
    message     TEXT        NOT NULL,
    details     TEXT        NOT NULL DEFAULT '{}',  -- JSON object, stored as the exact bytes that were hashed
    prev_hash   BYTEA       NOT NULL CHECK (octet_length(prev_hash) = 32),
    hash        BYTEA       NOT NULL CHECK (octet_length(hash) = 32)
);

CREATE INDEX IF NOT EXISTS audit_event_occurred_idx ON audit_event (occurred_us);
CREATE INDEX IF NOT EXISTS audit_event_action_idx ON audit_event (action, seq);
CREATE INDEX IF NOT EXISTS audit_event_actor_idx ON audit_event (actor_id, seq);
CREATE INDEX IF NOT EXISTS audit_event_vault_idx ON audit_event (vault_id, seq);

-- Signed chain heads: Ed25519 over "vh-audit-head-v1" || node_id || UInt64BE(seq) || hash || UInt64BE(signed_us),
-- by the key in key_attestation_keys(key_id).
CREATE TABLE IF NOT EXISTS audit_head
(
    seq        BIGINT  NOT NULL,
    hash       BYTEA   NOT NULL CHECK (octet_length(hash) = 32),
    signed_us  BIGINT  NOT NULL,
    node_id    TEXT    NOT NULL,
    key_id     INTEGER NOT NULL REFERENCES key_attestation_keys (id),
    signature  BYTEA   NOT NULL CHECK (octet_length(signature) = 64),
    PRIMARY KEY (seq, signed_us)
);

-- Where the retained chain starts after a purge: the last purged row's seq and hash.
CREATE TABLE IF NOT EXISTS audit_checkpoint
(
    seq       BIGINT PRIMARY KEY,
    hash      BYTEA       NOT NULL CHECK (octet_length(hash) = 32),
    purged    BIGINT      NOT NULL,
    purged_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION vh_audit_append_only() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    IF TG_OP = 'DELETE' AND current_setting('vh.audit_purge', true) = 'on' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'audit records are append-only (% on %)', TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

DROP TRIGGER IF EXISTS audit_event_append_only ON audit_event;
CREATE TRIGGER audit_event_append_only
    BEFORE UPDATE OR DELETE ON audit_event
    FOR EACH ROW EXECUTE FUNCTION vh_audit_append_only();

DROP TRIGGER IF EXISTS audit_head_append_only ON audit_head;
CREATE TRIGGER audit_head_append_only
    BEFORE UPDATE OR DELETE ON audit_head
    FOR EACH ROW EXECUTE FUNCTION vh_audit_append_only();

DROP TRIGGER IF EXISTS audit_checkpoint_append_only ON audit_checkpoint;
CREATE TRIGGER audit_checkpoint_append_only
    BEFORE UPDATE OR DELETE ON audit_checkpoint
    FOR EACH ROW EXECUTE FUNCTION vh_audit_append_only();

-- Retention: removes events older than `cutoff_us`, keeping the newest signed head's row and everything after it,
-- and records the checkpoint first. Returns the number of events removed.
CREATE OR REPLACE FUNCTION vh_audit_purge_before(cutoff_us BIGINT) RETURNS BIGINT
    LANGUAGE plpgsql AS
$$
DECLARE
    last_seq  BIGINT;
    last_hash BYTEA;
    keep_from BIGINT;
    removed   BIGINT;
BEGIN
    SELECT COALESCE(MAX(seq), 0) INTO keep_from FROM audit_head;
    SELECT seq, hash INTO last_seq, last_hash
    FROM audit_event
    WHERE occurred_us < cutoff_us AND seq < keep_from
    ORDER BY seq DESC
    LIMIT 1;
    IF last_seq IS NULL THEN
        RETURN 0;
    END IF;
    PERFORM set_config('vh.audit_purge', 'on', true);
    DELETE FROM audit_event WHERE seq <= last_seq;
    GET DIAGNOSTICS removed = ROW_COUNT;
    DELETE FROM audit_head WHERE seq <= last_seq;
    INSERT INTO audit_checkpoint (seq, hash, purged) VALUES (last_seq, last_hash, removed);
    PERFORM set_config('vh.audit_purge', 'off', true);
    RETURN removed;
END;
$$;

-- The audit_log table from migration 040 was never written. Drop it when empty; keep any rows under a new name.
DO
$$
BEGIN
    IF to_regclass('public.audit_log') IS NOT NULL THEN
        IF EXISTS (SELECT 1 FROM audit_log) THEN
            ALTER TABLE audit_log RENAME TO audit_log_legacy;
        ELSE
            DROP TABLE audit_log;
        END IF;
    END IF;
END;
$$;
