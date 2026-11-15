-- Replicated vaults: the join, leave and replica removal (design/cloud/mirrors.md, "Join (server side)", "Leave";
-- design/sync/manifest-applier.md, "As built: the join").
--
--   remote_manifest_state.writers_change  {"kind": "add"|"remove", "node": "<node id>"}: a change of the root's
--                                         writers this server's publishes carry until a recorded root shows it (a
--                                         join adds this node, a leave removes it, a replica removal another node).
--   manifest_writer_root                  each writer's last root this server recorded (its own and applied ones):
--                                         the replica status (vh vault sync info, storage.vault.get).
--
-- Idempotent and safe on upgraded installs: a nullable column and a new table.

ALTER TABLE remote_manifest_state ADD COLUMN IF NOT EXISTS writers_change JSONB;

DO $$ BEGIN
ALTER TABLE remote_manifest_state ADD CONSTRAINT remote_manifest_state_writers_change_check CHECK (
    writers_change IS NULL OR (
        jsonb_typeof(writers_change) = 'object'
        AND writers_change ->> 'kind' IN ('add', 'remove')
        AND coalesce(writers_change ->> 'node', '') <> ''));
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS manifest_writer_root
(
    vault_id     INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    node_id      TEXT        NOT NULL CHECK (node_id <> ''),
    epoch        BIGINT      NOT NULL CHECK (epoch > 0),
    root_sha256  TEXT        NOT NULL CHECK (root_sha256 ~ '^[0-9a-f]{64}$'),
    published_at TIMESTAMPTZ,
    recorded_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (vault_id, node_id)
);
