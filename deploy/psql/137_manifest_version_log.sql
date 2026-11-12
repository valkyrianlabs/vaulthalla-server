-- The manifest's publish path on buckets without conditional writes (design/encryption/06-publish-without-
-- preconditions.md §5, version_log): the root's provider version is the arbiter, so the chain position records it.
--
--   remote_manifest_state.root_version_id   the provider version id of the settled root (version_log buckets; NULL on
--                                           conditional buckets and for states from before this migration, which the
--                                           next read finds by the root's hash)
--   remote_manifest_state.base_version_id   the version id of the root it was built on (its prev), and
--   remote_manifest_state.settle_window     the version ids listed between that base and the settled root when it
--                                           settled (normally none): a later listing that shows another id between
--                                           them breaks the provider's ordering assumptions (order_violation, §5.3)
--   remote_manifest_state.own_epoch         the epoch of the last root this server published itself: a server stops
--                                           publishing only when a canonical root after it excludes it from the
--                                           root's `writers` (manifest_superseded, §5.5)
--   remote_manifest_state refused_reason    gains order_violation, superseded and publish_mode_mismatch
--   remote_manifest_gc                      when each segment became unreferenced by the canonical chain: version_log
--                                           buckets collect a segment after 24 h unreferenced, every version by id
--
-- Idempotent and safe on upgraded installs: new nullable columns, a new table, a widened CHECK.

ALTER TABLE remote_manifest_state ADD COLUMN IF NOT EXISTS root_version_id TEXT DEFAULT NULL;
ALTER TABLE remote_manifest_state ADD COLUMN IF NOT EXISTS base_version_id TEXT DEFAULT NULL;
ALTER TABLE remote_manifest_state ADD COLUMN IF NOT EXISTS settle_window TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE remote_manifest_state ADD COLUMN IF NOT EXISTS own_epoch BIGINT DEFAULT NULL;

ALTER TABLE remote_manifest_state DROP CONSTRAINT IF EXISTS remote_manifest_state_refused_check;
ALTER TABLE remote_manifest_state ADD CONSTRAINT remote_manifest_state_refused_check
    CHECK (refused_reason IS NULL OR refused_reason IN ('rollback', 'fork', 'order_violation', 'superseded',
                                                        'publish_mode_mismatch'));

CREATE TABLE IF NOT EXISTS remote_manifest_gc
(
    vault_id              INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    sid                   TEXT        NOT NULL,
    first_unreferenced_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (vault_id, sid)
);
