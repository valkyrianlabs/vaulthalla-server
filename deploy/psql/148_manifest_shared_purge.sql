-- Objects of a shared vault's trash this server purged locally without deleting them from the bucket
-- (design/sync/manifest-applier.md, "Orphan collection for shared-vault trash"): another writer may still name the
-- object live (it restored the file) or trashed. sync::vault_manifest::Service::collectSharedOrphans deletes one from the
-- bucket only after a grace period and only while the recorded head (re-read then), no deferred entry and no pending
-- own root name it; never an object this server did not purge itself.
--
-- Idempotent and safe on upgraded installs: a new table only.

CREATE TABLE IF NOT EXISTS manifest_shared_purge
(
    vault_id   INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    object_key TEXT        NOT NULL CHECK (object_key ~ '^o/[0-9a-hjkmnp-tv-z]{26}$'),
    purged_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (vault_id, object_key)
);
