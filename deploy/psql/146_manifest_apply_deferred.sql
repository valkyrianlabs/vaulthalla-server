-- The manifest applier's deferred entries (design/sync/manifest-applier.md, work item 4, "Open files").
--
--   manifest_apply_deferred   a content replacement, delete or trash another writer's root asked for while the file
--                             had a working copy open (FUSE): the entry as the root has it (`target`, manifest entry
--                             JSON; NULL for a delete) and the generation the local copy had then (`ours_generation`,
--                             hex). The collector reports `target` for the uid while the row exists, so a publish never
--                             reverts it; the first pass after the last release applies it, or, when the close sealed
--                             new bytes, hands the incoming object to the planner as a two-sided change. One row per
--                             entry: a newer root replaces it.
--
-- Idempotent and safe on upgraded installs: a new table only; nothing existing changes.

CREATE TABLE IF NOT EXISTS manifest_apply_deferred
(
    vault_id        INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    uid             UUID        NOT NULL,
    op              TEXT        NOT NULL CHECK (op IN ('replace_content', 'delete', 'trash')),
    target          JSONB       DEFAULT NULL CHECK ((op = 'delete') = (target IS NULL)),
    ours_generation TEXT        DEFAULT NULL CHECK (ours_generation IS NULL OR ours_generation ~ '^[0-9a-f]+$'),
    root_epoch      BIGINT      NOT NULL CHECK (root_epoch >= 1),
    root_sha256     TEXT        NOT NULL CHECK (root_sha256 ~ '^[0-9a-f]{64}$'),
    deferred_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (vault_id, uid)
);
