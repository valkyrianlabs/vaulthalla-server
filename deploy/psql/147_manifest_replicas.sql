-- Prerequisites of replicated vaults in the manifest applier (design/sync/manifest-applier.md, "As built: replica
-- prerequisites and status"), and the applier's status.
--
--   manifest_foreign_envelope   a KEV1 envelope another writer's root names (`keys[].envelopes`), as a reference: its
--                               kid, key version and recipient (read from the envelope's header, checked against the
--                               vault and version, the kid checked against its bytes). This server's roots name it
--                               while one of this server's grants has that recipient and the key version is in its
--                               history. Never a grant row: grants come from the account's signed policy only.
--   remote_manifest_pending     the sealed bytes of each root this server PUT since its last record (by hash, beside
--                               the hashes of publishing_roots), written before the PUT with the new segments' bytes
--                               (remote_manifest_base, by sid): when another writer built on such a root before this
--                               server recorded it, the apply uses it as its base. Cleared by each record.
--   remote_manifest_state.writers   the recorded root's `writers`: more than this node means another writer exists, and
--                               a trash is then purged here without a remote DELETE (the object may be named live
--                               again by the writer that restores it).
--   manifest_apply_report       the last apply of the vault (epoch, producing node, counts, conflicts, union base,
--                               notes), shown by storage.vault.get and `vh vault sync info`, and the root an apply was
--                               last stopped at (a key problem: alerted once per root).
--
-- Idempotent and safe on upgraded installs: new tables and a new column with a default; nothing existing changes.

CREATE TABLE IF NOT EXISTS manifest_foreign_envelope
(
    vault_id     INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    kid          TEXT        NOT NULL CHECK (kid ~ '^[0-9a-hjkmnp-tv-z]{26}$'),
    key_version  INTEGER     NOT NULL CHECK (key_version >= 1),
    recipient_id TEXT        NOT NULL CHECK (recipient_id ~ '^[0-9a-f]{64}$'),
    seen_at      TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (vault_id, kid)
);

CREATE TABLE IF NOT EXISTS remote_manifest_pending
(
    vault_id    INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    root_sha256 TEXT        NOT NULL CHECK (root_sha256 ~ '^[0-9a-f]{64}$'),
    bytes       BYTEA       NOT NULL,
    noted_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (vault_id, root_sha256)
);

ALTER TABLE remote_manifest_state ADD COLUMN IF NOT EXISTS writers TEXT[] NOT NULL DEFAULT '{}';

CREATE TABLE IF NOT EXISTS manifest_apply_report
(
    vault_id            INTEGER     PRIMARY KEY REFERENCES vault (id) ON DELETE CASCADE,
    epoch               BIGINT      NOT NULL CHECK (epoch >= 1),
    root_sha256         TEXT        NOT NULL CHECK (root_sha256 ~ '^[0-9a-f]{64}$'),
    producer            TEXT        NOT NULL,
    recorded            BOOLEAN     NOT NULL,
    union_base          BOOLEAN     NOT NULL,
    applied             INTEGER     NOT NULL DEFAULT 0,
    skipped             INTEGER     NOT NULL DEFAULT 0,
    deferred            INTEGER     NOT NULL DEFAULT 0,
    kept                INTEGER     NOT NULL DEFAULT 0,
    conflicts_decided   INTEGER     NOT NULL DEFAULT 0,
    conflicts_open      INTEGER     NOT NULL DEFAULT 0,
    notes               JSONB       NOT NULL DEFAULT '[]'::jsonb,
    applied_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    stopped_reason      TEXT        DEFAULT NULL,
    stopped_root_sha256 TEXT        DEFAULT NULL CHECK (stopped_root_sha256 IS NULL OR stopped_root_sha256 ~ '^[0-9a-f]{64}$'),
    stopped_at          TIMESTAMPTZ DEFAULT NULL
);
