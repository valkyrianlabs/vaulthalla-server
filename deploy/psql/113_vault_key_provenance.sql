-- Vault key provenance: the daemon's own record of every key version it creates or unseals, so `vh vault keys import`
-- restores only versions this node verifiably had (.claude/context/key-backup.md, revision 3).
--
--   key_attestation_keys  this node's Ed25519 public keys for key attestations. The private key is sealed on this
--                         host (KeyProvider "key_attest") and never exported. When it can no longer be unsealed (a TPM
--                         reset, a database restored onto a new host) the daemon generates a new keypair: a new row,
--                         older ones get retired_at, and every old public key stays so old attestations still verify.
--   key_check             lowercase hex of BLAKE2b-128 keyed by the 32 key bytes over "vh-key-check-v1" ‖ vault_id ‖
--                         UInt32BE(version) (vault/KeyCheck.hpp): a keyed PRF output that identifies one key version
--                         of one vault and reveals nothing usable about the key.
--   attestation           Ed25519 signature (64 bytes) by key attestation_key_id over "vh-key-attest-v1" ‖ node_id
--                         (device_node, migration 112) ‖ UInt64BE(vault_id) ‖ UInt32BE(version) ‖ key_check (16 bytes).
--                         Public, like the key check.
--   vault_key_salvage     best-effort salvage passes: files sealed under a key version the node can't attest are
--                         re-encrypted under a fresh daemon key with a supplied key held only in memory. One row per
--                         pass (its report); at most one running pass per vault.
--
-- key_check / attestation are set when a version is created and copied along when a rotation retires it or a deletion
-- retains it; rows from before this migration stay NULL until the daemon next unseals them, which fills them in.
--
-- Idempotent and safe on upgraded installs: new tables and nullable columns only; nothing existing changes.

CREATE TABLE IF NOT EXISTS key_attestation_keys
(
    id         SERIAL PRIMARY KEY,
    public_key BYTEA       NOT NULL UNIQUE CHECK (octet_length(public_key) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retired_at TIMESTAMPTZ          DEFAULT NULL
);

ALTER TABLE vault_keys ADD COLUMN IF NOT EXISTS key_check TEXT DEFAULT NULL;
ALTER TABLE vault_keys ADD COLUMN IF NOT EXISTS attestation_key_id INTEGER DEFAULT NULL;
ALTER TABLE vault_keys ADD COLUMN IF NOT EXISTS attestation BYTEA DEFAULT NULL;

ALTER TABLE vault_keys_trashed ADD COLUMN IF NOT EXISTS key_check TEXT DEFAULT NULL;
ALTER TABLE vault_keys_trashed ADD COLUMN IF NOT EXISTS attestation_key_id INTEGER DEFAULT NULL;
ALTER TABLE vault_keys_trashed ADD COLUMN IF NOT EXISTS attestation BYTEA DEFAULT NULL;

ALTER TABLE vault_deletion_key ADD COLUMN IF NOT EXISTS key_check TEXT DEFAULT NULL;
ALTER TABLE vault_deletion_key ADD COLUMN IF NOT EXISTS attestation_key_id INTEGER DEFAULT NULL;
ALTER TABLE vault_deletion_key ADD COLUMN IF NOT EXISTS attestation BYTEA DEFAULT NULL;

-- Constraints by name, so a re-run finds them instead of adding duplicates.
DO $$
BEGIN
    ALTER TABLE vault_keys ADD CONSTRAINT fk_vault_keys_attestation_key
        FOREIGN KEY (attestation_key_id) REFERENCES key_attestation_keys (id);
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
    ALTER TABLE vault_keys_trashed ADD CONSTRAINT fk_vault_keys_trashed_attestation_key
        FOREIGN KEY (attestation_key_id) REFERENCES key_attestation_keys (id);
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
    ALTER TABLE vault_deletion_key ADD CONSTRAINT fk_vault_deletion_key_attestation_key
        FOREIGN KEY (attestation_key_id) REFERENCES key_attestation_keys (id);
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS vault_key_salvage
(
    id             SERIAL PRIMARY KEY,
    vault_id       INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    versions       INTEGER[]   NOT NULL,
    new_version    INTEGER              DEFAULT NULL,
    state          TEXT        NOT NULL DEFAULT 'running' CHECK (state IN ('running', 'finished')),
    started_by     INTEGER              REFERENCES users (id) ON DELETE SET NULL,
    started_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at    TIMESTAMPTZ          DEFAULT NULL,
    salvaged       INTEGER     NOT NULL DEFAULT 0,
    unrecoverable  INTEGER     NOT NULL DEFAULT 0,
    skipped_remote INTEGER     NOT NULL DEFAULT 0,
    deferred       INTEGER     NOT NULL DEFAULT 0,
    failed         INTEGER     NOT NULL DEFAULT 0,
    failures       JSONB       NOT NULL DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_vault_key_salvage_vault ON vault_key_salvage (vault_id, started_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS uq_vault_key_salvage_running ON vault_key_salvage (vault_id) WHERE state = 'running';
