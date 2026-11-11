-- Vaulthalla Cloud recovery enrollment (Tier B, customer-key-controlled; spec 05 §3 as amended 2026-11-10;
-- design/cloud/server-link.md): which vaults a super admin explicitly enrolled with `vh cloud recovery enroll`.
-- Enrolling sends the vault's existing KEV1 envelopes (ciphertext wrapped to recipients the customer enrolled), its
-- key checks, attestations, attestation public keys and manifest checkpoint to the linked vaulthalla.cloud account;
-- never a key, seed, kit or export. `vh cloud recovery unenroll` deletes the cloud's records and this row.
--
-- Idempotent and safe on upgraded installs: one new table, nothing existing changes.

CREATE TABLE IF NOT EXISTS cloud_recovery_vault
(
    vault_id        INTEGER     PRIMARY KEY REFERENCES vault (id) ON DELETE CASCADE,
    vault_uid       TEXT        NOT NULL CHECK (vault_uid ~ '^[0-9a-hjkmnp-tv-z]{26}$'),
    installation_id TEXT        NOT NULL,
    enrolled_by     TEXT        NOT NULL,
    enrolled_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_upload_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
