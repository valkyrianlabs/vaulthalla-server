-- Recovered key versions (#371, design/encryption/03-metadata-recovery.md §6.2): `vh vault recover` rebuilds a vault
-- on a node that never held it, from its bucket and the customer's recovery material. A key version becomes canonical
-- there only when its attestation by the original node verifies against a public key the customer pinned (D1, #344);
-- the restoring node then re-attests it over its own node id and the new vault id (vault_keys / vault_keys_trashed).
--
--   vault_key_origin  one row per recovered version: where it was minted (the original node id, the vault id it had
--                     there, the key check over that id), the original node's attestation (key id, public key,
--                     signature), which customer material anchored it (kit or export) and when. Public, like the key
--                     checks and attestations it copies: no key material. The manifest root carries it as
--                     keys[].origin, so a later restore from the same bucket can still anchor the version with a kit
--                     that pins only the original node's keys.
--
-- Additive and idempotent: one new table, safe on upgraded installs. Nothing existing changes; vaults this node
-- created have no rows (their attestation is the original).

CREATE TABLE IF NOT EXISTS vault_key_origin
(
    vault_id               INTEGER     NOT NULL REFERENCES vault (id) ON DELETE CASCADE,
    version                INTEGER     NOT NULL CHECK (version >= 1),
    origin_node_id         TEXT        NOT NULL CHECK (length(origin_node_id) BETWEEN 1 AND 200),
    origin_vault_id        BIGINT      NOT NULL CHECK (origin_vault_id >= 1),
    origin_key_check       TEXT        NOT NULL CHECK (origin_key_check ~ '^[0-9a-f]{32}$'),
    attestation_key_id     INTEGER     NOT NULL CHECK (attestation_key_id >= 1),
    attestation_public_key BYTEA       NOT NULL CHECK (octet_length(attestation_public_key) = 32),
    attestation            BYTEA       NOT NULL CHECK (octet_length(attestation) = 64),
    anchor                 TEXT        NOT NULL CHECK (anchor IN ('kit', 'export')),
    recovered_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (vault_id, version)
);
