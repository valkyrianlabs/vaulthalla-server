-- The per-vault remote access gate (design/cloud/managed-remotes.md, "Entitlement states and the access gate"): what
-- an S3 vault may still do with its bucket. full (everything), read_only (reads and hydrates; no PUT, COPY, DELETE or
-- manifest publish: local writes are kept and go up once access is full again) or none (no request to the bucket at
-- all; local copies keep working). No row means full, which is every vault on an upgraded install.
--
-- Set by an internal setter: the managed-storage service as its entitlement changes, or an operator through
-- `vh vault remote access`. The daemon holds the value in memory, so the checks on FUSE and request paths never read
-- this table. A detach deletes the row with the vault's S3 binding.
--
-- Additive and idempotent: one new table, safe on upgraded installs. No existing row changes.

CREATE TABLE IF NOT EXISTS vault_remote_access
(
    vault_id INTEGER     PRIMARY KEY REFERENCES vault (id) ON DELETE CASCADE,
    access   TEXT        NOT NULL CHECK (access IN ('full', 'read_only', 'none')),
    reason   TEXT        DEFAULT NULL CHECK (reason IS NULL OR length(reason) <= 500),
    set_by   TEXT        NOT NULL CHECK (set_by <> ''),
    set_at   TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
