-- When the operator last took a `vh secret export all` (#351, design/sealing/master-secrets.md §5).
--
-- Binding sealed secrets to TPM PCR 7 makes a firmware or Secure Boot change lock them until they are restored from
-- the exports, so `vh secret reseal --pcr7` refuses without a recent export (24 hours), and health warns when a
-- PCR-bound host has none newer than 30 days. The exports themselves are never stored here: this records only that
-- one was taken, when, by whom and which secrets it held.
--
-- Additive and idempotent: one new table, nothing existing changes.

CREATE TABLE IF NOT EXISTS secret_exports
(
    id          BIGSERIAL PRIMARY KEY,
    exported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_id    INTEGER              DEFAULT NULL,
    actor_name  TEXT        NOT NULL DEFAULT '',
    secrets     TEXT[]      NOT NULL CHECK (cardinality(secrets) >= 1)
);

CREATE INDEX IF NOT EXISTS idx_secret_exports_exported_at ON secret_exports (exported_at DESC);
