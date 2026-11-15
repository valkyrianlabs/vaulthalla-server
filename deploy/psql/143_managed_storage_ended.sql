-- Managed storage's end of plan waits for a person or for time (design/cloud/managed-remotes.md, "As built"): a single
-- report from the account's service that the plan `ended` must not convert every managed vault to local at once.
-- Until an admin confirms it, or the service has reported `ended` continuously for cloud.storage.ended_grace_hours
-- (default 24), managed vaults stay attached with remote access none.
--
--   cloud_storage_account.ended_seen_at        when the service's state first read `ended` in the current run of
--                                              `ended` answers (cleared by any other state)
--   cloud_storage_account.ended_confirmed_at, .ended_confirmed_by
--                                              an admin's confirmation of that run (`vh cloud storage confirm-ended`),
--                                              cleared with it
--
-- Additive and idempotent: three nullable columns on a table only linked servers have rows in.

ALTER TABLE cloud_storage_account ADD COLUMN IF NOT EXISTS ended_seen_at TIMESTAMPTZ DEFAULT NULL;
ALTER TABLE cloud_storage_account ADD COLUMN IF NOT EXISTS ended_confirmed_at TIMESTAMPTZ DEFAULT NULL;
ALTER TABLE cloud_storage_account ADD COLUMN IF NOT EXISTS ended_confirmed_by TEXT DEFAULT NULL
    CHECK (ended_confirmed_by IS NULL OR ended_confirmed_by <> '');
