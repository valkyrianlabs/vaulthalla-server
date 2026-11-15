-- What each vault's bucket can do for writes that must never overwrite another writer's object
-- (design/encryption/06-publish-without-preconditions.md §7; storage/s3/Capability.hpp).
--
--   s3.manifest_publish  'conditional' (the bucket honours If-None-Match / If-Match) or 'version_log' (it rejects or
--                        ignores them and keeps object versions, e.g. Backblaze B2). NULL: never probed (the server
--                        keeps sending conditions, as before) or, with bucket_probe set, probed and insufficient.
--   s3.bucket_probe      the probe's result (verdict, each step's answer, when), and `changed_at` once a bucket
--                        probed as conditional refused a condition: the vault then stalls until it is probed again.
--
-- Existing rows stay NULL: each is probed on first use, never by this migration. A bucket or API key change clears
-- both (the upsert in db/preparedStatements/vault/vaults.cpp), so the new binding is probed again.
--
-- Idempotent and safe on upgraded installs: two new nullable columns and a CHECK.

ALTER TABLE s3 ADD COLUMN IF NOT EXISTS manifest_publish TEXT DEFAULT NULL;
ALTER TABLE s3 ADD COLUMN IF NOT EXISTS bucket_probe JSONB DEFAULT NULL;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 's3'::regclass AND conname = 's3_manifest_publish_check') THEN
        ALTER TABLE s3 ADD CONSTRAINT s3_manifest_publish_check
            CHECK (manifest_publish IS NULL OR (manifest_publish IN ('conditional', 'version_log')
                                                AND bucket_probe IS NOT NULL));
    END IF;
END
$$;
