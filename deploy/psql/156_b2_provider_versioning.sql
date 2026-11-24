-- Backblaze B2 provider versioning: Vaulthalla sets how long a B2 bucket keeps old versions.
--
-- Every B2 bucket keeps every version and that can't be switched off; a lifecycle rule (daysFromHidingToDeleting)
-- decides how long the old ones stay. Vaulthalla now writes that rule from the vault's recovery mode: off keeps
-- only the latest version (old ones are deleted a day after they are replaced), provider_versioning keeps them N
-- days or indefinitely (docs/vaults/recovery.md).
--
--   upstream_bucket.noncurrent_retention_mode   gains 'latest': Vaulthalla's rule keeps only the latest version
--                                                (B2 with the vault's mode off). Like 'indefinite' it has no days.
--   s3_gateway_upstream_profile.versioning      what a bucket created through the profile keeps: 'off' (the
--                                                default, also for NULL), 'indefinite', or '<N>d' (1..36500). Only
--                                                Backblaze B2 profiles may set anything but off (ops::s3_gateway).
--
-- Additive and idempotent: one CHECK widened (every existing row already satisfies the new one), one nullable column.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'upstream_bucket_noncurrent_retention_check') THEN
        ALTER TABLE upstream_bucket DROP CONSTRAINT upstream_bucket_noncurrent_retention_check;
    END IF;
    ALTER TABLE upstream_bucket ADD CONSTRAINT upstream_bucket_noncurrent_retention_check
        CHECK ((noncurrent_retention_mode = 'days' AND noncurrent_retention_days BETWEEN 1 AND 36500)
            OR (noncurrent_retention_mode IN ('unset', 'indefinite', 'latest') AND noncurrent_retention_days IS NULL));
END $$;

ALTER TABLE s3_gateway_upstream_profile
    ADD COLUMN IF NOT EXISTS versioning TEXT DEFAULT NULL;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 's3_gateway_upstream_profile_versioning_check') THEN
        ALTER TABLE s3_gateway_upstream_profile ADD CONSTRAINT s3_gateway_upstream_profile_versioning_check
            CHECK (versioning IS NULL OR CASE WHEN versioning ~ '^[1-9][0-9]{0,4}d$'
                                              THEN left(versioning, -1)::integer <= 36500
                                              ELSE versioning IN ('off', 'indefinite') END);
    END IF;
END $$;
