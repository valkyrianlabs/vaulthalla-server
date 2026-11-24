-- Backblaze B2 has a provider administration adapter now, so the provider part of a B2 bucket's identity is
-- 'backblaze-b2' (like 'aws-s3' and 'cloudflare-r2') instead of the generic 's3:backblaze-b2', and it follows the
-- endpoint host: a key for https://s3.<region>.backblazeb2.com reaches 'backblaze-b2' buckets whatever provider label it
-- was saved with. The account part stays what it was for these rows: the region's S3 endpoint host.
--
-- upstream_bucket rows recorded under the old identity (protection locks, managed-storage bindings) move to the new one
-- so that every lock keeps applying and every bucket keeps its record: 's3:backblaze-b2' rows are renamed. Rows under
-- another generic label ('s3:other', 's3:minio', …) whose account is a B2 S3 endpoint host are renamed too, one per
-- bucket: where several labels recorded the same bucket and none is 's3:backblaze-b2', the row bound to a vault wins,
-- then a managed or adopted record, then the oldest row. Every row that can't take the new identity (because another
-- row already has it) is left as it is, unreachable, and its lock is carried over to the row that has it (a lock is
-- never lost).
--
-- upstream_audit is append-only history and keeps the identity each entry was written with.
--
-- Idempotent: a second run finds nothing left to rename or carry over. No schema change.

UPDATE upstream_bucket b
SET provider = 'backblaze-b2', updated_at = CURRENT_TIMESTAMP
WHERE b.provider = 's3:backblaze-b2'
  AND NOT EXISTS (SELECT 1 FROM upstream_bucket n
                  WHERE n.provider = 'backblaze-b2' AND n.account_ref = b.account_ref AND n.bucket = b.bucket);

UPDATE upstream_bucket b
SET provider = 'backblaze-b2', updated_at = CURRENT_TIMESTAMP
WHERE b.id IN (SELECT DISTINCT ON (o.account_ref, o.bucket) o.id
               FROM upstream_bucket o
               WHERE o.provider LIKE 's3:%'
                 AND o.account_ref ~ '^s3\.[a-z]{2}-[a-z]+-[0-9]{3}\.backblazeb2\.com$'
                 AND NOT EXISTS (SELECT 1 FROM upstream_bucket n
                                 WHERE n.provider = 'backblaze-b2' AND n.account_ref = o.account_ref
                                   AND n.bucket = o.bucket)
               ORDER BY o.account_ref, o.bucket, (o.vault_id IS NOT NULL) DESC, (o.ownership <> 'unmanaged') DESC,
                        o.id);

UPDATE upstream_bucket n
SET is_protected = TRUE,
    protected_at = o.protected_at,
    protected_by = o.protected_by,
    protected_by_name = o.protected_by_name,
    protection_reason = o.protection_reason,
    updated_at = CURRENT_TIMESTAMP
FROM (SELECT DISTINCT ON (l.account_ref, l.bucket) l.*
      FROM upstream_bucket l
      WHERE l.is_protected
        AND l.provider LIKE 's3:%'
        AND l.account_ref ~ '^s3\.[a-z]{2}-[a-z]+-[0-9]{3}\.backblazeb2\.com$'
      ORDER BY l.account_ref, l.bucket, l.protected_at NULLS LAST, l.id) o
WHERE n.provider = 'backblaze-b2'
  AND NOT n.is_protected
  AND o.account_ref = n.account_ref
  AND o.bucket = n.bucket;
