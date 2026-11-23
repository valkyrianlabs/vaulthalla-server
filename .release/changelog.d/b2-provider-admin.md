- Upstream: Backblaze B2 provider administration over B2's S3-compatible API (storage/s3/provider/admin/B2Admin):
  ListBuckets (unpaged), HeadBucket, CreateBucket (x-amz-acl: private, LocationConstraint = the endpoint's region),
  DeleteBucket, GetBucketVersioning, Get Object Lock Configuration, ListObjectsV2/ListObjectVersions, DeleteObjects.
  Lifecycle and event notifications are not in that API: AdminClient::supportsLifecycle() is false, putLifecycle and
  putVersioning(Suspended) are CapabilityMissing with nothing sent, the probe reports lifecycle, versioning and
  events.* as missing, and admin::supportsEvents() keeps event-driven sync to AWS S3 and Cloudflare R2.
  - Bucket identity for a https://s3.<region>.backblazeb2.com endpoint is (backblaze-b2, <endpoint host>, bucket)
    whatever the key's provider label; a label that contradicts the endpoint is refused on save. Migration
    153_backblaze_b2_identity.sql renames existing upstream_bucket rows ('s3:backblaze-b2', and other generic labels
    over a B2 endpoint host) and carries a lock over where both exist.
  - B2 bucket names (6-63 characters, no "b2-" prefix) are validated before any request
    (storage::upstream::validBucketNameFor); a provisioning region other than the key's own is refused.
  - Bucket creation reports a name held by another account (HeadBucket 403, or CreateBucket BucketAlreadyExists) as
    taken instead of suggesting adoption.
  - admin::supportsAdmin() is false for keys issued by managed storage (origin "cloud").
- Web console: provider administration, the bucket inventory and "Create a new bucket" for Backblaze B2 credentials;
  lifecycle, event and region fields are hidden where B2 has none.
