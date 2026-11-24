- Backblaze B2 provider versioning (migration 156_b2_provider_versioning.sql: upstream_bucket.noncurrent_retention_mode
  gains 'latest'; s3_gateway_upstream_profile.versioning, NULL = off). B2Admin reads and writes lifecycle rules
  through B2's native API (b2_list_buckets with bucketTypes ["all"], b2_update_bucket with ifRevisionIs = the
  revision read, so a concurrent change is a 409 and nothing is written); Vaulthalla's own rules are recorded in the
  bucket's bucketInfo["vaulthalla-lifecycle"] and recognized only when a rule equals a recorded one; every other rule
  and bucketInfo entry is written back as read. The application key needs writeBuckets to set a rule.
  - Recovery capability contract per provider (recovery/provider/Capabilities.hpp, `capabilities` in
    vault.recovery.status): AWS S3 as before; B2 always versioned, retention N days / indefinite, history off, no
    enable, no suspend, restore by transfer only (CopyObject from a version id isn't documented by Backblaze);
    Cloudflare R2 nothing.
  - B2 rules are scoped by layout: opaque_v1 → prefix "o/" and never a rule under .vaulthalla/ (the version_log
    manifest keeps its older roots there); transparent and path_v0 → the whole bucket plus
    vaulthalla-manifest-versions.
  - A bucket Vaulthalla creates on B2 keeps only the latest version (owned rule daysFromHidingToDeleting 1, recorded
    'latest'); an S3 gateway upstream profile may set `versioning` off | <N>d | indefinite for the buckets it creates
    (B2 only; AWS S3 and R2 profiles accept only off). Mode off / local_snapshots on B2 rewrites the rule to the latest
    version, with recovery_retention_shorten when that deletes history; adopted buckets need the same acceptance,
    unmanaged ones accept_adoption, protected ones are never touched.
  - Provider versioning on B2: no PutBucketVersioning, no propagation window. `vault.recovery.suspend` on B2 is
    invalid. `keepsHistory()` (backlog replays) is false for a 'latest' bucket.
  - `vault.recovery.update` carries step-up family data.destroy when the provider would delete history sooner (AWS
    and B2): agents can no longer shorten provider retention.
  - `ops::upstream::detach` removes Vaulthalla's B2 rules too. `vh upstream lifecycle` stays refused on B2.
