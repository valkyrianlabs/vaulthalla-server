## Cloud storage

- **Buckets without conditional writes, such as Backblaze B2.** Some writes must never overwrite another writer's
  object, and Vaulthalla sends them with `If-None-Match` / `If-Match`. Backblaze B2 refuses those headers
  (`501 NotImplemented`), so until now every sync pass of a vault on B2 that changed anything ended in an error, and
  enrolling a recovery recipient there failed. Vaulthalla now probes each bucket once, when a vault is created on it or
  moved to it (existing vaults the first time they need it after the upgrade), and records what it supports.
  `vh vault storage probe <vault>` probes it again and shows the result; the probe writes a few bytes under
  `.vaulthalla/probe/` and deletes them.
  - On such a bucket, vaults without upstream encryption and encrypting vaults from before release 1.22 sync again,
    and recovery recipients can be enrolled.
  - Vaults with opaque storage (every encrypting vault created since 1.22) can't publish their encrypted manifest
    on such a bucket yet. Creating one there is refused (`conditional_writes_unsupported`); an existing one keeps
    uploading files, but its sync stops with `manifest_publish_unsupported` and `vh status` shows it as degraded.
    Moving a vault to opaque storage on such a bucket is refused too.
  - AWS S3 and Cloudflare R2 support conditional writes: nothing changes for them beyond the one probe.
  - A bucket probed as supporting conditional writes that later refuses one is never written without the condition:
    its vault's sync stops with `bucket_capability_changed`, operators are notified once, and it resumes after
    `vh vault storage probe`.
