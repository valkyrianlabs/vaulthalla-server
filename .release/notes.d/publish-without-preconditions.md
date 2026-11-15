## Cloud storage

- **Backblaze B2 and other buckets without conditional writes.** Some writes must never overwrite another writer's
  object, and Vaulthalla sends them with `If-None-Match` / `If-Match`. Backblaze B2 refuses those headers
  (`501 NotImplemented`), so until now every sync pass of a vault on B2 that changed anything ended in an error,
  enrolling a recovery recipient there failed, and encrypting vaults with opaque storage couldn't keep their encrypted
  manifest (file names and folders) on B2 at all. Vaulthalla now probes each bucket once, when a vault is created on
  it or moved to it (existing vaults the first time they need it after the upgrade), and records what it supports.
  `vh vault storage probe <vault>` probes it again and shows the result; the probe writes a few bytes under
  `.vaulthalla/probe/` and deletes them.
  - On a bucket that keeps object versions (B2 keeps every version by default) every kind of vault works: without
    upstream encryption, encrypting from before release 1.22, and encrypting with opaque storage. An opaque vault's
    encrypted manifest root is written as a new version of `.vaulthalla/root`, and the server lists the root's versions
    once per publish to confirm that its version is the one that counts. That is one listing request more per publish
    than on AWS S3 or Cloudflare R2; a pass that changes nothing still costs one HEAD. Restarts, `vh vault recover`,
    recovery recipients, key rotation and `vh vault migrate-layout` work there.
  - Keep every version under `.vaulthalla/` on such a bucket: Vaulthalla removes the root and segment versions it no
    longer needs itself. A lifecycle rule that deletes old versions there can make the vault refuse its manifest.
  - A bucket with neither conditional writes nor versions can't hold an opaque vault's manifest: creating or moving
    an encrypting vault there is refused (`bucket_capability_insufficient`); an existing one keeps uploading files, its
    sync stops with `manifest_publish_unsupported`, and `vh status` shows it as degraded.
  - AWS S3 and Cloudflare R2 support conditional writes: nothing changes for them beyond the one probe.
  - A bucket probed as supporting conditional writes that later refuses one is never written without the condition:
    its vault's sync stops with `bucket_capability_changed`, operators are notified once, and it resumes after
    `vh vault storage probe`.
- **Who may publish a vault's manifest.** The encrypted manifest's root now names the servers that may publish it.
  After `vh vault recover` on another server, the restored server takes the vault over; if the old server still runs,
  it stops publishing that vault's manifest and alerts its operators (`manifest_superseded`) instead of merging its
  older view into the restored vault. Two more alerts protect manifests on buckets without conditional writes:
  `manifest_order_violation` (the provider reordered the root's versions after the fact) and
  `manifest_publish_mode_mismatch` (another server published the root in the other mode). Each stops the vault's
  manifest publishing until an operator looks.
