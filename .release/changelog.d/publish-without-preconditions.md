- Probe each upstream bucket's write capability (design/encryption/06-publish-without-preconditions.md §7):
  conditional PUT honoured, rejected (501 / 400 NotImplemented, now `s3::PreconditionsUnsupported`) or ignored,
  object versions, GET If-Match. Stored per vault by migration 136 (`s3.manifest_publish`, `s3.bucket_probe`), probed
  at vault creation, bucket or key change, `vh vault recover`, layout migration start and lazily for older rows;
  cleared when a key's provider or endpoint changes.
- New `vh vault storage probe <vault>` and ws `vault.storage.probe` (`ops::vault_storage`; the vault's admin Edit
  permission; audited `vault.storage.probe`; agent-available).
- On buckets without conditional writes: manifest segments, the layout hint, KEV1 envelopes and the path_v0 index are
  PUT without conditions; the opaque_v1 root publish refuses before any request (`manifest_publish_unsupported`), new
  encrypting vaults and layout migrations there are refused, and health lists such vaults
  (`vaults_manifest_unpublishable`, degraded).
- A bucket stored as conditional that refuses a condition is marked changed, alerted once
  (`bucket_capability_changed`) and stalls until probed again; nothing falls back to an unconditional write.
