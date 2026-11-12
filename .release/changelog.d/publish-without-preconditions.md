- Probe each upstream bucket's write capability (design/encryption/06-publish-without-preconditions.md §7):
  conditional PUT honoured, rejected (501 / 400 NotImplemented, now `s3::PreconditionsUnsupported`) or ignored,
  object versions, GET If-Match. Stored per vault by migration 136 (`s3.manifest_publish`, `s3.bucket_probe`), probed
  at vault creation, bucket or key change, `vh vault recover`, layout migration start and lazily for older rows;
  cleared when a key's provider or endpoint changes.
- New `vh vault storage probe <vault>` and ws `vault.storage.probe` (`ops::vault_storage`; the vault's admin Edit
  permission; audited `vault.storage.probe`; agent-available).
- On buckets without conditional writes: manifest segments, the layout hint, KEV1 envelopes and the path_v0 index are
  PUT without conditions.
- `version_log` manifest publish (spec 06 §5) on buckets that keep versions (Backblaze B2): the root is PUT plainly,
  settled by one ListObjectVersions under rule C1 (the earliest successor of the base wins; a loser deletes its
  version by id and merges), versions above the head repaired, a 5xx or transport error on the root PUT treated as
  an unknown outcome (found by hash); readers follow C1 from the settled anchor, also without a probe when the root
  declares `publish: version_log`. GC deletes every version of a segment unreferenced for 24 h; a daily root janitor
  keeps the head, two predecessors and seven days. Migration 137: `remote_manifest_state.root_version_id`,
  `base_version_id`, `settle_window`, `own_epoch`, refused reasons `order_violation` / `superseded` /
  `publish_mode_mismatch`, table `remote_manifest_gc`.
- The manifest root gains `publish` and `writers` in both modes; a server excluded by a newer root stops
  (`manifest_superseded`), a head of another node in the other mode is refused (`manifest_publish_mode_mismatch`).
- Lifted the interim refusals of the capability probe: opaque_v1 vaults are created on, moved to and layout-migrated
  onto version_log buckets; only an insufficient bucket refuses (`bucket_capability_insufficient`), and health lists
  only insufficient or changed buckets (`vaults_manifest_unpublishable`).
- A bucket stored as conditional that refuses a condition is marked changed, alerted once
  (`bucket_capability_changed`) and stalls until probed again; nothing falls back to an unconditional write.
