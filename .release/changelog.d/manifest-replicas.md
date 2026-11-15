- Encrypted manifest (opaque_v1 vaults): the last apply of another server's root is recorded (epoch, producing node,
  counts, conflicts) and shown by `vh vault sync info` and `storage.vault.get` (`manifest`). An apply that has to stop
  (a key version this server doesn't hold or holds with another key check, a root that didn't load completely, a
  shared root on a vault syncing with the mirror strategy) alerts the operator once per root (`manifest_apply_stopped`).
- Roots this server writes keep other servers' recovery envelope references for the recipients this vault's grants
  have, and a root another server built on one of this server's unrecorded roots is applied on that root.
- With another server named in the vault's root, a trashed file is purged locally without deleting its object from the
  bucket.
- Migration 147: `manifest_foreign_envelope`, `remote_manifest_pending`, `remote_manifest_state.writers`,
  `manifest_apply_report`. Additive and idempotent.
