- Encrypted manifest: snapshot records are named by a random per-snapshot uid (`recovery_snapshot.uid`, given by the
  manifest collector at the vault's next publish and kept by `vh vault recover`) instead of the server's own snapshot
  id. Roots written before still read: their snapshot records (id only) are replaced by the same snapshots under their
  uids on the first publish after the upgrade. Older packages cannot read the new snapshot records in a restore (the
  tree and files still restore; the snapshot list is reported as unreadable).
- The server keeps a local copy of the last recorded manifest root and its sealed segments, written in the transaction
  that records the root, and a publish after a daemon restart merges on it instead of on the bucket's newest root.
- Migration 145: `recovery_snapshot.uid`, `remote_manifest_state.base_root`, `applying_epoch`,
  `applying_root_sha256`, table `remote_manifest_base`. Additive and idempotent; existing vaults get their local copy
  at their next recorded root.
