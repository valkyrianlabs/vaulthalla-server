- Encrypted manifest (opaque_v1 vaults): another server's key checks are verified over that server's vault id (a key
  check is bound to the vault id it was computed for), so a root another server published is no longer refused as a
  key mismatch.
- With another server named in the vault's root and a bucket that keeps no versions, a content change on both sides is
  never decided by the conflict policy: it stays an open conflict with both generations kept (the local copy and the
  bucket's object) until it is resolved.
- The manifest entry of a file describes the object it names (size and content hash from the remote index), never a
  local edit that is not uploaded yet.
- A pass no longer republishes another server's root that already says what this server holds (two writers no
  longer alternate roots on every pass).
- A file's modification time survives what used to restamp it: an applied root, a sync download, the fs_entry trigger
  (migration 149) and the apply's cache refresh. An mtime one writer changed (a rename, a chmod there) reaches the
  other.
- A provider version another writer knows became noncurrent is recorded as such.
- `vh vault recover` keeps the vault's creation time and counts the restored files in the filesystem root's totals (a
  restored node's first deletes no longer fail with EIO).
- An empty folder a restore created (no backing directory yet) can be moved through FUSE.
- An attribute change applies to a file without a group.
- Objects of such a vault's trash that this server purged locally are deleted from the bucket after 7 days, and only
  while no recorded, deferred or pending root names them.
- Migrations 148 (`manifest_shared_purge`, additive) and 149 (the fs_entry `updated_at` trigger keeps an explicit
  time). Both idempotent.
