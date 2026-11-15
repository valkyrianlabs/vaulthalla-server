## Fixes

- **Restored vaults.** After `vh vault recover`, deleting files no longer fails with an I/O error (the restored files
  are counted in the filesystem's totals), empty folders the restore created can be moved, and the vault keeps its
  original creation time.
- **Modification times.** A file keeps its modification time when its content is fetched from the bucket.
