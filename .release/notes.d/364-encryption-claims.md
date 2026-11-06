- **Clearer wording about upstream encryption.** The console, the docs and the README now say exactly what an S3/R2
  vault with upstream encryption protects: file contents are encrypted before upload, while file and folder names are
  visible to your storage provider. The Encryption page adds a table of who can read what for local and S3/R2 vaults
  and states that a vault can't be restored from its bucket alone.
