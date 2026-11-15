## Cloud storage

- **Limit what an S3/R2 vault may do with its bucket.** `vh vault remote access <vault> --set read-only|none|full`
  [--reason <text>]:
  - `read-only`: files are read and fetched from the bucket as before, but nothing is uploaded, deleted or published
    there. Sync passes are skipped (`skipped: remote read-only` in the sync history), changes made on the server are
    kept and go up with the first pass once access is full again, and key rotations wait.
  - `none`: no request goes to the bucket at all. Files with a local copy keep working; files without one fail as
    unavailable.
  - `vh vault remote status` shows the access, why and who set it; `vh status` and the health page report a
    read-only or unavailable remote as degraded. The setting survives restarts and is removed when the vault is
    detached. Agents can't change it.
