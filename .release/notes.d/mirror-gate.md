## Linked servers (experimental, off by default)

- **A mirror is read-only.** A vault a server holds as another server's copy (a mirror, or an orphaned copy whose
  core ended the mirror) can no longer be changed on that server, by anyone, through any way in: the mount answers
  "Read-only file system", the console and `vh` refuse with `read_only` and the reason (the link to the core is down,
  the first copy is still arriving, the copy stopped following its core, it is an orphaned copy, or changes are made
  on the core), uploads and text saves answer 503 with `Retry-After`, `vh fs put` exits with code 69, share uploads
  and the S3 gateway (503 `ServiceUnavailable`, super admins included) refuse, and so do restores, the vault's
  settings and attaching a remote. Changes made on the core keep arriving, and the mirror's super admins keep reading
  within what the core grants. Background work (format conversion, local versioning and its retention, key rotation,
  the trash purge) leaves a copy alone. Taking changes on a mirror comes in a later release.
- **`chmod`, `chown` and `touch` through the mount are recorded.** They used to change only the file on disk and were
  lost on the next refresh; they are now stored with the file, a mode change never moves its modification time, and a
  change of owner or group needs a super admin.
- **`vh fs put` no longer reports a file as stored when someone else created it first**; it says the path was created
  meanwhile. A missing file is now reported as missing (`not_found`) to someone who may see the folder it would be in,
  and as a permission refusal to anyone else.
