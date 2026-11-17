## Cloud storage

- **Backblaze B2: one server per vault.** Backblaze orders the versions of an object by when their upload started,
  not when it finished. For a vault that one server writes this is now handled: a manifest upload whose answer was
  lost and that Backblaze completed late used to stop the vault's sync with `order_violation`; the server now
  recognises it as its own earlier attempt and removes it. Two servers writing one vault on such a bucket can't be
  made safe the same way, so `vh vault join` refuses a vault whose bucket publishes without conditional writes
  (`join_version_log`), with the kit or `--from-cloud`. Replicated vaults need a bucket with conditional writes
  (AWS S3, Cloudflare R2). If you restore a vault on Backblaze to another server, stop the old server first.
- **Uploads that hang no longer hold a sync pass.** Small uploads (the encrypted manifest, envelopes, files sent in
  one request) give up after 30 s without a connection or 60 s without progress, and the manifest's root after 60 s
  in all.
