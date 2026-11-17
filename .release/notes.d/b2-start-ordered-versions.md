## Cloud storage

- **Backblaze B2: a late manifest upload no longer stops sync.** Backblaze orders the versions of an object by when
  their upload started, not when it finished. A manifest upload whose answer was lost and that Backblaze completed
  late used to stop the vault's sync with `order_violation`; the server now recognises it as its own earlier attempt
  and removes it. If you restore a vault on Backblaze to another server, stop the old server first: one server
  writes a vault on such a bucket.
- **Uploads that hang no longer hold a sync pass.** Small uploads (the encrypted manifest, envelopes, files sent in
  one request) give up after 30 s without a connection or 60 s without progress, and the manifest's root after 60 s
  in all.
