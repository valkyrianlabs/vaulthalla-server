- Test tooling: the Tier B harness's console lane replaces an existing file with `PUT /upload/content` and
  `If-Match`, as a client should, instead of sending it to the create-only upload session; a 412 is a concurrent-write
  conflict. Nothing in the daemon changed (#404).
