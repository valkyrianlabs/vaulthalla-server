## Sync

- **Upstream sync no longer hangs when several vaults are due at once.** In every release up to and including
  1.25.0, a sync pass and the uploads, downloads and deletes it waits for ran on one pool of threads (6 on a 12-core
  host). When about six passes were due together, which happens on every service start with enough S3 vaults, each
  thread held a pass waiting for operations that could never start, and sync stopped for good until a restart (which
  hung again). Stopping the service then logged `Future failed: std::future_error: Broken promise` and
  `N async sync operation(s) failed`. Passes now run on threads of their own (`sync.max_concurrent_passes`, default
  4), and their operations on `sync.worker_threads` threads, one per CPU core by default (12 on a 12-core host).
- **A failed, stalled or interrupted pass no longer stops a vault from syncing.** Only a successful pass used to
  schedule the next one; after an error, a request-budget stall or an exception (some left the vault answering "already
  running" to every trigger), the vault never synced again until a manual sync or a restart. Now a stalled pass runs
  again after the vault's interval, and a failed one after the interval, doubling with each further failure up to an
  hour (or the interval, if longer); a success resets it. A failing step ends the pass instead of running the next
  steps on top of it.
- **One failed upload no longer throws away the others.** The uploads and remote deletes that succeeded are recorded
  even when another operation of the pass failed, so the next pass retries only the failures instead of uploading
  everything again.
- **A vault with more to upload than its request budget allows now catches up.** A pass stopped by its S3 request
  budget (for example 1,000 PUTs with 1,984 files waiting) used to record none of the uploads it had made, so every
  pass started over with the same files, adding a new version of each on a versioned bucket. Each pass now keeps what
  it uploaded and the next one continues with the rest. Operations the budget refused are reported once, as a stall
  with the budget's reason, instead of one error per file.
- **Mirrored vaults stop uploading everything again on every pass.** A vault with strategy `mirror` and conflict
  policy `keep_local` in the transparent or encrypted path layout (such as the buckets the S3 gateway creates
  through an upstream profile with those settings) planned an upload of every file on every pass, even when the bucket already held
  exactly that content: a few GB every interval, and a new version of every object on buckets that keep versions.
  `keep_remote` mirrors downloaded every file the same way. Vaults in the encrypted opaque layout were not affected.
  A file is now transferred only when it is new or its content changed. Nothing to do after upgrading: the first
  pass recognises what the bucket already holds from what the server recorded when it uploaded it, uploads nothing
  that is already there, and no reconciliation or extra requests are needed. On buckets that keep versions, the
  extra versions earlier passes created stay until the bucket's lifecycle rules remove them.
- **Large passes are recorded.** A pass that moved more than 2 GiB failed to save its statistics (`value "…" is out
  of range for type integer`), and its vault then refused every later pass until a restart.
- **`database.pool_size` is used.** It was read and ignored: every install ran with 4 database connections, and
  concurrent sync passes timed out waiting for one (`Timed out after 30000ms waiting for a database connection (all 4
  pool connections in use)`), partly because a directory listing held one connection while it waited for a second.
  Listings use one connection now, the configured size is honoured (kept within 4 to 256, with a warning otherwise),
  and the default for new installs is 24. The server warns at startup when the pool is smaller than
  `sync.worker_threads` + `sync.max_concurrent_passes`.
- **`vh vault sync info` shows the real last sync and last success times** instead of 1970-01-01.

After upgrading: an existing `config.yaml` keeps its `database.pool_size` (10 on most installs). With the new sync
defaults on a 12-core host the server then warns that 10 is below 16; raise it to 24 (PostgreSQL's `max_connections`
permitting) and restart. `sync.worker_threads` and `sync.max_concurrent_passes` are optional and are read at startup.
