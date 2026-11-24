- Sync: passes run on their own pool (ThreadPoolManager::syncPassPool, sync.max_concurrent_passes, default 4) and
  their operations on the sync pool (sync.worker_threads, default one per CPU core, 4..64; 12 on 12 cores, was 6
  shared with the passes). Six passes due together held every worker of the shared pool while waiting on operations
  queued behind them, and upstream sync hung for good (every release up to 1.25.0).
- Sync: every regular pass is rescheduled however it ends (Local::finishRun, a scope guard in Local and Cloud):
  SUCCESS and STALLED after the interval, ERROR with backoff (interval x 2^(n-1), at most max(interval, 1 h)), reset by
  a success; scoped, interrupted and replaced tasks are not. Exceptions from startTask and the event save are logged
  and no longer leave runningFlag set. A stage that fails ends the pass; key-rotation exceptions are recorded as
  errors.
- Sync: after a pass with failed operations, the uploads and remote deletes that succeeded are recorded in the remote
  index and manifest (Cloud::completedActions).
- Sync events: sync_event.upsert and sync_throughput.upsert/accumulate cast their counter parameters to bigint (a pass
  over 2 GiB failed with "out of range for type integer"); Engine::newSyncEvent no longer fails a pass when the
  previous event cannot be saved.
- Database: database.pool_size is honoured (Transactions::initFromConfig, clamped to 4..256 with a warning; default 24,
  was ignored in favour of 4), with a startup warning below sync.worker_threads + sync.max_concurrent_passes. Row
  mappers read parent chains in the caller's transaction (files/directories/symlinks_from_pq_res(res, txn)), so a
  listing holds one pooled connection instead of waiting for a second.
- vh vault sync info prints the stored last sync and last success times; the engine's copy of the policy is updated
  when a pass starts and succeeds.
