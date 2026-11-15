- Experimental, off by default (`sync.replicas.experimental`): replicated vaults. `vh vault join` (with a recovery kit,
  or `--from-cloud` through the linked account's restore relay with `intent: join`) makes this server one more writer
  of a vault another server keeps in a bucket; `vh vault leave` and `vh vault replica remove` take a server out. At
  most three writers, buckets with conditional PUT only.
- A replicated vault refuses key rotation (and every path that mints a key version), key salvage, layout migration,
  the mirror strategy and adding or revoking a recovery recipient on one replica; a second copy of a vault's uid on one
  server is refused for joins and restores alike.
- The replica set in `vh vault sync info` and `storage.vault.get` (`manifest.replicas`, `writers_change`, `behind`).
- Managed storage: a joining server gets its own bucket key; a vault the account holder removed from this server stops
  syncing; former replicas the cloud lists are dropped from the manifest's writers.
- Migration 150: `remote_manifest_state.writers_change`, `manifest_writer_root`. Additive and idempotent.
