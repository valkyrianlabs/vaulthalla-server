- Attach a remote to a local vault (design/storage/attach-remote.md, BYOS): `vault::remote` (`vault/RemoteAttach.hpp`)
  run by `vault::RemoteAttachService`, states preparing, uploading, catching_up, verifying, cutover, done, failed,
  aborted. The vault stays local until one cutover transaction (vault.type, the s3 row with the probed publish mode,
  fsync to rsync, remote index and baselines at the sent generation, manifest chain position, gateway binding
  local to remote_cache); then the engine swap, orphan cleanup and the first sync pass.
- Migration 138: `vault_remote_attach`, `vault_remote_attach_item` (everything the attach wrote, the only list an
  abort deletes from) and `vault_key_envelope.envelope` (a local vault's KEV1 envelopes, cleared at the cutover).
  Additive and idempotent.
- New `vh vault remote attach|status|abort` and ws `vault.remote.attach|status|abort` (`ops::vault_remote`): attach and
  abort need the vault's admin Edit and sync config Edit permissions, the API key's Consume permission and the
  encryption-key Rotate permission, with a `keys` step-up bound to the vault; status needs the vault's admin View
  permission. Audited (`vault.remote.attach`, `vault.remote.abort`, `vault.remote.cutover`, `vault.remote.failed`,
  `vault.remote.aborted`). `vault remote attach` is excluded from MCP.
- `storage.vault.get` adds `remote` (none, attaching:<state>, attached); system health adds `remote_attach_failed`
  (degraded) and `remote_attaches_unfinished` (informational).
- Recovery recipients are accepted on local vaults; their envelopes are stored in the database
  (`vault::envelopes::storeFor` returns a database-backed store for a local vault).
- A key rotation requested during an attach is queued and started when it ends; a key salvage is refused meanwhile.
- New config key `vaults.remote_attach.max_passes` (1 to 20, default 3), read from `config.yaml` only.
- Price estimates and budget reservations accept a provider, key and tier without a cloud engine
  (`pricing::PriceSubject`); new budget operation `remote_attach`.
