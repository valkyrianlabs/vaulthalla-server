- Detach a remote from a vault (design/storage/attach-remote.md, "The reverse"): `vault::remote::detach`
  (`vault/RemoteDetach.hpp`) run by `vault::RemoteAttachService`, states preparing, hydrating, verifying, cutover,
  done, failed, aborted. Remote-only files are fetched through `CloudEngine::hydrate`, every live file's local copy is
  authenticated end to end, and every `vault_key_envelope` row gets its bytes from the bucket (checked with
  `kev1::inspect` against the vault, key version and grant) before one cutover transaction under the vault's pass
  lease: vault.type local, the s3 row, remote index, sync baselines and manifest rows deleted, rsync to fsync,
  gateway binding to local, the `upstream_bucket` row unbound, pending upstream backlog skipped, provider_versioning
  to local_snapshots, the attach row deleted; then the engine swap under the same lease. The bucket is never written
  to or deleted from. The cutover refuses while a live file lacks a verified item at its current generation or an
  envelope row has no bytes.
- Migration 139: `vault_remote_detach`, `vault_remote_detach_item`. Additive and idempotent.
- New `vh vault remote detach` and ws `vault.remote.detach` (same permissions as attach without the API key's, `keys`
  step-up bound to the vault, excluded from MCP); `vh vault remote abort` / `vault.remote.abort` also abort a detach
  before its cutover; `vault.remote.status` adds `detach` (model `VaultRemoteDetach`) and the progress phase
  `hydrating`. Audited (`vault.remote.detach`, `vault.remote.detach.cutover`, `vault.remote.detach.failed`,
  `vault.remote.detach.aborted`).
- `storage.vault.get` `remote` adds `detaching:<state>`; system health adds `remote_detach_failed` (degraded) and
  `remote_detaches_unfinished` (informational).
- Web console: Vault → Settings → Remote storage (`RemoteStoragePanel`, lazy) for attach, status, abort, resume and
  detach.
