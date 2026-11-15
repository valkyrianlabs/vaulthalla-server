- The per-vault remote access gate (design/cloud/managed-remotes.md, "Entitlement states and the access gate";
  `storage/RemoteAccess.hpp`): `full`, `read_only` or `none`, held in memory (read when a CloudEngine is built, set by
  `storage::remote_access::set`), so no check touches the database. Enforced by skipping the sync pass
  (`sync::Cloud`, stalled with `skipped: remote read-only|unavailable`), in `CloudEngine` upload, purge/delete,
  manifest publish, recovery envelopes and hydrate (a remote-only file fails `remote_unavailable` before any request),
  and as the last line in `s3::Controller::recordRequest` for every controller tagged with the vault (PUT/COPY/DELETE
  need full, LIST/HEAD/GET anything but none). Back to full starts the skipped pass. Key rotation from `vh vault keys
  rotate` waits while restricted.
- Migration 140: `vault_remote_access` (no row = full). Additive and idempotent. A detach deletes the row.
- New `vh vault remote access <vault> --set <mode> [--reason]` (`ops::vault_remote::setAccess`: the detach's
  permissions, no step-up; MCP-excluded); audited `vault.remote.access` (from, to, cause). `vault.remote.status` adds
  `access` (model `VaultRemoteAccess`); system health adds `vault_remote_restricted` and `vault_remote_unavailable`
  (degraded). The console's remote storage panel shows a restricted vault's access.
