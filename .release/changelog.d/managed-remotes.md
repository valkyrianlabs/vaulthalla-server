- Groundwork for managed storage on a linked server, which isn't offered yet (design/cloud/managed-remotes.md, "As
  built"). Migration 142 adds `api_keys.origin` and `.cloud_access`, `vault_cloud_storage`, `cloud_storage_account`,
  `admin_role.cloud_permissions` (the admin module `cloud`: view, storage, billing; built-in roles that see stats get
  view, super_admin everything) and an in-place mode for `vault_remote_detach` (`mode`, `lost`, item state `lost`).
  Every existing key stays `customer`, every existing detach `hydrate`.
- `CloudStorageService` replaces `CloudKeyService` (it still runs the account recovery key check, daily while
  linked). It contacts nobody unless the server is linked and a super admin confirmed the account recovery key.
  `vh cloud storage status|enable|disable|accept|decline|rotate|new-vaults|billing` and ws `cloud.storage.*`
  (capability `cloud.storage.managed_remotes`); everything but `status` is excluded from `vh mcp`.
- A bucket key managed storage issued is read-only to people: `vh api-key update|remove` refuse it (Conflict), and
  the `APIKey` model gains `origin` and `editable`. `Vault` and `AccessibleVault` gain `vault_uid`.
- `vh vault remote attach|detach|abort|access` refuse a vault in managed storage (`managed_storage`); revoking its
  account-key recovery grant by hand is refused (`managed_vault_account_key`); `vh cloud unlink` refuses while vaults
  are in managed storage unless `--force` (`managed_vaults`). `vh cloud recovery status --verify` compares the
  cloud's account-key envelopes with this server's records. New health entries under `cloud_storage`.
- `cloud.storage.poll_minutes` and `cloud.storage.default_retention_days` in config.yaml (defaults 15 and 30).
