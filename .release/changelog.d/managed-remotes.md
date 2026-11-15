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
- Managed storage follow-ups (migration 143 adds `cloud_storage_account.ended_seen_at`, `.ended_confirmed_at`,
  `.ended_confirmed_by`): an ended plan converts vaults only after `vh cloud storage confirm-ended` (ws
  `cloud.storage.ended.confirm`) or `cloud.storage.ended_grace_hours` (default 24) of continuous `ended`; an attach
  to a bucket that holds the vault's own earlier copy is refused `bucket_holds_this_vault` instead of
  `bucket_not_empty`; manifest roots carry the account's signed recovery policy (`recovery_policy.account_policy`),
  which a restore verifies and accepts when newer; root grants carry `account_key_generation`.
- Console: a managed storage page and a new-vault switch, both hidden unless the server reports the capability and
  storage is available. Route budgets for `/account`, `/users/[name]` (242 KB) and `/files` (232 KB) were raised: the
  generated ws contract the client ships grew with the managed-storage commands.
