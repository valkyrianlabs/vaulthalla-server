- Vault read grants (migration 155_vault_read_grants.sql: read_grant_recipient, vault_read_grant,
  vault_read_grant_recipient, permission vault.sync.action.read_grants = sync action bit 3, bit 11 of
  sync_permissions, granted to no role). ops::read_grants issues, for one vault, a read-only S3 gateway credential
  (vault-allowlist, built-in reader role, principal = the issuer) and a read-only upstream key restricted to the
  vault's bucket, and returns both in one JSON document only as an OpenPGP message encrypted to one or two pinned
  recipients. Nothing secret is stored, logged or audited; a failed upstream key or encryption rolls the gateway
  credential back; revoke deletes both and stays revocation_incomplete (retryable) while the provider refuses.
  - Backblaze B2 read keys (B2Admin::createReadKey / deleteReadKey): native b2_authorize_account (v4),
    b2_list_buckets, b2_create_key with capabilities listBuckets, listFiles, readFiles and bucketIds = [the bucket],
    b2_delete_key. The account key needs writeKeys. AWS S3 and Cloudflare R2: not supported yet
    (AdminClient::supportsReadKeys).
  - Recipients are OpenPGP public keys pinned by full fingerprint (file/stdin through vh, or a keyserver by
    fingerprint; the key must hash to it); super admins only, step-up family secrets, agents refused. Revoked,
    expired and sign-only keys are refused.
  - OpenPGP through the system gpg (crypto/openpgp/Gpg): throwaway --homedir, --no-options --no-autostart --batch,
    recipients by --recipient-file, plaintext over a socket on stdin. New runtime dependency: Debian Depends gpg;
    macOS cask depends_on formula gnupg; Brewfile gnupg for the tests.
  - Config vaults.read_grants.{max_per_vault (1..32, default 4), gateway_endpoint} (config.yaml only).
  - CLI: `vh vault read-grant issue|list|show|revoke` and `vh vault read-grant recipient list|add|remove`; recipient
    add/remove are MCP exclusions. `ops::api_keys::remove` refuses a key with grants that are not revoked.
