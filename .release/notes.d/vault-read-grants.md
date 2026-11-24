## Vaults

- **Vault read grants for backup orchestrators.** `vh vault read-grant issue <vault> --recipient <fingerprint>` creates
  a read-only S3 gateway credential for one vault and, for a Backblaze B2 vault whose objects are stored readable, a
  read-only B2 application key restricted to its bucket (`listBuckets`, `listFiles`, `readFiles`). Both come back in
  one document, only as an OpenPGP message encrypted to a public key a super admin pinned by its fingerprint, so a
  recovery tool can read the vault through the gateway, or straight from the bucket if this server is lost, without
  any person, agent or log seeing the secrets:

  ```bash
  vh vault read-grant recipient add --fingerprint A6A1752984DFB0DB38DD235D2096C49D7A8F000A \
    --keyserver https://keys.valkyrianlabs.com --label Sentinel
  vh vault read-grant issue finance --recipient A6A1752984DFB0DB38DD235D2096C49D7A8F000A --json
  vh vault read-grant list --vault finance
  vh vault read-grant revoke <grant>
  ```

  Issuing needs the new vault permission `vault.sync.action.read_grants` (no built-in role has it; add it to a vault
  role) and no step-up. A local vault, or one that encrypts its objects upstream, gets a gateway-only grant with
  `--gateway-only`. At most `vaults.read_grants.max_per_vault` (default 4) grants per vault; `revoke` deletes both
  credentials and retries until the provider has deleted its key. AWS S3 and Cloudflare R2 upstream keys are not
  supported yet. Set `vaults.read_grants.gateway_endpoint` to the gateway's public HTTPS URL. The package now depends
  on `gpg` (macOS: Homebrew `gnupg`). See [Vault Read Grants](/vaults/read-grants).
