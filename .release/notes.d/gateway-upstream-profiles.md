## S3 gateway

- **A bucket an S3 client creates can live in a provider account.** Until now a `CreateBucket` through the gateway
  always made a local vault. An *upstream profile* names a provider credential and the settings of the vault to
  create: upstream encryption on or off, the sync strategy, the conflict policy and an optional prefix for the
  upstream bucket's name. A gateway credential that uses a profile gets, for every bucket it creates, a new bucket
  in that provider account (AWS S3, Cloudflare R2 or Backblaze B2), an S3 vault over it with the profile's settings,
  and the gateway bucket bound to that vault:

  ```bash
  vh s3-gateway upstream create vl-b2 --api-key b2-main --no-encrypt --sync-strategy mirror --on-sync-conflict keep_local
  vh s3-gateway creds scope backup set --upstream vl-b2
  vh s3-gateway creds scope backup show
  ```

  In the web console: the **Upstream** tab of the S3 gateway page, and **New buckets** on a key.
  - A credential with no upstream setting keeps creating local vaults; nothing changes for existing credentials.
  - An existing bucket is never taken over. Your own bucket of that name is used only while it is empty; one that
    holds objects, or a name another account holds, fails the `CreateBucket` with `409 BucketAlreadyExists`. A
    provider failure is `503`. A refused `CreateBucket` never falls back to a local vault.
  - A client can pick a profile per request by sending its name as the region: in
    `CreateBucketConfiguration.LocationConstraint`, or as the region it signs with. `LocationConstraint=local` forces
    a local vault; real regions, which most clients send by default, select nothing. A request can only name the
    credential's own profile or one on its allowlist (`creds scope <credential> set --allow-upstream <profile>`), so
    one key can reach several provider accounts and no others; anything else is `403 AccessDenied`.
  - `s3_gateway.default_upstream_profile` sets a server default, used only by credentials set to
    `--upstream server-default`.
  - A profile's changed sync strategy or conflict policy also applies to the buckets already created from it, unless
    `s3_gateway.reapply_upstream_profile_changes` is off or the credential says otherwise (`--reapply off`).
  - Pointing a credential at a profile needs management of the credential plus `admin.upstream.provision` and
    permission to use the provider credential, for whoever makes the change and for the credential's principal; the
    principal is checked again on every `CreateBucket`.
  - A provider credential can't be deleted while a profile uses it.

  See [Upstream Profiles](/s3-gateway/buckets#upstream-profiles).
- The `remote_cache` and `remote_proxy` bucket modes are documented as what they are: whether the gateway keeps a
  local copy of an object it fetched for a read. How a vault and its upstream bucket are kept in step is the vault's
  sync strategy, whatever the mode.
