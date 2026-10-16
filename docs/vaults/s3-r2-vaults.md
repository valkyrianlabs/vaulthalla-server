---
title: S3 And R2 Vaults
description: Create and operate upstream-backed Vaulthalla vaults using AWS S3, Cloudflare R2, or compatible provider buckets.
order: 220
status: published
tags:
  - vaults
  - s3
  - r2
  - upstream-storage
---

# S3 And R2 Vaults

S3/R2 vaults use an upstream S3/R2 bucket as Vaulthalla storage. Vaulthalla connects to the external provider bucket with an upstream provider credential, stores or indexes file bodies according to the vault sync policy, and keeps local metadata in PostgreSQL.

:::callout{theme="info" title="Upstream storage, not downstream client access"}
This page is about upstream S3/R2 storage: the external provider bucket Vaulthalla uses as a vault backend. If you want AWS CLI, rclone, MinIO mc, SDKs, or apps to talk to Vaulthalla using the S3 protocol, use [S3 Gateway](/s3-gateway) instead.
:::

:::toc[On this page]{depth="3" theme="compact"}
:::

## Upstream Versus Downstream S3

| Concept | Upstream S3/R2 Vault | Downstream S3 Gateway |
| --- | --- | --- |
| Who connects? | Vaulthalla -> provider | S3 client -> Vaulthalla |
| Credential type | `vh api-key` upstream provider credential | `vh s3-gateway creds` inbound gateway credential |
| Bucket meaning | External AWS/R2 bucket | Vaulthalla gateway bucket bound to a vault |
| Encryption | Upstream object encryption setting | Client-visible S3 protocol; Vaulthalla storage encryption still applies |
| Sync | Controls provider side effects | Gateway mutates Vaulthalla; sync owns upstream side effects |

Use an upstream S3/R2 vault when Vaulthalla should store vault data in AWS S3, Cloudflare R2, or another compatible provider. Use S3 Gateway when downstream clients should access Vaulthalla through the S3 protocol.

## Upstream Provider Credentials

:::callout{theme="info" title="Let Vaulthalla manage the bucket"}
With an AWS S3 or Cloudflare R2 credential, Vaulthalla can also create the bucket for you, adopt an existing one,
protect buckets it must never touch, and sync from provider events instead of scans. See
[Managed Upstream Buckets](/vaults/upstream-buckets) and [Event-Driven Sync](/vaults/event-sync).
:::

Create an upstream provider credential before creating the vault:

```bash
vh api-key create r2-main \
  --access <access-key> \
  --secret <secret-key> \
  --provider cloudflare-r2 \
  --endpoint https://<account-id>.r2.cloudflarestorage.com
```

AWS-style example:

```bash
vh api-key create aws-main \
  --access <access-key> \
  --secret <secret-key> \
  --provider aws \
  --endpoint https://s3.amazonaws.com \
  --region us-east-1
```

The endpoint is required. The default region is `auto`, which is suitable for Cloudflare R2 and some compatible providers.

Vaulthalla validates credentials during API key creation. Some providers return `AccessDenied` for broad bucket-list checks even when the credentials are valid for the intended bucket, so bucket-specific permissions should still be tested with a vault dry-run.

## Minimum Upstream Bucket Permissions

Grant only the upstream bucket operations your sync policy needs. Typical S3/R2 vault operation may require:

- List bucket for reconcile and some remote-index refresh paths.
- Head/Get object for remote metadata and downloads.
- Put object for uploads and manifest publishes.
- Delete object when deletes are part of the sync policy.
- Copy object for provider-side copy paths where used.

Use request budgets and dry-runs before enabling broad remote operations on large upstream buckets.

## Create An Upstream-Backed Vault

```bash
vh vault create archive \
  --s3 \
  --api-key r2-main \
  --bucket vaulthalla-archive \
  --sync-strategy cache \
  --on-sync-conflict keep_local \
  --encrypt
```

Useful options:

| Option | Purpose |
| --- | --- |
| `--api-key` | Upstream provider credential name or id. |
| `--bucket` | Upstream S3/R2 bucket name. |
| `--storage-tier` or `--storage-class` | Provider storage class such as `standard`, `standard_ia`, or `infrequent_access`. |
| `--sync-strategy` | `cache`, `sync`, or `mirror`. Without it, the vault gets `vaults.s3.default_remote_sync_strategy` from `config.yaml` (`cache`). |
| `--on-sync-conflict` | S3 conflict policy: `keep_local`, `keep_remote`, `keep_newest`, or `ask`. Without it, the vault gets `vaults.s3.default_remote_conflict_policy` (`ask`: a file changed on both sides waits for `vh sync resolve` or the console; see [Sync](/vaults/sync#resolving-conflicts)). |
| `--encrypt` | Encrypt upstream object bodies before upload. |
| `--no-encrypt` | Store upstream object bodies without Vaulthalla encryption. |
| `--interval` | Sync interval. |
| `--owner` | Create for a specific owner where permitted. |

## Upstream Encryption

New S3/R2 vaults should normally use upstream encryption. With upstream encryption enabled, object payloads written by Vaulthalla are encrypted before upload and carry Vaulthalla metadata such as encryption status, IV, key version, and content hash.

With `--no-encrypt`, object payloads written upstream are plaintext from Vaulthalla's perspective. This can be useful for interoperability, but it changes the risk model. See [Encryption](/vaults/encryption) before disabling upstream encryption.

When changing encryption behavior on an existing upstream bucket, Vaulthalla may require explicit waivers:

```bash
vh vault update archive --no-encrypt --accept-decryption-waiver
vh vault update archive --encrypt --accept-overwrite-waiver
```

Read the prompt and understand whether existing objects will remain as-is, be overwritten, or need a planned migration.

## Sync Strategies

| Strategy | Behavior |
| --- | --- |
| `cache` | Keep a local cache and index remote-only objects without downloading every body up front. Bodies are fetched as needed. |
| `sync` | Two-way synchronization between local and remote state. |
| `mirror` | Local-to-remote mirror behavior. Remote changes are not treated as authoritative local changes. |

See [Sync](/vaults/sync) before enabling a strategy on an existing upstream bucket.

## Storage Tiers

Use storage tier options to request a provider storage class for uploaded objects. Examples include AWS `standard` or `standard_ia`, and Cloudflare R2 `standard` or `infrequent_access`.

Archive-tier objects may be indexed but skipped for body download until restored by the provider. Sync dry-run output reports archive-tier download skips when they are detected.

## Vault Web Console Settings

The Vaults page exposes the same major upstream S3/R2 settings:

- Upstream provider API key and upstream bucket.
- Storage tier.
- Sync strategy and conflict policy.
- Sync interval.
- Upstream encryption.
- Request budget preset or custom limits.
- Maximum remote-index age.
- Sync enabled state.

Use the web console for interactive setup and `vh vault sync info <vault>` for a scriptable view of the resulting policy.

## Expose This Vault Through S3 Gateway

To let downstream S3 clients access an S3/R2 vault through Vaulthalla, bind the vault as a remote-backed gateway bucket:

```bash
vh s3-gateway bucket bind archive --vault archive --mode remote_cache
```

See [S3 Gateway Buckets](/s3-gateway/buckets) for local and remote-backed gateway bucket setup.
