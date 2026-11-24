---
title: S3 Gateway Buckets
description: Create and bind local and remote-backed gateway buckets that expose Vaulthalla vaults through the S3 protocol.
order: 40
status: published
tags:
  - s3-gateway
  - buckets
  - vaults
  - storage
---

# S3 Gateway Buckets

A gateway bucket is a downstream S3 bucket name exposed by Vaulthalla and bound to a Vaulthalla vault. It is the name downstream S3 clients use in commands such as `s3://archive/path/file.txt`.

Bucket bindings are routing topology, not access policy. A binding maps `downstream bucket name -> Vaulthalla vault`. It does not grant any gateway credential access to that vault. Gateway credentials still need `user_access` principal permissions or role-based credential policy.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Bucket Modes

| Mode | Vault backing | Behavior |
| --- | --- | --- |
| `local` | Local Vaulthalla vault | Encrypted local object store exposed through S3. |
| `remote_cache` | Vaulthalla S3/R2 vault | Serves the vault through S3 and keeps a local copy of every object a read had to fetch from the upstream bucket. |
| `remote_proxy` | Vaulthalla S3/R2 vault | Serves the vault through S3 without keeping a local copy of objects fetched for a read. |

Local vaults must be bound as `local`. S3/R2 vaults must be bound as `remote_cache` or `remote_proxy`.

The mode only decides what the gateway does with an object it had to fetch. How the vault and its upstream bucket are kept in step is the vault's own [sync strategy](/vaults/sync) (`cache`, `sync` or `mirror`) and conflict policy, whatever the mode: a `mirror` vault bound as `remote_cache` still mirrors. A write through the gateway lands in the vault first and reaches the upstream bucket on the vault's next sync pass.

## Local Gateway Buckets

Create a new encrypted local vault and bind it as a gateway bucket:

```bash
vh s3-gateway bucket create-local archive --quota 500G
```

Creating a local gateway bucket creates a normal Vaulthalla local vault. The actor must have normal vault-create permission for the target owner. Creating a bucket for another owner follows the same target-user vault-create rules as ordinary vault creation and does not bypass Vaulthalla RBAC.

Bind an existing local vault:

```bash
vh s3-gateway bucket bind photos --vault 12 --mode local
vh s3-gateway bucket list
```

Local gateway buckets support standard object operations such as PUT, GET, HEAD, LIST, COPY, multipart upload, and DELETE while Vaulthalla stores encrypted local content.

## Remote-Backed Gateway Buckets

A remote-backed gateway bucket is a downstream S3 bucket backed by a Vaulthalla S3/R2 vault. Downstream clients talk to Vaulthalla; Vaulthalla uses its upstream provider credential and upstream S3/R2 bucket behind that vault.

Bind an existing S3/R2 vault:

```bash
vh s3-gateway bucket bind archive-edge --vault archive --mode remote_cache
vh s3-gateway bucket bind archive-proxy --vault archive --mode remote_proxy
```

Binding an existing vault requires S3 Gateway bucket-management authority plus authority to manage the vault. Binding does not grant object access to gateway credentials; each credential still needs `user_access` principal permissions or a role-based credential policy with a default role and, for `vault_allowlist`, a selected vault row.

Create a new remote-cache gateway bucket and its backing S3/R2 vault:

```bash
vh s3-gateway bucket create-remote-cache edge \
  --api-key r2-main \
  --upstream-bucket origin \
  --encrypt
```

`--api-key` names the upstream provider credential created with `vh api-key`. `--upstream-bucket` names the external AWS S3, Cloudflare R2, or compatible bucket used as the vault backend.

Creating a remote-cache bucket also creates a normal S3/R2 vault, so it requires vault-create permission for the owner and permission to use the upstream provider credential. That vault uses the `cache` sync strategy with `keep_local`, over an upstream bucket that already exists. To have Vaulthalla create the upstream bucket, or to use another strategy, use an [upstream profile](#upstream-profiles).

## Buckets Created By S3 Clients

An S3 client can create a bucket itself with a plain `CreateBucket` (`aws s3 mb`, `boto3.create_bucket`, `rclone mkdir`). The credential's principal must be an admin with `admin.s3_gateway.manage_buckets` and the right to create vaults; a `vault_allowlist` credential can't create buckets.

What the new bucket is depends on the credential:

| The credential's setting | `CreateBucket` creates |
| --- | --- |
| Nothing (the default) | A local vault, bound in `local` mode. |
| An upstream profile | An S3 vault over a new bucket in the profile's provider account, bound in `remote_cache` mode. |
| The server default | The same, with the profile named by `s3_gateway.default_upstream_profile`. |

A `CreateBucket` for a name that is already a gateway bucket answers like `HeadBucket`: success if the credential can see the bucket, and nothing is created.

## Upstream Profiles

An upstream profile says what a `CreateBucket` creates upstream: which provider credential (`vh api-key`) the bucket is created with, whether objects are encrypted before upload, the vault's sync strategy and conflict policy, and an optional prefix for the upstream bucket's name. The profile holds a reference to the provider credential, never its secret.

```bash
# Buckets mirror to a Backblaze B2 bucket of the same name, readable straight from Backblaze.
vh s3-gateway upstream create vl-b2 \
  --api-key b2-main \
  --no-encrypt \
  --sync-strategy mirror \
  --on-sync-conflict keep_local

# Every bucket this key creates now uses the profile.
vh s3-gateway creds scope backup set --upstream vl-b2
vh s3-gateway creds scope backup show

vh s3-gateway upstream list
vh s3-gateway upstream show vl-b2
vh s3-gateway upstream update vl-b2 --bucket-prefix acme-
vh s3-gateway upstream delete vl-b2
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--api-key` | required | The provider credential. It must be enabled for provider administration (`vh upstream admin enable <api-key>`): AWS S3, Cloudflare R2 or Backblaze B2. |
| `--encrypt` / `--no-encrypt` | encrypt | Whether objects are encrypted before they are uploaded. With `--no-encrypt` the upstream bucket holds the objects exactly as the client sent them, under the same keys. |
| `--sync-strategy` | `vaults.s3.default_remote_sync_strategy` | `cache`, `sync` or `mirror`. |
| `--on-sync-conflict` | `vaults.s3.default_remote_conflict_policy` | `keep_local`, `keep_remote`, `keep_newest` or `ask`. |
| `--bucket-prefix` | none | The upstream bucket is named `<prefix><gateway bucket>`. |

A profile's name is 1 to 32 lowercase letters, digits and hyphens. It can't be `local`, `server-default` or a real provider region such as `us-east-1`, and it never changes, because clients can [select a profile by name](#selecting-a-profile-per-request).

### What A CreateBucket Does

With a profile, `CreateBucket <name>`:

1. Looks for the upstream bucket `<prefix><name>` in the provider account.
2. Creates it if it does not exist. New buckets are private.
3. Creates an S3 vault named `<name>`, owned by the credential's principal, with the profile's encryption and sync settings.
4. Binds it as the gateway bucket `<name>` and answers the client.

An upstream bucket that already exists is never taken over:

| The upstream name | Result |
| --- | --- |
| Free | Created, and recorded as created by Vaulthalla. |
| Your own bucket, empty | Adopted and used. |
| Your own bucket, holding objects | `409 BucketAlreadyExists`. Nothing is created or changed. |
| Held by another account | `409 BucketAlreadyExists`. Nothing is created. |
| The provider is unreachable or fails | `503 ServiceUnavailable`. Nothing is created; the client can retry. |

A refused `CreateBucket` never falls back to a local vault. To put a gateway bucket over a bucket that already holds data, do it deliberately: create a vault that adopts it (`vh vault create <name> --s3 --api-key <key> --bucket <bucket> --bucket-mode adopt`), then `vh s3-gateway bucket bind`.

:::callout[Mirror with keep_local]{theme="warning"}
A `mirror` vault with `keep_local` makes the upstream bucket match the vault: an upstream object the vault does not hold is deleted on the next sync pass. That is why a `CreateBucket` only ever uses a bucket it created or an empty one. Keep other writers out of buckets a mirror vault owns.
:::

Bucket names are shared by every account of AWS S3 and of Backblaze B2, so a short name such as `backups` is usually taken. A prefix of your own (`--bucket-prefix acme-`) keeps the upstream names predictable and out of other accounts' way. The provider's own naming rules apply to the whole upstream name; Backblaze B2 needs at least 6 characters and refuses names starting with `b2-`.

### Selecting A Profile Per Request

A client can also name a profile itself, by sending the profile's name where S3 carries a region:

- as `CreateBucketConfiguration.LocationConstraint`, for example `aws s3api create-bucket --bucket reports --create-bucket-configuration LocationConstraint=vl-b2`;
- or by signing with it as the region (`region = vl-b2` in the client's configuration), which needs no extra argument.

`LocationConstraint=local` forces a local vault. Any other value, such as the real region most clients send by default, selects nothing. The order is: the request's `LocationConstraint`, the region it signed with, the credential's profile, then the server default if the credential follows it.

A request can only name a profile the credential was given: its own profile, or one on its allowlist. That lets one key reach several provider accounts without a key per account, and bounds which accounts a key can create buckets on:

```bash
# vl-b2 by default; r2-edge and aws-archive when the client names them.
vh s3-gateway creds scope backup set --upstream vl-b2 --allow-upstream r2-edge --allow-upstream aws-archive
vh s3-gateway creds scope backup set --allow-upstream none    # only its own profile again
```

`--allow-upstream` replaces the whole list. A request that names any other profile is refused with `403 AccessDenied`; it is never created as a local vault. A credential with no profile and no allowlist cannot be steered to a provider account by its client at all.

Naming a profile does not get around permissions either: the credential's principal must be allowed to create buckets with that profile's provider credential.

### Server Default

`s3_gateway.default_upstream_profile` names one profile as the server's default. It applies only to credentials that opted in:

```bash
vh s3-gateway creds scope backup set --upstream server-default
vh s3-gateway creds scope backup set --upstream local     # back to local vaults
```

Setting a server default never changes what existing credentials create. If a credential follows the server default and none is set, its `CreateBucket` fails with an error instead of creating a local vault.

### Changing A Profile

Changing a profile's API key, encryption or prefix affects only buckets created afterwards. Changing its sync strategy or conflict policy is also applied to the buckets already created from it, and `vh s3-gateway upstream update` reports each bucket it changed or left alone:

- `s3_gateway.reapply_upstream_profile_changes` (default `true`) is the server's setting;
- a credential can decide for the buckets it created: `vh s3-gateway creds scope backup set --reapply off` (or `on`, or `inherit` to follow the server again);
- the person changing the profile needs permission to change each vault's sync settings; a bucket they may not change is reported and left as it is.

A bucket follows the profile it was created from. Pointing a credential at another profile changes nothing for the buckets it already created.

### Permissions

| Action | Needs |
| --- | --- |
| Create, change or delete a profile | `admin.s3_gateway.manage_buckets`, `admin.upstream.provision`, and permission to use the provider credential. |
| Point a credential at a profile, or add one to its allowlist | Management of that credential, plus `admin.upstream.provision` and permission to use the provider credential, for the person making the change and for the credential's principal. |
| `CreateBucket` through a profile | The credential's principal must still hold those rights when the request arrives, plus what any gateway bucket needs. |

A profile can't be deleted while a credential (as its own profile or on its allowlist) or the server default uses it, and a provider credential can't be deleted while a profile uses it.

## API-Exclusive Buckets

API-exclusive buckets are intended for vaults created and owned primarily through S3 Gateway. They keep downstream S3 client expectations clearer by reducing unrelated Vaulthalla workflows that might create conflicting object state in the same vault.

Use API-exclusive local buckets for MinIO-like local object storage. Use API-exclusive remote-cache buckets when Vaulthalla should expose an S3-compatible proxy/cache edge while relying on the remote object index, manifest sync, and configured upstream provider bucket.

## Backfill

Backfill imports existing Vaulthalla metadata into gateway object state:

```bash
vh s3-gateway bucket backfill archive
vh s3-gateway bucket backfill archive --calculate-etags
```

The default backfill is metadata-only. `--calculate-etags` intentionally reads and decrypts local object bodies to calculate plaintext MD5 ETags and is only supported for local Vaulthalla files.
