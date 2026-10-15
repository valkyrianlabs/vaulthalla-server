---
title: Managed Upstream Buckets
navTitle: Managed Buckets
description: Let Vaulthalla administer AWS S3 and Cloudflare R2 buckets for your vaults - inventory, protection locks, new and adopted buckets, lifecycle rules and safe cleanup.
order: 225
status: published
tags:
  - vaults
  - s3
  - r2
  - upstream-storage
  - administration
---

# Managed Upstream Buckets

An upstream provider credential can also administer its AWS S3 or Cloudflare R2 account. With provider administration
turned on, Vaulthalla lists the account's buckets, creates new buckets for vaults, adopts existing ones, manages its own
lifecycle and event rules, and cleans up buckets it created. You choose the vault configuration; Vaulthalla runs the
bucket machinery.

Other S3-compatible providers (MinIO, Wasabi, Backblaze B2, ...) keep working as plain vault storage. Bucket protection
locks apply to them too; the rest of this page is AWS S3 and Cloudflare R2 only.

:::callout{theme="warning" title="Nothing here deletes data by default"}
Deleting or detaching a vault never deletes its bucket or objects. Deleting an upstream bucket is a separate,
explicitly confirmed and audited operation, and only for buckets Vaulthalla created.
:::

:::toc[On this page]{depth="3" theme="compact"}
:::

## One Credential Per Account

Provider administration extends the [upstream provider credential](/vaults/s3-r2-vaults) you already use. It does not
need extra cloud identities: one access-key pair per account does everything. Vaulthalla splits authority between
people with its own `admin.upstream` permissions (see [Permissions](#permissions)).

Turn it on for an existing credential:

```bash
vh upstream admin enable <api-key>
vh upstream admin status <api-key> --probe
```

`status --probe` checks what the credential can do without changing anything and lists each capability as available
or missing, with the permission to grant. A missing capability doesn't block the rest: a credential that can list and
create buckets but not create queues still manages buckets, and event-driven sync reports exactly what is missing.

In the web console: **Credentials** → the credential → **Provider administration**.

### AWS S3

The credential's IAM identity needs, on the buckets Vaulthalla manages:

- `s3:ListAllMyBuckets`, `s3:CreateBucket`, `s3:DeleteBucket`, `s3:GetBucketLocation`, `s3:ListBucket`,
  `s3:ListBucketVersions`, `s3:GetBucketVersioning`, `s3:GetBucketObjectLockConfiguration`,
  `s3:GetLifecycleConfiguration`, `s3:PutLifecycleConfiguration`, `s3:GetBucketNotification`,
  `s3:PutBucketNotification`, `s3:DeleteObject`, `s3:DeleteObjectVersion`, plus the object permissions plain vault
  storage already needs.
- For [event-driven sync](/vaults/event-sync), on queues named `vaulthalla-*` in the same account
  (`arn:aws:sqs:*:<account>:vaulthalla-*`): `sqs:CreateQueue`, `sqs:GetQueueUrl`, `sqs:GetQueueAttributes`,
  `sqs:SetQueueAttributes`, `sqs:ReceiveMessage`, `sqs:DeleteMessage`, `sqs:ChangeMessageVisibility`,
  `sqs:DeleteQueue`, and `sqs:ListQueues` (on `*`).

The same credential sets the queue's resource policy that lets Amazon S3 publish to it; no second IAM principal is
involved. Vaulthalla reads the account ID with STS `GetCallerIdentity`, which needs no permission.

### Cloudflare R2

R2's S3-compatible credentials (access key ID and secret) cover listing, creating and deleting buckets and lifecycle
rules. R2 event notifications and Cloudflare Queues are managed through Cloudflare's account API, which needs an API
token instead: an R2 secret access key is a hash of a token, not the token, so it can't sign those requests.

For [event-driven sync](/vaults/event-sync), create one Cloudflare API token for the account with **Account › Queues:
Edit** and **Account › Workers R2 Storage: Edit**, and store it on the same credential:

```bash
vh upstream admin enable <api-key> --provider-token
```

The token is asked for at a hidden prompt, sealed like the S3 secret, and never shown again (the console only says
whether one is stored). `--clear-provider-token` removes it. The account ID comes from the R2 endpoint
(`https://<account-id>.r2.cloudflarestorage.com`). R2 signs every request with region `auto`; location hints such as
`wnam` are only used when creating a bucket.

## Bucket Inventory

```bash
vh upstream buckets <api-key>
vh upstream buckets <api-key> --state unmanaged
```

The inventory is one account-level `ListBuckets` page merged with what Vaulthalla knows. It makes no bucket-level or
object calls. Each bucket has one state:

| State | Meaning |
| --- | --- |
| `managed` | Vaulthalla created it for a vault. |
| `adopted` | An existing bucket an administrator explicitly associated with a vault. |
| `unmanaged` | Discovered in the account, not controlled by Vaulthalla. |
| `protected` | Locked: excluded from every Vaulthalla operation (see below). The lock wins over the other states. |

Use `--filter <text>` to match names, and `--page-token` to continue a long listing.

## Protection Locks

A protected bucket is a hard exclusion. Vaulthalla will not probe it, inventory its objects, adopt it, bind a vault to
it, change its lifecycle or event rules, read or write it during sync, empty it or delete it. Scheduled syncs, retries
and work already in flight stop at their next request to it; a vault already bound to it stalls with a "bucket is
protected" error until the lock is removed. Account-level listings still show its name.

```bash
vh upstream protect <api-key> <bucket> --reason "production backups, not for Vaulthalla"
vh upstream unprotect <api-key> <bucket>
```

- The lock belongs to the bucket itself (provider, account and bucket name), not to the credential. Deleting and
  re-creating the credential keeps it, and any other credential for the same account sees it.
- The provider and account come from the credential's endpoint, not its label: a credential for an
  `….r2.cloudflarestorage.com` or `….amazonaws.com` endpoint is treated as Cloudflare R2 or AWS S3 whatever provider
  it was saved with, so a lock can't be sidestepped by relabelling a key. New credentials whose provider contradicts
  their endpoint are refused.
- Locks work for any provider, including ones without administration support.
- Bucket names are checked before they are used anywhere upstream (3–63 characters of `a-z 0-9 . -`); a name like
  `x/../prod` is refused. Buckets with older, non-conforming names can still be locked.
- Removing a lock needs the separate `admin.upstream.unprotect` permission and an explicit confirmation
  (`--yes` for scripts). Both directions are recorded in the audit log with who, when and the reason.
- Locks are kept in the database and loaded before the server makes any upstream request; if they can't be loaded, the
  server doesn't start.

## Create A Vault With A New Bucket

```bash
vh vault create media --s3 --api-key aws-admin --bucket-mode create --generate-bucket --region us-east-2
vh vault create media --s3 --api-key r2-admin --bucket-mode create --bucket vh-media --events
```

In the web console, **New vault** offers *Create a new bucket* for administrative credentials, with *Generate a name*,
the region or location hint, and optional advanced settings (incomplete-upload cleanup, event-driven sync).

Creating never takes over an existing bucket:

1. The name must not exist (a `HeadBucket` 404). An existing bucket is refused: adopt it instead.
2. The provider must create it. "Already exists" or "already owned by you" is refused and nothing changes.
3. The new bucket must be empty. If it isn't, creation stops, the bucket is left as it is and marked failed.

Only then does the vault get created and bound. If anything fails after the bucket was created, an empty bucket created
by this attempt is removed again; anything else is left untouched and marked failed. Retrying with the same name reuses
Vaulthalla's own empty bucket from the failed attempt. Two creations racing for one name can't both win.

## Adopt An Existing Bucket

Adoption associates a bucket that already exists, with its data, with a new vault. It is always explicit.

```bash
vh upstream adopt-check <api-key> <bucket>
vh vault create archive --s3 --api-key aws-admin --bucket <bucket> --bucket-mode adopt
```

`adopt-check` is a read-only admission check: it lists up to 10,000 keys and reads the metadata (not the bodies) of a
small sample. It reports object counts and bytes, whether objects are Vaulthalla-encrypted or plaintext, versioning and
object lock, and whether the bucket already holds a Vaulthalla manifest from another vault. It refuses protected
buckets and buckets another vault already uses.

Creating the vault then asks for confirmation (`--yes` for scripts; the console shows the report). Nothing in the
bucket is deleted, overwritten or converted: plaintext objects are imported as vault files and encrypted locally;
whether new uploads to the bucket are encrypted follows the vault's upstream encryption setting, and the usual
[encryption waiver](/vaults/encryption) is recorded. When event-driven sync is requested, the subscription is created
before the first full listing, so changes made during the listing aren't lost.

## Lifecycle Rules

```bash
vh upstream inspect <api-key> <bucket>
vh upstream lifecycle <api-key> <bucket> --abort-multipart-days 7
vh upstream lifecycle <api-key> <bucket> --clear
```

`inspect` shows the bucket's region, versioning, object lock, lifecycle rules and event rules, marking which ones are
Vaulthalla's. Vaulthalla owns exactly one lifecycle rule, `vaulthalla-managed`, on managed and adopted buckets, and
preserves every other rule unchanged.

| Option | AWS S3 | Cloudflare R2 |
| --- | --- | --- |
| `--abort-multipart-days N` (incomplete multipart uploads) | yes | yes |
| `--expire-days N` (delete current objects after N days) | yes, destructive | yes, destructive |
| `--expire-noncurrent-days N` (delete old versions) | yes, destructive | not offered |
| `--prefix P` | yes | yes |

Expiration rules delete data, so they need explicit confirmation (`--yes`). Value `0` removes a setting. New R2 buckets
come with Cloudflare's default multipart-abort rule; it is kept as a foreign rule.

## Vault Deletion, Detach And Cleanup

Deleting a vault ([Deleting And Restoring Vaults](/vaults/deleting-vaults)) leaves its bucket and objects in place
unless you chose the existing opt-in upstream object purge. The bucket stays `managed` or `adopted` with no vault.

**Detach** gives a bucket that no vault uses back to you: Vaulthalla removes its own event rules and lifecycle rule, and
the bucket becomes `unmanaged`. Data is untouched.

```bash
vh upstream detach <api-key> <bucket>
```

**Cleanup** deletes a bucket Vaulthalla created, with every object version in it:

```bash
vh upstream cleanup <api-key> <bucket>
```

It first prints a preflight: object, version and delete-marker counts, bytes, versioning and object lock, sample keys
and anything that blocks it. It is refused for protected buckets, adopted or unmanaged buckets, buckets any vault
(including one pending deletion) is bound to, and buckets with a live event subscription. To go ahead you type the
bucket name (or pass the preflight's `--confirm-token`, valid for 10 minutes). Right before deleting, every check runs
again. Object-lock and retention rules are the provider's to enforce: objects it refuses to delete are reported, and the
result is `partial`, never `deleted`. Large buckets are deleted in rounds; run the command again to continue. Nothing
is ever purged because a vault creation or a sync failed.

## Permissions

Provider administration uses its own admin permission module, `admin.upstream`, on top of the credential permissions
(`admin.keys.api.*`) every operation also needs for the key it uses:

| Permission | Allows | Built-in roles |
| --- | --- | --- |
| `admin.upstream.view` | inventory, inspect, event status, audit log | super_admin, admin, platform_operator, security_admin, auditor, vault_admin |
| `admin.upstream.configure` | turn administration on or off, lifecycle rules, event subscriptions and repair | super_admin, admin, platform_operator |
| `admin.upstream.provision` | create managed buckets, adopt buckets | super_admin, admin, platform_operator |
| `admin.upstream.protect` | lock a bucket | super_admin, admin, platform_operator, security_admin |
| `admin.upstream.unprotect` | remove a lock | super_admin |
| `admin.upstream.destroy` | detach and clean up buckets | super_admin |

Grant them to custom roles with `vh role admin update <role> --allow-upstream-<name>` or the console's role editor. The
CLI and the web console run the same operations with the same checks.

## Audit Log

```bash
vh upstream audit
vh upstream audit --bucket <bucket>
```

Every lock and unlock, creation, adoption, lifecycle change, event subscription change, detach and cleanup, and
refusals that matter (protected bucket, name collision), is recorded with the account, bucket, credential, vault, who
did it and the outcome.
