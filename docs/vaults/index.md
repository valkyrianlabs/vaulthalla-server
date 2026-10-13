---
title: Vaults
description: Understand Vaulthalla vaults, storage types, metadata, FUSE access, ownership, and vault-level permissions.
order: 200
status: published
tags:
  - vaults
  - storage
---

# Vaults

A vault is the main storage boundary in Vaulthalla. It defines where file bodies live, how sync behaves, which users and groups can access content, and which encryption and cost controls apply.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Vault Types

Vaulthalla supports two operator-facing vault types:

| Type | Storage location | Best for |
| --- | --- | --- |
| Local vault | Vaulthalla-managed local state on the host | Low-latency local storage, simple deployments, controlled single-host workflows |
| S3/R2 upstream vault | AWS S3, Cloudflare R2, or another upstream S3-compatible provider bucket | Remote object storage, cloud-backed archives, cross-host access patterns, larger buckets |

Local vaults and S3/R2 vaults use the same high-level access-control model, but they differ in sync policy, request budgets, upstream object encryption, and recovery planning.

S3 Gateway is a separate downstream protocol surface, not a third vault type. Use [S3 Gateway](/s3-gateway) when AWS CLI, rclone, MinIO mc, SDKs, or apps should talk to Vaulthalla through the S3 protocol.

## Metadata And File Bodies

Vaulthalla stores runtime metadata in PostgreSQL. That metadata includes users, groups, roles, vault definitions, sync policy, remote indexes, shares, audit state, and encryption key records.

File bodies are stored according to the vault type:

- Local vault file bodies live under Vaulthalla-managed local state.
- S3/R2 vault file bodies live in the configured upstream provider bucket, with optional local cache state depending on sync strategy.

This split matters for backup. A usable disaster recovery plan needs PostgreSQL data, Vaulthalla config/state, and exported recovery material. See [Backup And Recovery](/vaults/backup-and-recovery).

## FUSE Mount

On Linux, the core daemon exposes vaults as a filesystem at:

```text
/mnt/vaulthalla
```

The web console and CLI operate through Vaulthalla permissions and metadata. Host-level filesystem access still depends on the daemon, FUSE health, Linux permissions, and the mounted state. The macOS package has no mount yet; see [Filesystem Access](/vaults/filesystem-access) for the mount's model and the alternatives on a Mac.

## Ownership

Vault commands can target an explicit owner where supported:

```bash
vh vault info <vault> --owner <user-or-id>
vh vault delete <vault> --owner <user-or-id>
```

Ownership is useful when administrators manage vaults on behalf of users or teams. For scripts, prefer stable ids where possible.

Deleting a vault is reversible for a while: it disappears at once, can be restored with `vh vault restore` until the retention window ends, and its encryption key is kept for longer. See [Deleting And Restoring Vaults](/vaults/deleting-vaults).

## Vault Roles

Vault roles grant permissions inside a vault. Assign them to users or groups:

```bash
vh vault role assign <vault> <role-id> --user alice
vh vault role assign <vault> <role-id> --group operators
vh vault role list <vault>
```

Vault permissions include browsing, creating, downloading, deleting, renaming, moving, sharing, syncing, metadata, tag, version, file-lock, access, and vault management capabilities.

Path-level overrides can further allow or deny permissions for a pattern:

```bash
vh vault role override add <vault> --user alice --pattern "/finance/*" --download --disable
```

## Encryption

Vaults use per-vault encryption keys protected by TPM-backed master keys. S3/R2 vaults also have an upstream object encryption setting that controls whether object bodies written to the bucket are encrypted by Vaulthalla before upload.

Use [Encryption](/vaults/encryption) before changing `--encrypt`, `--no-encrypt`, key rotation, or key export behavior.

## Create A Vault

Local:

```bash
vh vault create docs --local --desc "Team documents" --quota 50G
```

Upstream-backed S3/R2:

```bash
vh vault create archive \
  --s3 \
  --api-key r2-main \
  --bucket vaulthalla-archive \
  --sync-strategy cache \
  --encrypt
```

See [Local Vaults](/vaults/local-vaults), [S3 And R2 Vaults](/vaults/s3-r2-vaults), and [Vaults Exposed Through S3 Gateway](/vaults/s3-gateway). S3 Gateway setup and client usage live under [S3 Gateway](/s3-gateway).
