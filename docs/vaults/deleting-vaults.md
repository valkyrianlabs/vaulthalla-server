---
title: Deleting And Restoring Vaults
navTitle: Deleting Vaults
description: How vault deletion works in Vaulthalla, the restore window, purging local and upstream data, and how long encryption keys are kept.
order: 255
status: published
tags:
  - vaults
  - deletion
  - keys
  - recovery
---

# Deleting And Restoring Vaults

Deleting a vault is a schedule, not an instant wipe. The vault disappears at once, stays restorable for a while, and is then purged by the daemon. Its encryption key is kept longer than its data, so encrypted copies elsewhere stay recoverable.

:::toc[On this page]{depth="3" theme="compact"}
:::

## What Happens When You Delete A Vault

1. **Right away**, the vault disappears from listings, the FUSE mount at `/mnt/vaulthalla`, sync, share links and the S3 gateway. Its name, slug, FUSE name and S3 bucket binding stay reserved.
2. **Until `vaults.retention_window` ends** (default `5m`), you can restore it exactly as it was: files, roles, share links and sync settings.
3. **Then the daemon purges it**: the vault's local backing and cache directories are removed, the bucket's objects too when you chose that, and the vault's database rows go. The name is free again.

[File recovery](/vaults/recovery) data follows the same schedule: local snapshots and local versions are removed with the vault's local data. Provider versions are never deleted: when you chose to delete a versioned bucket's objects, the purge leaves delete markers, and the old versions stay in the bucket (and are billed) until its retention removes them. Export the vault's keys before deleting it if you want those versions to stay readable: the export of a deleted vault carries its current key only, not the retired versions old object versions may be sealed with.
4. **The sealed encryption key is kept** until `vaults.tpm_retention_window` ends (default `90d`, `180d` for S3 vaults), counted from the deletion. After that it is destroyed. A small record of the deleted vault (name, key version, timestamps) stays.

**Delete now** skips the restore window: the purge starts within moments. It never shortens the key retention window.

:::callout{theme="warning" title="Export the key of an encrypted S3 vault before keeping its bucket"}
When you delete an S3 vault but keep the objects in its bucket, they stay encrypted with the vault's key. If that key was never exported, losing it means losing that data for good. Export it first, or at the latest before the key retention window ends.
:::

## Delete From The CLI

```bash
vh vault delete <id-or-name> [--owner <user-or-id>]
```

In a terminal the command asks, in order:

1. For S3 vaults: also delete every object in the bucket when the vault is purged? (default: no)
2. When encrypted objects stay in the bucket and the key was never exported: a warning with the export command, and a typed `DELETE WITHOUT KEY` to continue.
3. Delete (restorable), delete now, or cancel. Delete now asks you to type the vault name.

Without a terminal, or with `--yes`, the command does what the flags say and nothing else:

| Flag | Effect |
| --- | --- |
| (none) | Scheduled delete, restorable until the retention window ends. S3 bucket objects are kept. |
| `--now` | Purge right away. Needs `--yes` (or the typed confirmation in a terminal). |
| `--delete-upstream` | S3: delete every object in the bucket when the vault is purged. |
| `--keep-upstream` | S3: keep the bucket's objects (the default). |
| `--accept-key-loss` | S3: keep encrypted objects in the bucket although the key was never exported. |
| `--yes` | Don't ask. |

Examples:

```bash
vh vault delete 42
vh vault delete 42 --now --yes
vh vault delete archive --owner alice --delete-upstream --yes
```

Running `vh vault delete <vault> --now` on a vault that is already pending deletion purges it on the next pass.

## Restore Or Review Deleted Vaults

```bash
vh vault deleted
vh vault deleted --json
vh vault restore <id-or-name> [--owner <user-or-id>]
```

`vh vault deleted` lists pending deletions (restorable), purges in progress (with the last error if one failed), and purged vaults whose key is still kept. It keeps warning about encrypted upstream data whose key was never exported.

A restore works until the purge starts. Once it has started it cannot be undone.

## Delete From The Web Console

Open the vault, then **Settings → Delete vault**. One dialog shows how long the vault stays restorable and how long its key is kept, asks S3 vaults whether to delete the bucket's objects too, and shows the key warning with the export command to copy. **Delete** schedules the deletion; **Delete now** asks you to type the vault name.

The **Deleted vaults** panel on the Vaults page lists pending and purged deletions with **Restore** and **Purge now**.

Keys are never exported through the browser. Run the export command on the server, or back the key up from a Mac paired with Vaulthalla Desktop.

## Export A Key, Before Or After Deletion

```bash
vh vault keys export <vault-id> --recipient <gpg-fingerprint> --output /var/lib/vaulthalla/vault-<vault-id>-key.gpg
```

The same command works for a deleted vault until its key retention window ends. Vaulthalla records each export of the current key version; the delete flows stop warning once an export is recorded. A key rotation needs a new export.

See [Secrets And Key Export](/vaults/secrets-and-key-export).

## Permissions

Deleting, deleting now, restoring and listing deleted vaults all need the vault **remove** permission for the vault's owner scope (self, user or admin). Purging is internal to the daemon. Deleting a user account deletes the vaults it owns the same way.

An account whose API keys are still bound to vaults cannot be deleted. A deleted S3 vault keeps its binding until it is purged, so delete those vaults (`--now` purges them right away) or move them to another key first.

## How The Purge Works

The daemon's retention service checks every 30 seconds, and right after a **delete now**.

- **Upstream objects first**, only when chosen. Each pass lists at most 10 pages of 1000 keys and sends at most 10 000 DELETE requests, then continues on the next pass. LIST requests are billed by most providers; DELETE requests usually are not. If another vault uses the same bucket on the same endpoint, or the binding is gone, the objects are kept and the record says why.
- **Local data next**: the vault's backing and cache directories, only when each is a plain directory directly under `/var/lib/vaulthalla`. Symlinks are never followed.
- **Database rows last**, in one transaction.

A purge interrupted by a restart resumes on the next start. A failed attempt is retried with a growing delay (up to an hour); `vh vault deleted` shows the error.

## Configuration

```yaml
vaults:
  retention_window: 5m
  tpm_retention_window: 90d
  s3:
    tpm_retention_window: 180d
```

Durations take `s`, `m`, `h`, `d` or `w`. A change applies to vaults deleted afterwards: each deletion keeps the deadlines it was given. See [Configuration](/reference/configuration).
