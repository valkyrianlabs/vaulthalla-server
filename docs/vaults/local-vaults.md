---
title: Local Vaults
description: Create and operate Vaulthalla vaults backed by local host storage.
order: 210
status: published
tags:
  - vaults
  - local-storage
---

# Local Vaults

Local vaults keep file bodies in Vaulthalla-managed local state on the host. They are the simplest vault type when the deployment does not need S3-compatible object storage.

:::toc[On this page]{depth="3" theme="compact"}
:::

## When To Use A Local Vault

Use a local vault when:

- The host has enough disk for the stored data.
- You want simple operation without object-storage credentials.
- Low-latency local access matters.
- Backup tooling can capture local Vaulthalla state and PostgreSQL consistently.

Use an S3/R2 vault when object-storage durability, remote bucket workflows, or cloud-side inventory/event tooling is part of the design.

## Create

```bash
vh vault create docs \
  --local \
  --desc "Team documents" \
  --quota 50G \
  --on-sync-conflict keep_both
```

Common options:

| Option | Purpose |
| --- | --- |
| `--desc` | Human-readable vault description. |
| `--quota` | Size limit such as `10G`, or `unlimited`. |
| `--interval` | Sync interval. |
| `--owner` | Create for a specific owner where permitted. |
| `--on-sync-conflict` | Local conflict policy: `overwrite`, `keep_both`, or `ask`. |

## Update

```bash
vh vault update docs --quota 100G
vh vault update docs --on-sync-conflict ask
```

## Access Files

Use the web filesystem browser, `vh fs`, or on Linux the mounted filesystem surface:

```text
/mnt/vaulthalla
```

See [Filesystem Access](/vaults/filesystem-access).

Access is still controlled by Vaulthalla roles and the daemon. If a user can see the mount but cannot perform an operation, check the vault role assignment first.

## Sync Behavior

Local vault sync does not need S3 remote-index logic, request budgets, or S3 Inventory. Local conflict behavior is controlled by:

```bash
vh vault sync set docs --on-sync-conflict keep_both
vh vault sync info docs
```

Local conflict policies:

| Policy | Behavior |
| --- | --- |
| `overwrite` | Replace the older side with the chosen winner. |
| `keep_both` | Preserve both versions when a conflict is detected. |
| `ask` | Stall for operator or UI-directed resolution where supported. |

## Backup Considerations

Local vaults require backup of local Vaulthalla state in addition to PostgreSQL and exported recovery material. A PostgreSQL dump alone is not enough because it does not contain local file bodies.

See [Backup And Recovery](/vaults/backup-and-recovery).
