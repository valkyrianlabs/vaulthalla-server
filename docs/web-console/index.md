---
title: Web Console Workflows
navTitle: Web Console
description: Map common Vaulthalla web console workflows to the equivalent CLI and understand the browser-based control surface.
order: 120
status: published
tags:
  - web
  - web-console
  - workflows
---

# Web Console Workflows

The Vaulthalla web console is the browser-based control surface for most operator tasks. It is not an arbitrary host shell. It sends authenticated WebSocket commands to the Vaulthalla daemon and exposes supported workflows through pages, forms, tables, and file actions.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Web Console Versus CLI

| Task | Web console | CLI |
| --- | --- | --- |
| View runtime health | Health | `vh status` |
| Browse files | Files | `vh fs ls`, and `/mnt/vaulthalla` on Linux |
| Create vaults | Vaults → New vault | `vh vault create ...` |
| Manage S3/R2 API keys | Provider credentials | `vh api-key ...` |
| Manage users and groups | Users and Groups | `vh user ...`, `vh group ...` |
| Manage roles | Roles (admin and vault roles in one list) | `vh role ...`, `vh vault role ...` |
| Manage shares | Shares, and Share link… on a file or folder in Files | Web-first workflow |
| Manage price budgets | Cost control | `vh pricing budget ...` |
| Resolve sync conflicts | Sync Conflicts (top bar and System) | `vh sync resolve` |
| Manage S3 Gateway | S3 gateway | `vh s3-gateway ...` |
| Configure operator email | Notifications | `vh email ...` |

Use the CLI for lifecycle commands, recovery exports, automation, and host-local troubleshooting. Use the web console for interactive administration, file browsing, health telemetry, shares, and policy editing.

## Health

The Health area (formerly the dashboard) summarizes runtime health, filesystem activity, storage, operations, and trends. It can show setup advisories, such as an unbound CLI admin UID, without marking the whole runtime unhealthy.

Health needs the `admin.stats.view` admin permission (held by the built-in `admin`, `auditor`, `platform_operator` and `super_admin` roles). A vault's own statistics are shown to its owner and to admins with `view_stats` on that vault. `vh status` stays available to every local operator in the `vaulthalla` group: it is the host-level liveness check and works while the database is down, so it doesn't look up an account.

Treat dashboard backup/recovery indicators as status signals. They do not prove a real backup has completed.

## Filesystem

The Filesystem page lets authenticated users browse and act on vault files according to their vault roles. Available actions depend on permissions and context.

Typical actions include:

- Preview.
- Download.
- Upload.
- Copy.
- Delete.
- Share.

If an action is missing or denied, check the user's vault role and any path overrides.

See [File Previews](/web-console/previews) for what opens in the browser (images, PDFs, video and audio, 3D models, text and Markdown editing) and what preview-only share links allow.

See [File Recovery](/web-console/recovery) for recovery history, restores, snapshots and provider versioning.

See [Uploads](/web-console/uploads) for resumable uploads: part sizes, resuming after a reload, and what reverse proxies and Cloudflare need.

## Vault Management

The Vaults page supports local and S3/R2 vault creation. For S3/R2 vaults, the form includes:

- API key.
- Bucket.
- Storage tier.
- Sync strategy.
- Conflict policy.
- Sync interval.
- Upstream encryption.
- Request-budget preset or custom limits.
- Maximum remote-index age.

After creating or editing an S3/R2 vault, confirm the policy from the CLI:

```bash
vh vault sync info <vault>
```

## Sync Conflicts

When an S3/R2 vault's conflict policy is `ask` (the default for new S3/R2 vaults), a file that changed both in the vault and in the bucket since they were last in sync is recorded as a sync conflict. That file stops syncing until someone decides; everything else keeps syncing. See [Vault Sync](/vaults/sync) for how conflicts are detected.

A **Sync Conflicts** button with the number of open conflicts appears in the top bar, and a **Sync Conflicts** page appears under **System** in the sidebar. Both are hidden while there is nothing for you to resolve. You only see conflicts in vaults where you hold `vault.sync.action.resolve_conflicts` (through a vault role, your own role's scope as the owner, or an admin's vault globals); resolving a file also needs Overwrite on that file.

On the page you can:

- Filter by vault (only vaults that have conflicts are listed).
- Choose **Keep local** (upload the vault's copy over the bucket's) or **Keep remote** (download the bucket's copy over the vault's) for one file.
- Tick several files, or select all, and apply **Keep local** or **Keep remote** to all of them at once. Each file is handled on its own, and the page lists every file that could not be resolved with the reason.
- Click a file to compare both copies side by side: sizes, modification times, hashes and types always; images, video and audio next to each other; text files as a line diff.

:::callout{theme="info" title="Bucket reads are metered"}
Previewing the bucket's copy downloads it from your provider, within the vault's request and price budgets. Small copies load when you open the comparison; larger ones wait for **Load the bucket copy**, and copies over 32 MiB are not previewed.
:::

A file whose copy changed again after the conflict was recorded is refused with "Changed since recorded" and stays in the list, so a decision never overwrites a change you have not seen.

## Cost Control

The Cost Control page manages price budgets. Request budgets remain part of each S3/R2 vault sync policy.

Use the CLI when you need scriptable checks:

```bash
vh pricing budget status
vh pricing budget ledger --limit 100
vh vault sync dry-run <vault>
```

## S3 Gateway

**S3 gateway** manages the downstream S3-compatible protocol surface. Use it to check service readiness, create gateway credentials, bind gateway buckets, set gateway key and key/vault budgets, review ledger/status details, and copy client snippets.

See [S3 Gateway](/s3-gateway) for endpoint setup, downstream client examples, credential scopes, bucket modes, budget behavior, and S3 operation semantics.

## Shares

The web console is the primary share workflow. It creates the one-time public URL or email-validated share URL, lets operators rotate links, and restricts share-mode file actions to the share role.

See [Sharing](/sharing).

## Operator Email

The **Notifications** page (operator email) configures notification providers and checks delivery history. Use it with CLI smoke tests:

```bash
vh email doctor
vh email test --dry-run
vh email history --limit 100
```

## When To Use The CLI Instead

Use `vh` instead of the web console for:

- Package lifecycle setup and teardown.
- Admin Linux UID assignment.
- Database bootstrap and remote database setup.
- Nginx and Certbot setup.
- Vault key and internal secret exports.
- Shell-based automation.
- Recovery and low-level service troubleshooting.
