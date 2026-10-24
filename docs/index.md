---
title: Vaulthalla Documentation
navTitle: Home
description: Install, operate, secure, back up and troubleshoot Vaulthalla, the self-hosted encrypted cloud, on Linux and macOS.
order: 1
status: published
tags:
  - overview
  - operator
---

# Vaulthalla Documentation

Vaulthalla is **the final cloud**: sovereign, encrypted storage on hardware you own. A native C++ daemon encrypts every file before it reaches a disk or a bucket, enforces one set of permissions across the web console, the `vh` CLI, the S3-compatible gateway and (on Linux) a real filesystem mount, and syncs vaults to S3-compatible providers under cost limits you set. It runs on Linux and on Apple Silicon Macs.

These pages are for the people who install and run it, and the people who use it. Contributor documentation is under [Contributors](/contributors/README).

:::toc[On this page]{depth="2" theme="compact"}
:::

## Start Here

:::cards{columns="3" cardTheme="muted"}

:::card[Install Vaulthalla]{href="/getting-started/installation" linkScope="title" eyebrow="Linux or macOS"}
Choose a platform and install from APT, the macOS installer package, or Homebrew.
:::

:::card[First Run]{href="/getting-started/first-run" linkScope="title"}
Sign in, secure the generated admin password, confirm CLI access, and create a vault.
:::

:::card[HTTPS]{href="/https" linkScope="title"}
Serve the console on a home-network name or a public domain: nginx on Linux, Caddy on macOS.
:::

:::

## Your Platform

:::cards{columns="2" cardTheme="muted"}

:::card[Linux]{href="/linux" linkScope="title" eyebrow="amd64 · Ubuntu 24.04"}
The Debian package, systemd services, TPM2 key sealing, the FUSE mount, PostgreSQL and nginx integration. [Install](/linux/installation) · [Administer](/linux/administration) · [Troubleshoot](/linux/troubleshooting)
:::

:::card[macOS]{href="/macos" linkScope="title" eyebrow="Apple Silicon · macOS 14+"}
The installer package or Homebrew cask, launchd LaunchDaemons, a bundled PostgreSQL and Caddy. [Install](/macos/installation) · [Administer](/macos/administration) · [Troubleshoot](/macos/troubleshooting)
:::

:::

Every difference between the two is in [Platform Comparison](/reference/platforms); everything else on this site applies to both.

## Daily Operation

:::cards{columns="3" cardTheme="muted"}

:::card[Web Console]{href="/getting-started/web-console" linkScope="title"}
Files, previews, shares, vaults, users, cost control, health and notifications in the browser.
:::

:::card[CLI Guide]{href="/cli" linkScope="title"}
`vh` for status, users, roles, vaults, sync, API keys, secrets, budgets and file transfers.
:::

:::card[Vaults]{href="/vaults" linkScope="title"}
Local and S3/R2 vaults, ownership, permissions, and [filesystem access](/vaults/filesystem-access).
:::

:::card[Sync]{href="/vaults/sync" linkScope="title"}
Cache, sync or mirror strategies, dry-runs, S3 Inventory imports and conflict resolution.
:::

:::card[Sharing]{href="/sharing" linkScope="title"}
Public and email-validated share links with expiry, limits and upload policies.
:::

:::card[S3 Gateway]{href="/s3-gateway" linkScope="title"}
Vaults as S3 buckets for the AWS CLI, rclone, MinIO mc, SDKs and backup tools.
:::

:::

## Safety And Recovery

:::cards{columns="3" cardTheme="muted"}

:::card[Encryption]{href="/vaults/encryption" linkScope="title"}
How master keys are protected on each platform, per-vault AES-256-GCM keys, upstream encryption and rotation.
:::

:::card[Backup And Recovery]{href="/vaults/backup-and-recovery" linkScope="title"}
A recovery set that actually restores: database, state, configuration, key and secret exports.
:::

:::card[Cost Control]{href="/cost-control" linkScope="title"}
Request budgets and price budgets that stop S3/R2 work before it runs up a bill.
:::

:::

## Administration And Reference

- [Users, Groups And Roles](/admin/users-groups-roles), [S3 Gateway Administration](/admin/s3-gateway), [Operator Emails](/admin/operator-emails), [AI Agents And MCP](/admin/mcp-and-agents).
- [Configuration](/reference/configuration), [Runtime Paths](/reference/runtime-paths), [Platform Comparison](/reference/platforms), [Command Reference](/cli/command-reference).
- When something breaks: [Linux Troubleshooting](/linux/troubleshooting), [macOS Troubleshooting](/macos/troubleshooting), then [General Troubleshooting](/troubleshooting/general-troubleshooting) for vaults, sync, previews, shares and costs.

## What Ships Today

| Area | Status |
| --- | --- |
| Linux (amd64, APT): daemon, web console, CLI, FUSE mount, TPM2 sealing, nginx integration | Production |
| Encrypted local and S3/R2 vaults, sync, cost controls, RBAC, sharing, S3 gateway | Production, on both platforms |
| macOS (Apple Silicon): installer package, Homebrew cask, launchd, bundled PostgreSQL, `vh setup caddy` | New in this release |
| `vh fs` file transfers over the CLI socket | Production, on both platforms (the CLI file path on macOS) |
| Hardware video encoding in `vaulthalla-preview-media` | Detected, not yet validated on real GPUs |
| Finder access on macOS through Vaulthalla Desktop (the server never mounts on macOS), Secure Enclave key sealing, an Apple-signed package | Planned, not shipped |

These docs describe what the installed product does. Anything planned is labeled as such.
