---
title: Vaulthalla On macOS
navTitle: macOS Overview
description: What Vaulthalla runs on a Mac, what is supported today, what is not yet, and how it differs from Linux.
order: 50
status: published
tags:
  - macos
  - platform
  - operator
---

# Vaulthalla On macOS

Vaulthalla runs on Apple Silicon Macs as a headless system service: the same C++ daemon, web console, `vh` CLI, encrypted vaults, RBAC, sharing and S3 gateway as on Linux, started at boot by launchd before anyone logs in. It installs from a self-contained installer package or a Homebrew cask, and both run the same package.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Requirements

| Requirement | Supported |
| --- | --- |
| Hardware | Apple Silicon (arm64). Intel Macs are not supported. |
| macOS | 14 (Sonoma) or later. |
| Disk | Room for vault data, the bundled PostgreSQL database and previews under `/Library/Application Support/Vaulthalla`. |
| Accounts | An administrator account to install (the installer asks for its password). |

Nothing else is required: the package brings its own PostgreSQL, Node runtime, Caddy and libraries, so a Mac without Homebrew or Xcode tools runs it.

## What Runs

The package installs four LaunchDaemons in the system domain. All of them run as `_vaulthalla`, a hidden role account the installer creates; none runs as root.

| LaunchDaemon | Role | Listens on |
| --- | --- | --- |
| `sh.vaulthalla.postgres` | The bundled PostgreSQL 16 cluster, private to Vaulthalla | `127.0.0.1:36971` and a socket only `_vaulthalla` can reach |
| `sh.vaulthalla.server` | The Vaulthalla daemon | `127.0.0.1:36969` (WebSocket), `127.0.0.1:36970` (HTTP), the CLI socket |
| `sh.vaulthalla.web` | The web console | `127.0.0.1:36968` |
| `sh.vaulthalla.caddy` | HTTPS front end, only after [`vh setup caddy`](/https/caddy) | `:80` and `:443` |

Every listener except Caddy binds to the loopback address, so nothing is reachable from your network until you set up HTTPS.

## Supported Today

:::cards{columns="2" cardTheme="muted"}

:::card[Installer package and Homebrew]{href="/macos/installation" linkScope="title"}
A `.pkg` you open in Finder or install from the command line, or `brew install --cask vaulthalla/tap/vaulthalla`. Upgrades reinstall over the top and keep every vault.
:::

:::card[HTTPS through Caddy]{href="/https/caddy" linkScope="title"}
`sudo vh setup caddy --domain vault.home.arpa` with certificates from a Vaulthalla CA, Let's Encrypt, Cloudflare DNS or your own files.
:::

:::card[Encrypted vaults and sync]{href="/vaults" linkScope="title"}
Local and S3/R2 vaults, AES-256-GCM at rest, sync strategies and cost controls, exactly as on Linux.
:::

:::card[Web console, CLI, sharing, S3 gateway]{href="/getting-started/first-run" linkScope="title"}
The installing user is enrolled for `vh` and becomes the CLI `admin`. Other local users can be enrolled.
:::

:::

## Not Yet Supported

:::callout[Know these limits before you rely on a Mac]{variant="warning"}
- **No Finder mount.** The package does not include the FUSE bridge, so vaults are not mounted as a folder. Use the web console, the S3 gateway, or [`vh fs`](/cli/command-reference#vault-files). See [Filesystem Access](/vaults/filesystem-access).
- **Secrets are not hardware-sealed.** Linux seals vault master keys with a TPM. macOS currently stores them in `0600` files inside the service's `0700` state directory (the `file` secrets backend), protected by file permissions and FileVault, not by the Secure Enclave. Keep FileVault on. See [Encryption](/vaults/encryption#how-master-keys-are-protected).
- **The package is not signed by Apple yet.** Opening it from Finder needs one manual approval. See [Installation](/macos/installation#open-the-package).
- **`vh setup nginx`, `vh setup db` and `vh setup remote-db` are Linux commands.** On macOS the package sets up its own database, and HTTPS goes through Caddy.
:::

## How macOS Differs From Linux

Shared behavior is documented once; the differences that matter to an operator are summarized here and in detail in [Platform Comparison](/reference/platforms).

| Topic | Linux | macOS |
| --- | --- | --- |
| Install channel | APT (`apt.vaulthalla.sh`) | Installer package or Homebrew cask |
| Service manager | systemd units | launchd LaunchDaemons |
| Service account | `vaulthalla` | `_vaulthalla` (hidden; the alias `vaulthalla` resolves to it) |
| Database | Distribution PostgreSQL, set up by the package | Bundled PostgreSQL 16, private to Vaulthalla |
| Key protection | TPM2 (hardware or managed software TPM) | `file` backend (permissions + FileVault) |
| Filesystem mount | FUSE at `/mnt/vaulthalla` | None in the package |
| HTTPS | `vh setup nginx` | `vh setup caddy` |
| CLI access | `vaulthalla` group + UID binding | `_vaulthalla` group; the installing user is enrolled automatically |

## Next Steps

- [Install on macOS](/macos/installation)
- [Administer the macOS service](/macos/administration)
- [Serve Vaulthalla over HTTPS with Caddy](/https/caddy)
- [macOS Troubleshooting](/macos/troubleshooting)
