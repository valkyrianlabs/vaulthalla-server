---
title: Install Vaulthalla
navTitle: Install
description: Choose a platform and install Vaulthalla - Linux through APT or macOS through the installer package or Homebrew.
order: 10
status: published
tags:
  - install
  - setup
  - operator
---

# Install Vaulthalla

Vaulthalla runs on Linux and on Apple Silicon Macs. Both run the same daemon, web console, CLI, encryption, access control, sharing and S3 gateway; they differ in how the service is installed and managed, how master keys are protected, and whether vaults can be mounted as a filesystem.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Choose A Platform

| | Linux | macOS |
| --- | --- | --- |
| Hardware | amd64 (x86-64) | Apple Silicon (arm64) |
| Operating system | Ubuntu 24.04 LTS (tested) | macOS 14 Sonoma or later |
| Install channel | APT, `apt.valkyrianlabs.com` (alias `apt.vaulthalla.sh`) | Installer package or Homebrew cask |
| Service manager | systemd | launchd |
| Database | Distribution PostgreSQL (local or remote) | Bundled PostgreSQL 16 |
| Master key protection | TPM2 (hardware or software TPM) | Protected files + FileVault |
| Filesystem mount | FUSE at `/mnt/vaulthalla` | Not in the package |
| HTTPS | `vh setup nginx` | `vh setup caddy` |
| Status | Production | New in this release; see [what is not supported yet](/macos#not-yet-supported) |

For a server you will rely on, Linux is the more complete platform. A Mac is a good fit for a home or small-office server where the web console, sync, sharing and the S3 gateway cover how you reach your files.

## Quick Install

:::tabs{default="linux"}

:::tab[Linux]{value="linux"}
```bash
curl -fsSL https://apt.vaulthalla.sh/install.sh | bash
```

The installer adds the signed Vaulthalla APT repository and installs the `vaulthalla` package with PostgreSQL and nginx. Add `-s -- --interactive` after `bash` to choose an install profile and the Linux user who administers Vaulthalla.

Then sign in at `http://<host>/` as `admin` with the password in `/var/lib/vaulthalla/super_admin_initial_password`.

Full guide: [Install On Linux](/linux/installation).
:::

:::tab[macOS (Homebrew)]{value="brew"}
```bash
brew install --cask vaulthalla/tap/vaulthalla
```

Then sign in at `http://127.0.0.1:36968` as `admin` with the password in `/Library/Application Support/Vaulthalla/state/super_admin_initial_password`.

Full guide: [Install On macOS](/macos/installation).
:::

:::tab[macOS (package)]{value="pkg"}
Download `vaulthalla-<version>-arm64.pkg` from the [GitHub releases](https://github.com/vaulthalla/server/releases), then:

```bash
sudo installer -pkg vaulthalla-<version>-arm64.pkg -target /
```

The package is not signed by Apple yet: opening it from Finder needs **Open Anyway** in System Settings → Privacy & Security once.

Full guide: [Install On macOS](/macos/installation).
:::

:::

## After Installing

:::steps

### Sign in and change the generated password

Every install generates its own `admin` password and stores a plaintext copy that only root can read. See [First Run](/getting-started/first-run).

### Serve it over HTTPS

[nginx on Linux](/https/nginx) or [Caddy on macOS](/https/caddy), for a private network name or a public domain.

### Create a vault and plan backups

[Local Vaults](/vaults/local-vaults), [S3 And R2 Vaults](/vaults/s3-r2-vaults), and [Backup And Recovery](/vaults/backup-and-recovery) before important data goes in.

:::

## Building From Source

Source builds (`make install`, `make dev`) are for development. Production installs use the APT package on Linux and the installer package or Homebrew cask on macOS. See [Development Setup](/contributors/development-setup).
