[![build](https://img.shields.io/github/actions/workflow/status/vaulthalla/vaulthalla/build_and_test.yml?label=build)](https://github.com/vaulthalla/vaulthalla/actions)
[![release](https://img.shields.io/github/v/release/vaulthalla/vaulthalla?display_name=tag&sort=semver)](https://github.com/vaulthalla/vaulthalla/releases)
[![license](https://img.shields.io/github/license/vaulthalla/vaulthalla?v=2)](https://github.com/vaulthalla/vaulthalla/blob/main/LICENSE)
![Linux](https://img.shields.io/badge/Linux-amd64-A81D33?logo=debian&logoColor=white)
![macOS](https://img.shields.io/badge/macOS-Apple%20Silicon-000000?logo=apple&logoColor=white)
[![AES-256-GCM/NI](https://img.shields.io/badge/AES--256--GCM%2FNI-encrypted-cyan)](https://github.com/vaulthalla/vaulthalla)

# Vaulthalla: The Final Cloud

**Stop renting back your own data.**

Vaulthalla is sovereignty-first, encrypted, self-hosted storage for hardware you own. It is a compiled C++ daemon,
not a web app bolted onto a database: files are encrypted before they reach a disk or a bucket, one permission model
governs the web console, the `vh` CLI, the S3-compatible gateway and (on Linux) a real filesystem mount, and vaults
sync to S3-compatible providers under budgets you set. It is a rapidly maturing alternative to tools like Nextcloud
and MinIO, and it runs on Linux servers and Apple Silicon Macs.

> 📖 **Documentation: [vaulthalla.io/docs](https://vaulthalla.io/docs)** covers installation on both platforms,
> HTTPS, administration, storage, sharing, the S3 gateway, the CLI, backup and troubleshooting.

## Platforms

| Platform | Architecture | Install | Status |
| --- | --- | --- | --- |
| Linux: Ubuntu 24.04 LTS (tested), Debian family | amd64 | APT repository `apt.vaulthalla.sh` | Production |
| macOS 14 Sonoma or later | Apple Silicon (arm64) | Installer package or Homebrew cask | New: [see what is not supported yet](https://vaulthalla.io/docs/macos) |

Intel Macs, Windows and ARM Linux are not supported.

## Install

### Linux

```bash
curl -fsSL https://apt.vaulthalla.sh/install.sh | bash
```

Add `-s -- --interactive` after `bash` to choose an install profile and the Linux user who administers Vaulthalla.
The installer adds the signed APT repository, installs the `vaulthalla` package with PostgreSQL and nginx, and starts
the services. Upgrades arrive through `apt upgrade`. Guide: [Install On Linux](https://vaulthalla.io/docs/linux/installation).

### macOS

```bash
brew install --cask vaulthalla/tap/vaulthalla
```

Or download `vaulthalla-<version>-arm64.pkg` from the [releases](https://github.com/vaulthalla/vaulthalla/releases) and
run `sudo installer -pkg vaulthalla-<version>-arm64.pkg -target /`. The package is self-contained (it bundles
PostgreSQL, Node and Caddy), sets up a hidden `_vaulthalla` service account and its LaunchDaemons, and enrolls you as
the CLI administrator. It is not signed by Apple yet: opened from Finder it needs **Open Anyway** in System Settings →
Privacy & Security once. Guide: [Install On macOS](https://vaulthalla.io/docs/macos/installation).

## First Run

1. Sign in to the web console as `admin` with the password generated for your install:

   | | Console | Initial password |
   | --- | --- | --- |
   | Linux | `http://<host>/` | `sudo cat /var/lib/vaulthalla/super_admin_initial_password` |
   | macOS | `http://127.0.0.1:36968` | `sudo cat "/Library/Application Support/Vaulthalla/state/super_admin_initial_password"` |

2. Change it with `vh setup set-super-admin-password` (or keep it and delete that file).
3. Serve it over HTTPS:
   - Linux: `sudo vh setup nginx --domain vault.example.com --certbot`
   - macOS: `sudo vh setup caddy --domain vault.home.arpa --trust` for a home-network name with Vaulthalla's own
     certificate authority, or `--domain vault.example.com` for Let's Encrypt.
4. Create a vault, then export its keys before important data goes in.

## Why Vaulthalla

- **Encrypted at rest, always.** Every vault is AES-256-GCM with per-vault keys; master keys are sealed by the host's
  TPM2 on Linux (or a managed software TPM on VPS hosts). Cloud copies can be encrypted before they leave the host.
- **A real filesystem on Linux.** Vaults mount at `/mnt/vaulthalla` through a native FUSE driver, governed by the same
  permissions as everything else.
- **Local or S3-backed storage.** Keep vaults on local disks or sync them to S3-compatible providers such as Cloudflare
  R2, with request budgets and price guardrails so a sync can't run up your bill.
- **S3-compatible gateway.** Serve vaults as buckets to the AWS CLI, rclone, SDKs and backup tools.
- **Identities, RBAC and sharing.** Users, groups and roles with global and per-vault permissions; local accounts map to
  Vaulthalla users for the CLI; public and email-validated share links.
- **CLI and web console.** `vh` for operators and automation, a web console for everyone, both enforcing the same rules.
- **HTTPS in one command.** nginx with Let's Encrypt on Linux; Caddy on macOS with Let's Encrypt, Cloudflare DNS, your
  own certificate, or a name-constrained Vaulthalla CA for internal names.
- **Yours.** No vendor account to run it: the daemon, database and keys live on your hardware.

## What Ships Today

| | Feature |
| --- | --- |
| **Production** | Linux package, systemd services, FUSE mount, TPM2 key sealing, nginx/Certbot integration; encrypted local and S3/R2 vaults; sync (cache, sync, mirror); request and price budgets; RBAC; sharing; S3 gateway; web console; `vh` |
| **New** | macOS: installer package and Homebrew cask, launchd services, bundled PostgreSQL, `vh setup caddy`; `vh fs` for file access over the CLI (the macOS file path until a mount ships) |
| **Experimental** | Hardware video encoding in the optional `vaulthalla-preview-media` package (software encoding is the tested path) |
| **Planned** | A Finder mount on macOS, Secure Enclave key sealing on macOS (macOS keys are currently protected by file permissions and FileVault), an Apple-signed package, a native Mac app |

The full list of platform differences is in [Platform Comparison](https://vaulthalla.io/docs/reference/platforms).

## Status

Vaulthalla moves quickly and releases often. Check the [release notes](RELEASE_NOTES.md) before upgrading. Builds from
source are for development only; production installs use the APT package on Linux and the installer package or
Homebrew cask on macOS. Contributors start at [Development Setup](https://vaulthalla.io/docs/contributors/development-setup).

## Support

Bug reports and pull requests are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md). For install or runtime issues,
include the output of `vh status` and the recent daemon log: `sudo journalctl -u vaulthalla -n 150 --no-pager` on Linux,
`sudo tail -n 150 /Library/Logs/Vaulthalla/vaulthalla.log /Library/Logs/Vaulthalla/server.log` on macOS.

Licensed under the terms in [LICENSE](LICENSE).
