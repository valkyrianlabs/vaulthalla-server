---
title: Platform Comparison
navTitle: Platforms
description: Every operator-visible difference between Vaulthalla on Linux and on macOS - install, services, paths, database, keys, filesystem, HTTPS and CLI.
order: 690
status: published
tags:
  - reference
  - platform
  - linux
  - macos
---

# Platform Comparison

Vaulthalla is one code base: vault formats, encryption, the database schema, RBAC, sharing, sync, cost controls, the S3 gateway, the web console and the CLI's commands behave the same on both platforms. This page lists where they differ. Everything not listed here is shared.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Support

| | Linux | macOS |
| --- | --- | --- |
| Architecture | amd64 | arm64 (Apple Silicon) |
| Operating system | Ubuntu 24.04 LTS (tested) | macOS 14 Sonoma or later |
| Install | `apt.valkyrianlabs.com` (alias `apt.vaulthalla.sh`) | `vaulthalla-<version>-arm64.pkg`, or the Homebrew casks `valkyrianlabs/tap/vaulthalla` (server + Desktop, macOS 27+) and `valkyrianlabs/tap/vaulthalla-server` |
| Package signing | APT repository signed by the Valkyrian Labs LLC key (`494D71A1EEDDF87BD48E50486D64CB7BDFC30EC6`) | Developer ID (Valkyrian Labs LLC, `ZG2G6V7GLC`) and notarized by Apple, from 1.18.0 |
| Upgrades | `apt upgrade` | Install the newer package, or `brew upgrade --cask vaulthalla` (or `vaulthalla-server`) |
| Removal | `apt remove` / `apt purge` | `uninstall.sh` / `uninstall.sh --purge` |

## Services

| | Linux | macOS |
| --- | --- | --- |
| Manager | systemd | launchd (LaunchDaemons, system domain) |
| Daemon | `vaulthalla.service` | `sh.vaulthalla.server` |
| Web console | `vaulthalla-web.service` | `sh.vaulthalla.web` |
| Database | distribution `postgresql` (or remote) | `sh.vaulthalla.postgres` (bundled) |
| HTTPS proxy | distribution `nginx` | `sh.vaulthalla.caddy` (bundled) |
| Software TPM | `vaulthalla-swtpm.service` when no hardware TPM | none |
| Service account | `vaulthalla` | `_vaulthalla` (hidden, uid 450–499, alias `vaulthalla`) |
| Logs | journald (`journalctl -u vaulthalla`) | `/Library/Logs/Vaulthalla/*.log` |

## Paths

| | Linux | macOS |
| --- | --- | --- |
| Configuration | `/etc/vaulthalla/config.yaml` | `/Library/Application Support/Vaulthalla/config.yaml` |
| State, vault data, sealed secrets | `/var/lib/vaulthalla` | `/Library/Application Support/Vaulthalla/state` |
| CLI socket | `/run/vaulthalla/cli.sock` | `/Library/Application Support/Vaulthalla/run/cli.sock` |
| Mount | `/mnt/vaulthalla` | none |
| Programs | `/usr/bin`, `/usr/lib/vaulthalla`, `/usr/share/vaulthalla` | `/usr/local/bin`, `/usr/local/lib/vaulthalla`, `/usr/local/libexec/vaulthalla`, `/usr/local/share/vaulthalla` |

Full maps: [Runtime Paths](/reference/runtime-paths).

## Database

| | Linux | macOS |
| --- | --- | --- |
| Server | Distribution PostgreSQL 16 (11 or newer works), or a remote server | Bundled PostgreSQL 16 |
| Address | local socket / `localhost:5432`, or remote | `127.0.0.1:36971` |
| Setup | Package postinst, `vh setup db`, `vh setup remote-db` | Package postinstall (`vaulthalla-provision`) |
| Remote database | `vh setup remote-db` | Not automated |

## Keys And Encryption

| | Linux | macOS |
| --- | --- | --- |
| Vault data | AES-256-GCM | AES-256-GCM |
| Master key protection | TPM2: hardware, or the managed software TPM | `file` backend: `0600` files in the `0700` state directory, protected by permissions and FileVault |
| Reported as | the TPM backend | `secrets backend: file (development: no hardware binding)` |

A Secure Enclave or keychain backend for macOS is planned and not shipped. See [Encryption](/vaults/encryption#how-master-keys-are-protected).

## Filesystem

| | Linux | macOS |
| --- | --- | --- |
| Mount | FUSE at `/mnt/vaulthalla`, `multiuser` | None: the server never mounts (`mount.mode` is always `disabled`; Finder access belongs to Vaulthalla Desktop) |
| File access without a mount | web console, `vh fs`, S3 gateway | web console, `vh fs`, S3 gateway |
| HTTP upload staging | through the mount | a private directory under the state root |

See [Filesystem Access](/vaults/filesystem-access).

## HTTPS

| | Linux | macOS |
| --- | --- | --- |
| Command | `sudo vh setup nginx` | `sudo vh setup caddy` |
| Internal names | HTTP only | Vaulthalla CA (name-constrained) |
| Public names | `--certbot` or `--certbot-dns-cloudflare` | Let's Encrypt, or `--dns-cloudflare` |
| Own certificate | not automated | `--cert` / `--key` |

See [HTTPS And Reverse Proxies](/https).

## CLI Access

| | Linux | macOS |
| --- | --- | --- |
| Group | `vaulthalla` | `_vaulthalla` |
| Enroll a user | `sudo usermod -aG vaulthalla <user>` | `sudo dseditgroup -o edit -a <user> -t user _vaulthalla` |
| Admin binding | `vh setup assign-admin` (or the first CLI user at UID 1000+) | The installing user, at install time |
| Lifecycle commands | `setup db`, `setup remote-db`, `setup nginx`, `teardown db`, `teardown nginx` | `setup caddy`, `teardown caddy` |

## Previews

The optional converter packages `vaulthalla-preview-cad` (STEP models) and `vaulthalla-preview-media` (video and audio probing, poster frames, transcodes) are Debian packages and exist only on Linux. On macOS, previews that need them show that the converter isn't installed; images, PDFs, text and browser-playable media preview as usual.
