---
title: Vaulthalla On Linux
navTitle: Linux Overview
description: What the Debian package installs and runs on Linux, which hosts are supported, and where Linux differs from macOS.
order: 40
status: published
tags:
  - linux
  - platform
  - operator
---

# Vaulthalla On Linux

Linux is Vaulthalla's original and most complete platform. The `vaulthalla` Debian package installs the daemon, the web console, the `vh` CLI, systemd units, a lifecycle utility, the SQL migrations and an nginx template, and sets up PostgreSQL, TPM-backed key protection and nginx when it can do so safely. Upgrades arrive through `apt`.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Supported Hosts

| Requirement | Supported |
| --- | --- |
| Architecture | amd64 (x86-64) with AES and PCLMUL instructions |
| Distribution | Ubuntu 24.04 LTS (tested); other Debian-family releases with systemd may work but are not validated |
| Install channel | `apt.valkyrianlabs.com`, also served as `apt.vaulthalla.sh` (signed by the Valkyrian Labs LLC key); the package depends on libraries published only there |
| Key protection | A hardware TPM2 (`/dev/tpmrm0` or `/dev/tpm0`) or the packaged software TPM (`swtpm`) |
| Database | PostgreSQL 11 or newer, local (set up automatically) or remote |
| Filesystem | FUSE 3 for the `/mnt/vaulthalla` mount |

## What Runs

| Unit | Role |
| --- | --- |
| `vaulthalla.service` | The daemon. Owns the CLI socket `/run/vaulthalla/cli.sock` and the FUSE mount at `/mnt/vaulthalla`. |
| `vaulthalla-web.service` | The web console, on `127.0.0.1:36968`. |
| `vaulthalla-swtpm.service` | The software TPM, only on hosts without a hardware TPM. |
| `nginx` | The distribution's nginx, with a Vaulthalla-managed site (see [nginx](/https/nginx)). |
| `postgresql` | The distribution's PostgreSQL, when the database is local. |

The daemon runs as the `vaulthalla` system user. Operators use `vh` from their own Linux accounts, as members of the `vaulthalla` group mapped to a Vaulthalla user by UID.

## What Only Linux Has Today

- **The FUSE mount.** Vaults appear under `/mnt/vaulthalla` as a real filesystem with the same permissions as everywhere else. See [Filesystem Access](/vaults/filesystem-access).
- **TPM2 key sealing.** Master keys are sealed by the host TPM, or by a managed `swtpm` on hosts without one. See [Encryption](/vaults/encryption).
- **nginx integration and lifecycle commands.** `vh setup db`, `vh setup remote-db` and `vh setup nginx` manage the distribution's PostgreSQL and nginx.
- **Optional preview converters.** `vaulthalla-preview-cad` (STEP models) and `vaulthalla-preview-media` (video and audio) are Debian packages.

[Platform Comparison](/reference/platforms) lists every difference.

## Next Steps

- [Install on Linux](/linux/installation)
- [Administer the Linux service](/linux/administration)
- [Serve Vaulthalla over HTTPS with nginx](/https/nginx)
- [Linux Troubleshooting](/linux/troubleshooting)
