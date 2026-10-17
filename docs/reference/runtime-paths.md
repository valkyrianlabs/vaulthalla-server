---
title: Runtime Paths
description: Reference for Vaulthalla configuration, runtime, state, log, mount, SQL, web, proxy, database and key paths on Linux and macOS.
order: 700
status: published
tags:
  - reference
  - paths
  - operations
---

# Runtime Paths

Use this reference when backing up, troubleshooting, or verifying package layout. Linux paths come first; the [macOS](#macos) section maps the same roles onto the Mac's layout. The differences are summarized in [Platform Comparison](/reference/platforms).

:::toc[On this page]{depth="3" theme="compact"}
:::

## Linux

### Core Paths

| Path | Purpose |
| --- | --- |
| `/etc/vaulthalla/config.yaml` | Main runtime configuration. |
| `/run/vaulthalla` | Runtime sockets and transient secrets. |
| `/var/lib/vaulthalla` | Vaulthalla state, local vault bodies, cache/index state (including the encrypted preview cache), and sealed blobs. |
| `/var/lib/vaulthalla/.vh-recovery` | Encrypted local snapshots and local versions ([File Recovery](/vaults/recovery)), one directory per vault. |
| `/var/log/vaulthalla` | Log location where file logging is configured. |
| `/mnt/vaulthalla` | FUSE filesystem mount. |
| `/usr/share/vaulthalla/psql` | Packaged SQL schema and migration assets. |
| `/usr/lib/vaulthalla/helpers` | Optional preview converter helpers from `vaulthalla-preview-cad` and `vaulthalla-preview-media` (`preview.derive.helper_dir`). |
| `/usr/share/vaulthalla-web` | Packaged web runtime. |
| `/var/cache/vaulthalla-web` | Web runtime cache. |

### Services

| Service | Purpose |
| --- | --- |
| `vaulthalla.service` | Core daemon. Owns the CLI socket `/run/vaulthalla/cli.sock`. |
| `vaulthalla-web.service` | Web console runtime. |
| `vaulthalla-swtpm.service` | Managed software TPM fallback. |

### Nginx Paths

| Path | Purpose |
| --- | --- |
| `/usr/share/vaulthalla/nginx/vaulthalla.conf` | Packaged Nginx template. |
| `/etc/nginx/sites-available/vaulthalla` | Managed site configuration. |
| `/etc/nginx/sites-enabled/vaulthalla` | Enabled site symlink. |
| `/var/lib/vaulthalla/nginx_site_managed` | Marker for package-managed Nginx state. |

Use `sudo vh setup nginx` and `sudo vh teardown nginx` instead of editing managed state by hand when possible.

### TPM Paths

| Path | Purpose |
| --- | --- |
| `/dev/tpmrm0` | Preferred hardware TPM resource manager device. |
| `/dev/tpm0` | Hardware TPM fallback device. |
| `/var/lib/swtpm/vaulthalla` | Software TPM state. |

Sealed key blobs are stored in Vaulthalla state. Treat TPM and sealed key state as sensitive backup material.

### CLI Socket

The CLI connects to:

```text
/run/vaulthalla/cli.sock
```

If `vh` fails with a permission error:

```bash
ls -l /run/vaulthalla/cli.sock
id
getent group vaulthalla
systemctl status vaulthalla.service
```

## macOS

### Data And Configuration

Everything that holds data belongs to the hidden `_vaulthalla` account.

| Path | Owner and mode | Purpose |
| --- | --- | --- |
| `/Library/Application Support/Vaulthalla` | `root:wheel 0755` | Service root. |
| `…/config.yaml` | `root:_vaulthalla 0640` | Runtime configuration. Written only when missing. |
| `…/state` | `_vaulthalla 0700` | Vault data (ciphertext), sealed secrets (`file` backend), previews cache, upload staging, local snapshots and versions (`.vh-recovery`), the initial admin password. |
| `…/run` | `_vaulthalla 0750` | The CLI socket `cli.sock` (`0660`, group `_vaulthalla`) and the one-time database password handoff. |
| `…/postgres` | `_vaulthalla 0700` | The bundled PostgreSQL cluster (`data/`) and its socket. |
| `…/caddy` | `_vaulthalla 0700` | After `vh setup caddy`: the Caddyfile, certificates, ACME account and the Vaulthalla CA. |
| `…/vaulthalla-local-ca.crt` | `0644` | The Vaulthalla CA certificate to install on devices (internal names). |
| `…/mount` | `_vaulthalla 0700` | Reserved for a future service-private mount; unused by the package. |
| `…/uninstall.sh`, `…/vaulthalla-provision` | `root:wheel 0755` | Copies kept outside the package receipt so uninstalling still works after the program files are gone. |
| `/Library/Logs/Vaulthalla` | `_vaulthalla 0750` | `vaulthalla.log`, `server.log`, `web.log`, `postgres.log`, `caddy.log`. |

`…` is `/Library/Application Support/Vaulthalla`.

### Programs

| Path | Purpose |
| --- | --- |
| `/usr/local/bin/vh`, `vaulthalla`, `vaulthalla-cli`, `vaulthalla-server` | CLI and daemon. |
| `/usr/local/lib/vaulthalla` | `vaulthalla-provision`, `vaulthalla-caddy`, the lifecycle utility, bundled libraries (`lib*.dylib`). |
| `/usr/local/libexec/vaulthalla/postgresql` | Bundled PostgreSQL 16. |
| `/usr/local/libexec/vaulthalla/node` | Node runtime for the web console. |
| `/usr/local/libexec/vaulthalla/caddy/caddy` | Caddy with the Cloudflare DNS module. |
| `/usr/local/share/vaulthalla` | SQL migrations, configuration and LaunchDaemon templates, libmagic database. |
| `/usr/local/share/vaulthalla-web` | Web console. |
| `/Library/LaunchDaemons/sh.vaulthalla.{server,web,postgres,caddy}.plist` | LaunchDaemons. |

## Network Defaults

| Listener | Default | Platform |
| --- | --- | --- |
| Web runtime | `127.0.0.1:36968` | both |
| WebSocket server | `127.0.0.1:36969` | both |
| HTTP server (previews, downloads, uploads) | `127.0.0.1:36970` | both |
| S3 gateway (disabled by default) | `0.0.0.0:39000` | both |
| Bundled PostgreSQL | `127.0.0.1:36971` | macOS |
| Caddy | `:80`, `:443` (after `vh setup caddy`) | macOS |
| Software TPM | `127.0.0.1:2321` and `127.0.0.1:2322` | Linux |

These listeners are intended for local service wiring and the HTTPS proxy, not direct public exposure. The isolated development instance adds 100 to the Vaulthalla ports.
