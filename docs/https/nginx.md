---
title: Serve Vaulthalla With nginx
navTitle: nginx (Linux)
description: Use vh setup nginx on Linux to put the console behind nginx, with Let's Encrypt over HTTP-01 or Cloudflare DNS-01 and an optional S3 hostname.
order: 63
status: published
tags:
  - https
  - nginx
  - linux
  - tls
---

# Serve Vaulthalla With nginx

On Linux, the Debian package integrates with the distribution's nginx. `sudo vh setup nginx` writes a Vaulthalla-managed site from the runtime configuration, validates it with `nginx -t`, reloads nginx conservatively, and checks that the console answers. With a certificate option it also obtains and renews a Let's Encrypt certificate.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Modes

```bash
sudo vh setup nginx                                   # HTTP, catch-all server name
sudo vh setup nginx --domain vault.example.com        # HTTP for one name
sudo vh setup nginx --domain vault.example.com --certbot
sudo vh setup nginx --domain vault.example.com --s3-domain s3.vault.example.com \
  --certbot-dns-cloudflare /etc/vaulthalla/certbot/cloudflare.ini
```

| Mode | Certificate | Requirements |
| --- | --- | --- |
| No certificate option | None (HTTP) | Use only on a trusted network or behind another TLS terminator. |
| `--certbot` | Let's Encrypt, HTTP-01, through Certbot's nginx plugin | The domain resolves to the host and port 80 reaches it from the internet. |
| `--certbot-dns-cloudflare <credentials>` | Let's Encrypt, DNS-01 through Cloudflare | DNS on Cloudflare and a scoped API token; no inbound ports needed. The only mode that supports `--s3-domain`. |

Package installation may already have run the HTTP mode when nginx was active and the checks were low risk. Running `vh setup nginx` again is safe: it regenerates the managed site and keeps the domain and S3 domain it recorded, so `sudo vh setup nginx --certbot` later adds a certificate for the domain already configured.

## Before It Changes Anything

`vh setup nginx` refuses rather than overwrites when:

- nginx isn't installed, or something other than nginx listens on ports 80/443;
- the domain is already configured in another nginx site;
- `/etc/nginx/sites-available/vaulthalla` exists, differs from the packaged template, and isn't Vaulthalla-managed.

It also checks the built-in `admin` password: if the generated initial password is still in use and its plaintext copy still exists, it offers to change it, delete the file and keep it, continue, or cancel. Without a terminal it warns and continues. Publishing the console with a default credential lying on disk is the mistake this prevents.

## What It Configures

| Item | Path |
| --- | --- |
| Managed site | `/etc/nginx/sites-available/vaulthalla` and its `sites-enabled` symlink |
| Managed marker | `/var/lib/vaulthalla/nginx_site_managed` |
| Certificates | `/etc/letsencrypt/live/<domain>/` (Certbot) |
| Renewal hook (Cloudflare mode) | `/etc/letsencrypt/renewal-hooks/deploy/vaulthalla-nginx-reload.sh` |

Routes are described in [What The Proxy Routes](/https#what-the-proxy-routes). The managed site turns proxy buffering off for `/preview`, `/download` and `/upload`, so decrypted downloads and media streams pass straight through and are never spooled to nginx's temporary files. Upgraded hosts with an older site still stream without buffering because the daemon sends `X-Accel-Buffering: no` on every streamed response.

On a fresh host without `--domain`, the unmodified distribution default site (`/etc/nginx/sites-enabled/default`) would shadow Vaulthalla on port 80, so setup disables that symlink and records it. `apt remove`, `apt purge` and `vh teardown nginx` restore it. A modified default site is never touched.

## Let's Encrypt Over HTTP-01

```bash
sudo vh setup nginx --domain vault.example.com --certbot
```

Setup validates Certbot's prerequisites, issues the certificate with Certbot's nginx plugin, and reloads nginx; if issuance fails it rolls back the low-risk changes it made. Renewals run from Certbot's own timer. Rerunning with `--certbot` when a certificate and HTTPS block already exist takes the renew-safe path.

`--certbot` cannot be combined with `--s3-domain`.

## Cloudflare DNS-01 And The S3 Hostname

```bash
sudo vh setup nginx --domain vault.example.com --s3-domain s3.vault.example.com \
  --certbot-dns-cloudflare /etc/vaulthalla/certbot/cloudflare.ini
```

DNS-01 proves ownership through a temporary TXT record written with the Cloudflare API, so Let's Encrypt never connects to the host: it works on LAN, lab and firewalled hosts. Vaulthalla requests one certificate covering both hostnames, writes both HTTPS server blocks itself and installs a deploy hook that reloads nginx after renewals.

The credentials file is a root-owned, `0600` Certbot file containing `dns_cloudflare_api_token = <token>`. Creating the token and the file, and the error messages, are covered step by step in [S3 Gateway Setup](/s3-gateway/setup#managed-nginx-s3-domain-endpoint). Certbot reads the file on every renewal, so keep it in place; package purge keeps `/etc/vaulthalla/certbot/` for that reason.

## Check And Remove

```bash
sudo nginx -t
systemctl status nginx
curl -I https://vault.example.com/
sudo vh teardown nginx
```

`vh teardown nginx` removes the Vaulthalla site and restores the distribution default site if setup disabled it; it leaves unrelated nginx configuration alone. `VH_SKIP_NGINX_CONFIG=1` at install time opts out of automatic nginx setup, and that choice is remembered across upgrades until `vh setup nginx` opts back in.

`vh setup nginx` is a Linux command. On macOS, use [Caddy](/https/caddy).
