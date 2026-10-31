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

## Uploads Through nginx

Resumable uploads use paths under `/upload`, which the managed site already routes with `client_max_body_size 0` and request buffering off. The `/upload` location sets no timeouts of its own, so nginx's 60-second defaults apply between successive reads and writes. That is enough: a part is answered once it is stored, and finishing an upload waits at most about five seconds because files are sealed in the background. Nothing needs changing for resumable uploads. See [Uploads](/web-console/uploads#reverse-proxies).

## Share Port 443 With Vaulthalla Desktop

Vaulthalla Desktop normally reaches the node directly on port `36972` ([Direct Device Connections](/admin/direct-connections)). Where that port is blocked, nginx can route a dedicated device host name on port 443 to the device listener with a TLS passthrough. The console keeps its own name on the same port.

The passthrough routes at layer 4: a `stream {}` server reads the server name from the TLS ClientHello (`ssl_preread`) and forwards the encrypted connection unchanged. nginx never decrypts device traffic and needs no certificate for the device name. It can't terminate TLS for that name, because the device protocol's client certificate and pinned server key only work end to end.

Because the `stream {}` server takes port 443, the console's HTTPS servers in `http {}` move to a local port (`127.0.0.1:8443` below), and the stream server routes every other name there. The public hop adds a PROXY protocol header, so the console still sees each client's real address (share rate limits and logs depend on it). The device listener doesn't read PROXY headers, so a second local hop removes the header before the device listener.

:::steps

### Install the stream module

Debian and Ubuntu ship it as a separate package:

```bash
sudo apt install libnginx-mod-stream
```

### Move the console's HTTPS servers off port 443

In `/etc/nginx/sites-available/vaulthalla`, in every server block that has them (the console's, and the S3 host name's if you have one), replace

```nginx
    listen 443 ssl;
    listen [::]:443 ssl;
```

with

```nginx
    listen 127.0.0.1:8443 ssl proxy_protocol;
    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;
```

Leave the port 80 redirect server as it is.

### Add the stream router

Create `/etc/nginx/vaulthalla-stream.conf`, with your device host name in the `map`:

```nginx
stream {
    # Route by the name in the TLS ClientHello; nothing is decrypted here.
    map $ssl_preread_server_name $vaulthalla_tls_route {
        device.example.com  127.0.0.1:8441;   # Vaulthalla Desktop -> device hop below
        default             127.0.0.1:8443;   # the console (and S3 host name) in http {}
    }

    server {
        listen 443;
        listen [::]:443;
        ssl_preread on;
        proxy_pass $vaulthalla_tls_route;
        proxy_protocol on;                    # the console learns the client's address
        proxy_connect_timeout 10s;
        proxy_timeout 1h;
    }

    # Device hop: accepts the PROXY header and passes the TLS stream on untouched.
    server {
        listen 127.0.0.1:8441 proxy_protocol;
        proxy_pass 127.0.0.1:36972;
        proxy_timeout 1h;
    }
}
```

Then include it at the top level of `/etc/nginx/nginx.conf`, outside `http {}`, for example just before the `http {` line:

```nginx
include /etc/nginx/vaulthalla-stream.conf;
```

### Reload and check

```bash
sudo nginx -t && sudo systemctl reload nginx
sudo ss -ltnp 'sport = :443'
sudo tail -n 20 /var/log/nginx/error.log
```

`nginx -t` doesn't catch two servers claiming port 443. If one is left in `http {}`, the reload logs `bind() to 0.0.0.0:443 failed (98: Address already in use)` and nginx keeps running the previous configuration (a full restart would fail).

### Advertise it and publish the name

Add the passthrough to `config.yaml` and restart the daemon:

```yaml
device_server:
  advertise:
    public:
      - {host: device.example.com, port: 443, kind: passthrough}
```

Point `device.example.com` at the host's public address with a **DNS-only** record. A Cloudflare-proxied (orange-cloud) record terminates TLS at Cloudflare and can never carry device connections.

:::

The passthrough reaches the listener over loopback, so it works with remote connections off, and the node sees passthrough devices as `127.0.0.1`. What that means is covered in [TLS Passthrough On Port 443](/admin/direct-connections#tls-passthrough-on-port-443).

:::callout[Rerunning vh setup nginx undoes the move]{variant="warning"}
`sudo vh setup nginx` regenerates the managed site, which writes `listen 443 ssl` back into it. The reload then fails as described above: the running nginx keeps the old configuration, but nginx won't start at all on its next restart or reboot until you move the HTTPS servers to `127.0.0.1:8443` again. Package upgrades never rewrite an existing site file. After anything rewrites the site, check that no server in `http {}` listens on 443.
:::

## Check And Remove

```bash
sudo nginx -t
systemctl status nginx
curl -I https://vault.example.com/
sudo vh teardown nginx
```

`vh teardown nginx` removes the Vaulthalla site and restores the distribution default site if setup disabled it; it leaves unrelated nginx configuration alone. `VH_SKIP_NGINX_CONFIG=1` at install time opts out of automatic nginx setup, and that choice is remembered across upgrades until `vh setup nginx` opts back in.

`vh setup nginx` is a Linux command. On macOS, use [Caddy](/https/caddy).
