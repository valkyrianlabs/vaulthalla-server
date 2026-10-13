---
title: HTTPS And Reverse Proxies
navTitle: HTTPS Overview
description: How Vaulthalla is served over HTTPS on Linux (nginx) and macOS (Caddy), for private-network and public deployments.
order: 60
status: published
tags:
  - https
  - tls
  - operator
---

# HTTPS And Reverse Proxies

Vaulthalla's own listeners (web console, WebSocket server, HTTP transfer server) bind to `127.0.0.1` and speak plain HTTP. A reverse proxy in front of them terminates TLS, serves one hostname, and routes each path to the right listener. Vaulthalla configures that proxy for you with one command per platform.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Pick Your Path

:::cards{columns="2" cardTheme="muted"}

:::card[nginx on Linux]{href="/https/nginx" linkScope="title" eyebrow="vh setup nginx"}
The Debian package's integration with the distribution's nginx. HTTP only, Let's Encrypt over HTTP-01 (`--certbot`), or Cloudflare DNS-01 with a dedicated S3 hostname.
:::

:::card[Caddy on macOS]{href="/https/caddy" linkScope="title" eyebrow="vh setup caddy"}
The package's bundled Caddy, run as the service account. A Vaulthalla CA for internal names, Let's Encrypt or Cloudflare DNS-01 for public ones, or your own certificate.
:::

:::

| | Linux: `vh setup nginx` | macOS: `vh setup caddy` |
| --- | --- | --- |
| Proxy | Distribution nginx | Caddy bundled in the package |
| Runs as | nginx's own user | `_vaulthalla` (unprivileged; macOS allows it :80/:443) |
| Internal names (`vault.home.arpa`) | HTTP only (no managed internal CA) | Vaulthalla CA, name-constrained to your hostnames |
| Public names, reachable host | `--certbot` (HTTP-01) | Let's Encrypt (HTTP-01 / TLS-ALPN), the default |
| Public names, host behind NAT | `--certbot-dns-cloudflare <credentials>` | `--dns-cloudflare <credentials>` |
| Your own certificate files | Not automated | `--cert` and `--key` |
| S3 gateway hostname | `--s3-domain` (with Cloudflare DNS-01) | `--s3-domain` (any certificate source) |
| Renewal | certbot's timer, nginx reloaded by a deploy hook | Caddy, automatically |
| Remove | `sudo vh teardown nginx` | `sudo vh teardown caddy [--purge]` |

The Cloudflare credentials file is the same on both: a root-owned `0600` file containing `dns_cloudflare_api_token = <token>`.

## Internal Or Public

**Internal deployments** use a name only your network resolves, such as `vault.home.arpa` (the name reserved for home networks), `vault.internal` or `vault.lan`. No public certificate authority can issue for these names, so the certificate comes from a CA you control and each client device trusts it once. On macOS, `vh setup caddy` creates and manages that CA; see [Trust The Vaulthalla CA](/https/client-trust).

**Public deployments** use a domain you own, such as `vault.example.com`, with a certificate from Let's Encrypt that every device already trusts. Either the host is reachable from the internet on ports 80/443 (HTTP-01 / TLS-ALPN), or you prove domain ownership through DNS (Cloudflare DNS-01) and the host can stay private.

:::callout[Never expose the internal listeners]{variant="warning"}
Do not publish ports 36968, 36969 or 36970 directly, or forward them from a router. They are plain HTTP and expect the proxy in front of them. Only the proxy's ports 80 and 443 belong on a network. The S3 gateway, when enabled, listens on `0.0.0.0:39000` by default; behind a proxy hostname, set `s3_gateway.host: 127.0.0.1` in [Configuration](/reference/configuration).
:::

## What The Proxy Routes

Both integrations generate the same routes:

| Path | Goes to | Notes |
| --- | --- | --- |
| `/ws` | WebSocket server (`127.0.0.1:36969`) | Upgraded connections for the console. |
| `/preview`, `/download`, `/upload` | HTTP server (`127.0.0.1:36970`) | Streamed both ways: decrypted downloads and uploads are never buffered to disk by the proxy. |
| everything else | Web console (`127.0.0.1:36968`) | |
| the S3 hostname (optional) | S3 gateway (`s3_gateway.port`, default 39000) | Path-style requests; long timeouts for large objects. |

The proxy passes the original `Host` and sets `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Real-IP`.
