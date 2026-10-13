---
title: Serve Vaulthalla With Caddy
navTitle: Caddy (macOS)
description: Use vh setup caddy on macOS to serve the console, WebSockets, transfers and the S3 gateway over HTTPS, for internal or public hostnames.
order: 61
status: published
tags:
  - https
  - caddy
  - macos
  - tls
---

# Serve Vaulthalla With Caddy

On macOS, `sudo vh setup caddy` puts Vaulthalla behind HTTPS in one command. It writes a Caddy configuration with the same routes `vh setup nginx` uses on Linux, chooses where the certificate comes from based on the hostname, validates the configuration, starts Caddy as a LaunchDaemon, and checks the result over a verified TLS connection. Caddy renews certificates by itself.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Quick Start

:::tabs{default="internal"}

:::tab[Home or office network]{value="internal"}
```bash
sudo vh setup caddy --domain vault.home.arpa --trust
```

Vaulthalla creates its own certificate authority for `vault.home.arpa`, trusts it on this Mac, and serves `https://vault.home.arpa`. Point the name at the Mac in your router's DNS (or add `--hosts-entry` to test on the Mac itself), and [trust the CA on your other devices](/https/client-trust).
:::

:::tab[Public domain]{value="public"}
```bash
sudo vh setup caddy --domain vault.example.com --email you@example.com
```

Let's Encrypt issues the certificate. `vault.example.com` must resolve to this Mac and ports 80 and 443 must reach it from the internet.
:::

:::tab[Public domain, private host]{value="cloudflare"}
```bash
sudo vh setup caddy --domain vault.example.com --dns-cloudflare /etc/vaulthalla/cloudflare.ini
```

Let's Encrypt validates through Cloudflare DNS, so the Mac needs no inbound ports from the internet. See [Cloudflare DNS](#public-names-through-cloudflare-dns).
:::

:::tab[Your own certificate]{value="files"}
```bash
sudo vh setup caddy --domain vault.home.arpa --cert fullchain.pem --key privkey.pem
```

Uses a certificate you already have, for example from a company CA.
:::

:::

## How The Certificate Source Is Chosen

| You pass | Certificate source |
| --- | --- |
| `--cert` and `--key` | Your files, copied into Caddy's private directory. |
| `--dns-cloudflare <file>` | Let's Encrypt, DNS-01 through Cloudflare. |
| `--internal`, or a hostname ending in `.home.arpa`, `.internal`, `.lan`, `.local`, `.localhost` or `.test` | The Vaulthalla CA. |
| any other hostname | Let's Encrypt, HTTP-01 or TLS-ALPN. |

The settings are saved, so a later `sudo vh setup caddy` with no options re-applies them (after an upgrade, or to regenerate the configuration). Passing a new `--domain` chooses the source again for that name.

Public CAs cannot issue for internal names, so `vh setup caddy` refuses `--email` or `--dns-cloudflare` combined with an internal name rather than trying and failing at Let's Encrypt. It never turns off certificate verification anywhere: every check it runs verifies the certificate chain.

## Internal Names With The Vaulthalla CA

For an internal name, Vaulthalla generates a root certificate authority (EC P-256, valid for 10 years) whose certificate carries critical **X.509 name constraints**: it may only vouch for the hostnames you configured. Caddy uses it to issue an intermediate and short-lived server certificates, and renews both by itself.

Name constraints are what make it safe to trust on your devices. A normal private CA, once trusted, could vouch for any website; current macOS, iOS, Windows, Chrome and Firefox reject this one for any name outside its list, even if its key were stolen.

```bash
sudo vh setup caddy --domain vault.home.arpa                                  # constrained to vault.home.arpa
sudo vh setup caddy --domain vault.home.arpa --s3-domain s3.home.arpa         # both names
sudo vh setup caddy --domain vault.home.arpa --ca-scope home.arpa             # anything under home.arpa
```

Use `--ca-scope` when you expect to add hostnames later: a CA scoped to `home.arpa` covers `photos.home.arpa` too. Without it, configuring a hostname outside the CA's list creates a **new** CA (the old one is kept as `ca.replaced-<date>`), and every device must trust the new one. Vaulthalla never widens an existing CA's constraints.

The CA certificate to install on devices is exported to:

```text
/Library/Application Support/Vaulthalla/vaulthalla-local-ca.crt
```

`vh setup caddy` prints its SHA-256 fingerprint and per-device instructions. The full guide is [Trust The Vaulthalla CA](/https/client-trust). `--trust` adds it to this Mac's System keychain; macOS asks you to confirm.

The private key stays in `/Library/Application Support/Vaulthalla/caddy/ca`, readable only by `_vaulthalla`.

## Public Names With Let's Encrypt

```bash
sudo vh setup caddy --domain vault.example.com --email you@example.com
```

Requirements:

- `vault.example.com` resolves to this Mac's public address.
- Ports 80 and 443 reach the Mac from the internet (port forwarding on your router).
- `--email` is optional; Let's Encrypt uses it for expiry and account notices.

Issuance happens in the background after Caddy starts. `vh setup caddy` waits for a trusted certificate; if issuance is still running when it gives up, it says so instead of failing, and `caddy.log` shows progress. Rehearse with `--acme-staging` to stay clear of Let's Encrypt's rate limits; staging certificates are not trusted by browsers, so the final check is skipped.

### Public Names Through Cloudflare DNS

When the Mac shouldn't or can't be reachable from the internet, prove ownership through DNS instead. Create a Cloudflare API token with **Zone → DNS → Edit** on the zone, and store it in a root-owned, `0600` file in the same format `vh setup nginx --certbot-dns-cloudflare` uses on Linux:

```bash
sudo install -d -m 0700 /etc/vaulthalla
sudo install -m 0600 /dev/null /etc/vaulthalla/cloudflare.ini
sudo nano /etc/vaulthalla/cloudflare.ini        # one line: dns_cloudflare_api_token = <token>
sudo vh setup caddy --domain vault.example.com --dns-cloudflare /etc/vaulthalla/cloudflare.ini
```

Editing the file keeps the token off command lines and out of your shell history.

The file is refused if it isn't owned by root, is readable by anyone else (mode other than `0600` or `0400`), or has no `dns_cloudflare_api_token` line. The token is copied into Caddy's configuration, which only `_vaulthalla` can read, so later renewals don't depend on the file. Rerunning with the file applies a rotated token.

DNS validation needs the Caddy shipped in the package, which includes the Cloudflare module. A source build using Homebrew's Caddy refuses this mode with a clear message.

## Your Own Certificate

```bash
sudo vh setup caddy --domain vault.home.arpa --cert fullchain.pem --key privkey.pem
```

The certificate and key must be PEM, the key unencrypted, the pair must match, and the certificate must cover every configured hostname; `vh setup caddy` checks all of this before changing anything. Both are copied into Caddy's private directory (the key stays `0600`). Caddy does not renew certificates you provide: rerun with new files before the old ones expire. The expiry date is printed when you set it up and by `--status`.

## The S3 Gateway Hostname

```bash
sudo vh setup caddy --domain vault.home.arpa --s3-domain s3.home.arpa
sudo vh setup caddy --s3-domain none          # stop serving it
```

The S3 hostname uses the same certificate source and is routed to the S3 gateway (`s3_gateway.port`, default 39000) with path-style addressing and long timeouts for large objects. Enable the gateway first (`s3_gateway.enabled: true`); until then that hostname answers 502. See [S3 Gateway Setup](/s3-gateway/setup).

## Options

| Option | Effect |
| --- | --- |
| `--domain <name>` | The console hostname. Required the first time. |
| `--s3-domain <name>` | A second hostname for the S3 gateway; `none` removes it. |
| `--internal` | Use the Vaulthalla CA whatever the hostname. |
| `--ca-scope <domain>` | Let the Vaulthalla CA cover `<domain>` and everything under it. |
| `--email <address>` | Let's Encrypt account contact. |
| `--acme-staging` | Let's Encrypt's staging service (rehearsals). |
| `--dns-cloudflare <file>` | Let's Encrypt through Cloudflare DNS. |
| `--cert <file>` `--key <file>` | Your own certificate. |
| `--listen <address>` | Bind ports 80/443 to one address instead of every interface. |
| `--trust` | Trust the Vaulthalla CA on this Mac. |
| `--hosts-entry` | Point the hostname(s) at `127.0.0.1` in this Mac's `/etc/hosts` (a marked line). |
| `--dry-run` | Print the configuration that would be used and change nothing (the Cloudflare token is masked). |
| `--status` | Show the hostnames, certificate source, the certificate being served, and the daemon state. |

## What It Sets Up

| Item | Where |
| --- | --- |
| LaunchDaemon | `sh.vaulthalla.caddy`, running Caddy as `_vaulthalla`. macOS lets an unprivileged process listen on ports 80 and 443. |
| Configuration | `/Library/Application Support/Vaulthalla/caddy/Caddyfile` (`0600`), generated; do not edit it. |
| Certificates, ACME account, the CA | `/Library/Application Support/Vaulthalla/caddy` (`0700`, `_vaulthalla` only). |
| Log | `/Library/Logs/Vaulthalla/caddy.log` (warnings and errors). |

Caddy's admin API is turned off, so no local user can reconfigure the running proxy. Responses carry `Strict-Transport-Security` (one year) and no `Server` header, and plain HTTP on port 80 redirects to HTTPS. A generated configuration is validated by Caddy, as `_vaulthalla`, before it replaces the working one: a configuration that wouldn't load never takes effect.

Package upgrades stop Caddy with the other daemons and start it again with the configuration in place.

## Status, Changes And Removal

```bash
sudo vh setup caddy --status
sudo vh setup caddy                            # re-apply the saved settings
sudo vh teardown caddy                         # stop serving HTTPS; keep certificates and the CA
sudo vh teardown caddy --purge                 # also delete certificates, the ACME account and the CA
```

`teardown` also removes the `--hosts-entry` line. Devices that trusted the Vaulthalla CA keep trusting it until you remove it there: see [Remove Trust](/https/client-trust#remove-trust).

## Troubleshooting

| Message or symptom | Fix |
| --- | --- |
| `port 80 is in use by …` / `port 443 is in use by …` | Another program listens there (a web server, another proxy). Stop it, or use `--listen` to bind to a different address. |
| `… is an internal name: public CAs can't issue for it` | Drop `--email`/`--dns-cloudflare`, or use `--cert`. |
| `the generated configuration didn't validate; nothing was changed` | The lines above say why; the previous configuration keeps running. |
| `didn't answer with a valid certificate` | Check `caddy.log`. For internal names, check the hostname resolves on the Mac (`--hosts-entry`). |
| `not answering with a trusted certificate yet` (public) | Issuance is still running or failing: DNS must point at the Mac and ports 80/443 must reach it, or use `--dns-cloudflare`. |
| The browser warns about the certificate | The device doesn't trust the Vaulthalla CA, or the name isn't one it covers. See [Trust The Vaulthalla CA](/https/client-trust). |

`vh setup caddy` is macOS-only. On Linux it says so and points at [nginx](/https/nginx).
