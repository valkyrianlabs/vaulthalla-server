---
title: S3 Gateway Setup
description: Enable the Vaulthalla S3 Gateway service and choose direct listener or managed Nginx S3-domain endpoints for downstream S3 clients.
order: 10
status: published
tags:
  - s3-gateway
  - setup
  - nginx
  - operator
---

# S3 Gateway Setup

Use this page to enable the S3 Gateway service and choose how downstream S3 clients reach Vaulthalla.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Service Commands

The gateway runtime service is named `S3GatewayService`. Enabling or disabling it updates Vaulthalla config and restarts only the gateway service.

```bash
vh s3-gateway status
vh s3-gateway enable
vh s3-gateway disable
```

`vh s3-gateway status` reports the configured endpoint, readiness, and request counters. Disabling the service does not remove gateway credentials, bucket bindings, or budget policies.

## Config

The gateway is disabled by default:

```yaml
s3_gateway:
  enabled: false
  host: 0.0.0.0
  port: 39000
  max_connections: 1024
  max_body_size_mb: 5120
  require_sigv4: true
  allow_path_style: true
  allow_virtual_hosted_style: true
  default_bucket_mode: local
  default_api_exclusive: true
  multipart:
    min_part_size_mb: 5
    abort_after_days: 7
  synthetic_local_request_cost_usd:
    list: "0.00000001"
    head: "0.00000001"
    get: "0.00000001"
    put: "0.00000001"
    delete: "0.00000001"
    copy: "0.00000001"
    downloaded_gb: "0.00000000"
    uploaded_gb: "0.00000000"
```

Older configuration files also carry `default_remote_sync_strategy` and `default_remote_conflict_policy` here. They were never gateway settings: they are the defaults for new S3/R2 vaults and now live under `vaults.s3` (see [Configuration](/reference/configuration#vault-defaults)). The old keys are still read when the new ones are absent. Remote-cache gateway buckets always use the `cache` strategy with `keep_local`.

`synthetic_local_request_cost_usd` is used only when a gateway credential has `enforce_budget_for_local_requests` enabled. It gives local/cache requests a tiny nominal cost for gateway key budgets without creating provider, vault, or global upstream usage.

## Direct Listener

Use the direct listener for local clients and development:

```bash
aws configure set s3.addressing_style path
aws --endpoint-url http://127.0.0.1:39000 s3api list-buckets
```

The default local URL is:

```text
http://127.0.0.1:39000
```

Keep SigV4 enabled for real client validation. Downstream clients should generally use path-style addressing, especially when they share configuration with the public S3-domain endpoint.

## Managed Nginx S3-Domain Endpoint

Managed Nginx can publish the gateway on its own HTTPS hostname, next to the web console:

```bash
sudo vh setup nginx \
  --domain vaulthalla.example.com \
  --s3-domain s3.vaulthalla.example.com \
  --certbot-dns-cloudflare /etc/vaulthalla/certbot/cloudflare.ini
```

The S3 domain proxies requests to the direct gateway listener and preserves the signed URI. It marks requests as path-style-only so the router does not interpret `s3.vaulthalla.example.com` as a virtual-hosted bucket.

### Why The S3 Domain Needs Cloudflare DNS-01

`--s3-domain` works only with `--certbot-dns-cloudflare <credentials>`. `--certbot` is refused with `--s3-domain requires --certbot-dns-cloudflare <credentials> for managed HTTPS routing`.

With an S3 domain, Vaulthalla writes both HTTPS server blocks itself, so it needs one certificate that covers both hostnames before Nginx is reloaded. The only certificate mode that issues that certificate is `certbot certonly` with Certbot's Cloudflare DNS plugin. `--certbot` hands the HTTPS block to Certbot's Nginx plugin, which edits the site for `--domain` only and has no S3 host to add.

DNS-01 proves domain ownership by writing a temporary TXT record through the Cloudflare API. Let's Encrypt never connects to the host, so the S3 domain works on LAN, lab, and firewalled hosts that have no inbound port 80. The Cloudflare credentials file is where Certbot gets the API token for those TXT records.

### Prerequisites

:::steps
1. Put the DNS zones for both hostnames on Cloudflare. They can be the same zone, as in `vaulthalla.example.com` and `s3.vaulthalla.example.com`.
2. Point both hostnames at the host (`A`/`AAAA` records, or local DNS for LAN-only hosts). Issuance does not need this, but clients do.
3. Install the Certbot plugin: `sudo apt install certbot python3-certbot-dns-cloudflare`. The package recommends it, so it is usually present already.
4. Create a Cloudflare API token: in the Cloudflare dashboard, open **My Profile → API Tokens → Create Token**, choose the **Edit zone DNS** template, and set **Zone Resources** to the zone or zones above. The token needs the **Zone → DNS → Edit** permission.
:::

### Create The Credentials File

The file is a Certbot `dns-cloudflare` credentials file. It holds one setting:

```ini
# /etc/vaulthalla/certbot/cloudflare.ini
dns_cloudflare_api_token = <your Cloudflare API token>
```

`dns_cloudflare_api_token` is the variable name. Certbot also accepts the legacy pair `dns_cloudflare_email` plus `dns_cloudflare_api_key` (the account-wide Global API Key), but a scoped token is safer. Do not put both forms in the file.

Create it root-owned and private, without echoing the token into shell history:

```bash
sudo install -d -m 0700 -o root -g root /etc/vaulthalla/certbot
sudo install -m 0600 -o root -g root /dev/null /etc/vaulthalla/certbot/cloudflare.ini
sudoedit /etc/vaulthalla/certbot/cloudflare.ini
```

`vh setup nginx` refuses the file if it is missing, is not a regular file, or is readable by group or others. Any path works. `/etc/vaulthalla/certbot/cloudflare.ini` is the convention used in these docs. Pass it as the value of `--certbot-dns-cloudflare`. The older two-flag form, `--certbot-dns-cloudflare --cloudflare-credentials <path>`, still works.

:::callout{theme="warning" title="Leave the file in place after setup"}
Certbot records the credentials path in `/etc/letsencrypt/renewal/<domain>.conf` and reads it on every renewal. Moving or deleting the file, or revoking the token, makes the next renewal fail. Package purge keeps `/etc/vaulthalla/certbot/` for this reason.
:::

### Run Setup

```bash
sudo vh setup nginx \
  --domain vaulthalla.example.com \
  --s3-domain s3.vaulthalla.example.com \
  --certbot-dns-cloudflare /etc/vaulthalla/certbot/cloudflare.ini
```

Setup then:

- requests one certificate named after `--domain` that covers both hostnames, or reuses it when it is current and already covers both;
- installs a Certbot deploy hook that reloads Nginx after renewal;
- renders an HTTP to HTTPS redirect for both hostnames, the web console on `--domain`, and the S3 gateway on `--s3-domain`.

The S3 domain is recorded in the managed site, so later runs of `sudo vh setup nginx --certbot-dns-cloudflare <path>` keep it without repeating `--s3-domain`.

### Troubleshooting

| Message | Fix |
|---|---|
| `--s3-domain requires --certbot-dns-cloudflare <credentials> for managed HTTPS routing` | Replace `--certbot` with `--certbot-dns-cloudflare <path>`. |
| `--certbot-dns-cloudflare requires the Cloudflare credentials file path` | Put the file path right after the flag: `--certbot-dns-cloudflare <path>`. |
| `Cloudflare credentials file must not be group/world accessible` | `sudo chmod 0600 <path>` |
| `certbot Cloudflare DNS plugin is not installed` | `sudo apt install python3-certbot-dns-cloudflare` |
| Certbot reports `Either dns_cloudflare_api_token (recommended), or dns_cloudflare_email and dns_cloudflare_api_key are required` | The file has no usable setting. Check the variable name and the `=`. |
| Certbot reports a Cloudflare authentication or zone error | The token is wrong, expired, or lacks **Zone → DNS → Edit** on the zone of one of the hostnames. |

## Path-Style And SigV4

Use path-style URLs for downstream clients:

```text
https://s3.vaulthalla.example.com/archive/reports/report.pdf
```

That shape maps `archive` to the gateway bucket and `reports/report.pdf` to the object key. SigV4 signs the path sent by the client, so reverse proxies must preserve the URI and host behavior expected by the managed S3-domain configuration.

Virtual-hosted style may be accepted by the direct listener when enabled, but path-style is the operational default for public reverse-proxy mode.

### Behind Cloudflare Or Another CDN

A proxied (orange-cloud) Cloudflare record, or any CDN in front of the S3 domain, works with these rules:

- **Bypass the cache for the S3 hostname.** Add a Cache Rule that matches the S3 hostname and sets **Bypass cache**. The gateway also sends `Cache-Control: private, no-store` on every response, including presigned GETs, so a CDN that honors origin headers never stores one; the rule covers CDNs or settings that override origin cache headers.
- **A stripped `Content-Length: 0` is fine.** Cloudflare drops `Content-Length: 0` from bodiless requests (GET, HEAD, DELETE), while the AWS CLI's CRT transfer client signs `content-length`. When a request carries neither `Content-Length` nor `Transfer-Encoding` and no body arrived, the gateway canonicalizes the signed header as `0`, the length the request actually had, as MinIO does. A request that carries a body never gets an implied length.
- **Upload size limits still apply.** Cloudflare caps request bodies by plan (100 MB on Free and Pro). Keep the CLI's multipart part size below the limit, for example `aws configure set default.s3.multipart_chunksize 64MB`.

## Web Console Workflow

Use the browser workflow for interactive setup:

1. Open **S3 gateway** (under Storage & cost) in the web console.
2. Check service readiness and endpoint information.
3. Create a gateway credential.
4. Copy the secret immediately; the secret access key is shown only once.
5. Choose `user_access`, `vault_allowlist`, or `global` scope.
6. For `vault_allowlist`, choose the key default vault role, select vaults, then add per-vault role or path overrides only for exceptions.
7. For `global`, choose the key default vault role; gateway bucket bindings define the vault set.
8. Create or bind a gateway bucket.
9. Set gateway key or key/vault budgets.
10. Copy AWS CLI or MinIO client snippets.
11. Use budget status and ledger views to troubleshoot `AccessDenied` or `SlowDown` responses.

## CLI Workflow

Use the CLI for automation and host-local checks:

```bash
vh s3-gateway status
vh s3-gateway enable
vh s3-gateway disable
```

Credentials:

```bash
vh s3-gateway creds create laptop --json
vh s3-gateway creds list
vh s3-gateway creds revoke VH...
vh s3-gateway creds scope backup show
vh s3-gateway creds scope backup set --scope vault-allowlist
vh s3-gateway creds role assign backup --vault archive --role contributor
vh s3-gateway creds role override add backup --vault archive --pattern "/private/*" --permission download --effect deny
vh s3-gateway creds role override list backup --vault archive
vh s3-gateway creds role revoke backup --vault archive
```

Boolean scope flags and `creds scope allow-vault` are CLI/API shorthand. Gateway authorization uses selected vaults, default vault roles, role exceptions, and path overrides.

Buckets:

```bash
vh s3-gateway bucket list
vh s3-gateway bucket bind photos --vault 12 --mode local
vh s3-gateway bucket create-local archive
vh s3-gateway bucket create-remote-cache edge --api-key r2-main --upstream-bucket origin --encrypt
vh s3-gateway bucket backfill archive
```

Budgets:

```bash
vh s3-gateway budget set-key backup --monthly 5 --mode enforce --currency USD
vh s3-gateway budget set-key-vault backup --vault archive --monthly 2 --mode enforce
vh s3-gateway budget list --key backup
vh s3-gateway budget disable-key backup
vh s3-gateway budget disable-key-vault backup --vault archive
vh s3-gateway budget status --key backup
vh s3-gateway budget ledger --key backup --limit 50
```
