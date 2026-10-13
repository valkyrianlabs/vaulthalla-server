---
title: CLI Guide
navTitle: CLI
description: Use the Vaulthalla CLI for setup, status, users, roles, vaults, API keys, sync, secrets, pricing budgets, and diagnostics.
order: 100
status: published
tags:
  - cli
  - operator
---

# CLI Guide

The Vaulthalla CLI is installed as `vh` and `vaulthalla`. Both invoke the same local command client. Use `vh` in examples unless you prefer the long command name.

:::toc[On this page]{depth="3" theme="compact"}
:::

## How The CLI Connects

Most CLI commands connect to the local control socket:

| Platform | Socket | Group |
| --- | --- | --- |
| Linux | `/run/vaulthalla/cli.sock` | `vaulthalla` |
| macOS | `/Library/Application Support/Vaulthalla/run/cli.sock` | `_vaulthalla` |

The socket is intended for local operators. Non-root users need membership in the group and an application user mapped to their uid (`vh user create|set --linux-uid`; the option has that name on macOS too).

Root commands are not a replacement for application permissions. A normal operator should use their own account after [First Run](/getting-started/first-run) binds the admin uid (on macOS the installer binds the installing user).

## Help And Status

```bash
vh
vh help
vh help vault
vh help vault sync
vh version
vh status
```

Running a namespace without a subcommand prints help for that namespace:

```bash
vh vault
vh user
vh role
```

### Exit Codes

`vh` fails fast instead of hanging when the daemon is unavailable, and its exit status is safe to use in scripts:

| Exit | Meaning |
|---|---|
| `0` | Success (`vh status`: healthy) |
| `1` | The command failed, for example an unknown vault, user or group (`vh status`: degraded) |
| `2` | Invalid usage (`vh status`: critical, for example the database is unreachable) |
| `69` | The daemon is not running: nothing listens on the control socket |
| `75` | The daemon did not answer in time (default 10s, `VAULTHALLA_CLI_TIMEOUT` overrides) |
| `76` | The daemon sent an unreadable reply |
| `77` | No permission to open the control socket: run with `sudo` or join the `vaulthalla` group |

```bash
vh status >/dev/null || echo "vaulthalla is not healthy"
```

## Lifecycle Commands

Lifecycle commands modify host services and require `sudo`. They run locally and don't need the daemon.

:::tabs{default="linux"}

:::tab[Linux]{value="linux"}
```bash
sudo vh setup db
sudo vh setup remote-db --host <host> --port 5432 --user <user> --database <name> --password-file <path>
sudo vh setup nginx --domain vault.example.com
sudo vh setup nginx --domain vault.example.com --certbot
sudo vh setup nginx --domain vaulthalla.dev --s3-domain s3.vaulthalla.dev --certbot-dns-cloudflare /etc/vaulthalla/certbot/cloudflare.ini
sudo vh teardown nginx
sudo vh teardown db
```

The `--s3-domain` form needs a Cloudflare API token in a root-only credentials file (`dns_cloudflare_api_token = <token>`). See [S3 Gateway Setup](/s3-gateway/setup#create-the-credentials-file).
:::

:::tab[macOS]{value="macos"}
```bash
sudo vh setup caddy --domain vault.home.arpa --trust
sudo vh setup caddy --domain vault.example.com --email you@example.com
sudo vh setup caddy --status
sudo vh teardown caddy
```

The package sets up the database itself; `setup db`, `setup remote-db` and `setup nginx` are Linux commands. `vh setup caddy` on Linux says so and points at nginx. See [Serve Vaulthalla With Caddy](/https/caddy).
:::

:::

For unattended lifecycle automation, use:

```bash
VAULTHALLA_NONINTERACTIVE=1 sudo -E vh setup db
```

or lifecycle options such as `--non-interactive` or `--yes` where available.

## Command Conventions

Vaulthalla accepts both long option forms and normalized `--key=value` forms:

```bash
vh vaults --s3 --limit 5
vh vaults --s3 --limit=5
```

Some resources accept either name or id. For scripts, prefer ids once the resource exists.

Use `--json` on commands that support structured output:

```bash
vh vaults --json
```

## Common Operator Flow

1. Check health:

```bash
vh status
```

2. Create or verify users and roles:

```bash
vh user create alice --role admin
vh group create operators --desc "Operations team"
vh permissions --type vault
```

3. Create an S3 API key if needed:

```bash
vh api-key create r2-main \
  --access <access-key> \
  --secret <secret-key> \
  --provider cloudflare-r2 \
  --endpoint https://<account-id>.r2.cloudflarestorage.com
```

4. Create a vault:

```bash
vh vault create docs --local --quota 50G
vh vault create archive --s3 --api-key r2-main --bucket vaulthalla-archive --sync-strategy cache
```

5. Inspect sync state:

```bash
vh vault sync info archive
vh vault sync dry-run archive
```

6. Export recovery material before storing critical data:

```bash
vh vault keys export all --recipient <gpg-fingerprint> --output vaulthalla-vault-keys.json.gpg
vh secret export all --recipient <gpg-fingerprint> --output vaulthalla-secrets.json.gpg
```

## CLI Security Notes

Treat these outputs as sensitive:

- `vh secret export ...`
- `vh vault keys export ...`
- Any command output that contains provider credentials, tokens, or unencrypted key material.

`vh fs get` writes vault plaintext wherever you point it (or to standard output); `vh fs put` sends the local file's plaintext to the daemon over the control socket, where it is encrypted like a web upload.

Use GPG recipients and files for exports whenever possible. Avoid pasting unencrypted key export output into tickets, chats, terminals with logging, or shell history.

## Reference

Use [Command Reference](/cli/command-reference) for the command families and examples.
