---
title: Vault Read Grants
navTitle: Read Grants
description: Hand a backup orchestrator read-only credentials for one vault, through the S3 gateway and straight from its upstream bucket, delivered only as an OpenPGP message to a key you pinned.
order: 258
status: published
tags:
  - vaults
  - backup
  - s3-gateway
  - backblaze-b2
  - openpgp
---

# Vault Read Grants

A read grant gives a backup or disaster-recovery tool what it needs to read one vault from two places: through
Vaulthalla's S3 gateway while this server runs, and directly from the vault's upstream bucket if this server is lost.
Vaulthalla creates both credentials and hands them over only as an OpenPGP message encrypted to a public key you pinned
beforehand. No person, agent, log line or API response sees the secrets in plaintext.

:::toc[On this page]{depth="3" theme="compact"}
:::

## What a grant contains

One `issue` creates:

- **An S3 gateway credential** that can only read this vault: scope `vault-allowlist`, the built-in `reader` role, the
  vault selected. It acts as the account that issued it, so it never reaches further than that account does.
- **A read-only upstream key** limited to the vault's bucket, created with the provider account key the vault already
  uses. On Backblaze B2 that is a native application key restricted to the bucket, with the capabilities
  `listBuckets`, `listFiles` and `readFiles` only: never `listAllBucketNames`, writing, deleting or key management.

Both go into one JSON document with everything a client needs (gateway endpoint, bucket and addressing style; upstream
endpoint, region, bucket, key id and secret; the vault's id and name; the grant id and issue time; whether the objects
upstream are stored readable). The document is encrypted to one or two pinned recipients and returned as an
ASCII-armored OpenPGP message. Vaulthalla records the grant (ids only, and the armored message), never a secret.

| Vault | What you get |
| --- | --- |
| Backblaze B2, upstream encryption off | Gateway credential and B2 read key |
| Upstream encryption on | Refused: the bucket's objects are unreadable without this server's keys. `--gateway-only` issues the gateway half alone |
| Local vault (no bucket) | Refused unless you pass `--gateway-only` |
| AWS S3, Cloudflare R2, other providers | Not supported for the upstream half yet; `--gateway-only` works |

The vault must be exposed by the S3 gateway (`vh s3-gateway bucket bind`). The upstream key is created with the
vault's API key, which must be enabled for provider administration (`vh upstream admin enable <key>`), and on B2 it
must hold the `writeKeys` capability; without it the grant is refused and says so.

## Pin a recipient

A recipient is an OpenPGP public key, pinned by its full 40-digit fingerprint. Pinning is the privileged step: super
admins only, with a step-up of the secrets family in the web console (the host CLI is exempt, as for every secret
operation). Agents (`vh mcp`) are refused.

```bash
vh vault read-grant recipient add --fingerprint A6A1752984DFB0DB38DD235D2096C49D7A8F000A \
  --keyserver https://keys.valkyrianlabs.com --label Sentinel
vh vault read-grant recipient add --fingerprint <fingerprint> --key-file recipient.asc
vh vault read-grant recipient list
vh vault read-grant recipient remove <fingerprint>
```

`--keyserver` fetches `/vks/v1/by-fingerprint/<fingerprint>` from the server you name (https only); `--key-file` is
read by `vh` on your side (`-` reads standard input). Either way the key must hash to the fingerprint you typed, or
nothing is pinned: a name or e-mail address is never enough. A key that is revoked, expired, has no user ID or has no
valid encryption subkey is refused, and the message says which. Removing a recipient only stops new grants to it.

## Issue, list and revoke

```bash
vh vault read-grant issue <vault> --recipient <fingerprint> [--recipient <fingerprint>] [--gateway-only] [--json]
vh vault read-grant list [--vault <vault>] [--all] [--json]
vh vault read-grant show <grant> [--ciphertext] [--json]
vh vault read-grant revoke <grant> [--json]
```

Issuing needs the vault permission `vault.sync.action.read_grants` on that vault (no built-in role carries it; grant it
in a vault role) and being able to list and read the vault yourself. It needs no step-up: the result is useless to
anyone but the recipient. Without `--json`, `issue` prints the armored message alone on standard output, so it can be
piped straight to `gpg --decrypt` on the recipient's machine; with `--json` the message is in `ciphertext`. A
service account on the same host calls it through the local CLI socket like any other account.

A vault holds at most `vaults.read_grants.max_per_vault` grants that are not revoked (default 4), so a loop can't mint
provider keys without bound.

`revoke` deletes the gateway credential and the upstream key. If the provider refuses or fails to delete the key, the
grant stays `revocation_incomplete`, the command fails, and running it again retries. An API key that created the
upstream keys of grants that are not revoked can't be removed.

## Configuration

```yaml
vaults:
  read_grants:
    max_per_vault: 4          # 1 to 32
    gateway_endpoint: ""      # the S3 gateway URL written into grants, e.g. https://s3.example.com
```

Set `gateway_endpoint` to the HTTPS name clients reach the gateway by (the `--s3-domain` of `vh setup nginx`). Left
empty, grants name the direct listener, `http://<s3_gateway.host>:<s3_gateway.port>`.

## The grant document

```json
{
  "type": "vaulthalla.vault-read-grant",
  "version": 1,
  "grant_id": "79y1x7s0pkawdszr14d2pf2dbr",
  "issued_at": "2026-11-24T12:00:00Z",
  "issued_by": "sentinel",
  "recipients": ["A6A1752984DFB0DB38DD235D2096C49D7A8F000A"],
  "vault": {"id": 12, "name": "finance", "uid": "…"},
  "gateway": {
    "endpoint": "https://s3.example.com", "region": "us-east-1", "bucket": "finance",
    "addressing_style": "path", "access_key_id": "…", "secret_access_key": "…",
    "credential_id": 31, "access": "read"
  },
  "upstream": {
    "provider": "backblaze-b2", "endpoint": "https://s3.us-west-004.backblazeb2.com", "region": "us-west-004",
    "bucket": "vl-finance", "bucket_id": "…", "addressing_style": "path",
    "access_key_id": "…", "secret_access_key": "…", "key_name": "vh-read-79y1x7s0pkawdszr14d2pf2dbr",
    "capabilities": ["listBuckets", "listFiles", "readFiles"],
    "objects_readable": true, "storage_layout": "transparent"
  }
}
```

A gateway-only grant has `"upstream": null` and `upstream_omitted` set to `local_vault`, `upstream_encrypted` or
`gateway_only`.

## Requirements

GnuPG (`gpg`) must be installed on the server: the Debian package depends on `gpg` and the macOS cask on Homebrew's
`gnupg`. Vaulthalla runs it in a throwaway directory that holds only the recipients' public keys, never starts an
agent, and passes the document over a pipe.
