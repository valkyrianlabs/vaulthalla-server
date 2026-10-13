---
title: General Troubleshooting
description: Diagnose common Vaulthalla CLI, web, vault, sync, S3/R2, encryption, sharing, cost-control, and backup issues.
order: 810
status: published
tags:
  - troubleshooting
  - operations
---

# General Troubleshooting

Use this guide after Vaulthalla is installed but an operator workflow is failing. Problems with the install itself, the services, the database or HTTPS are platform-specific: see [Linux Troubleshooting](/linux/troubleshooting) and [macOS Troubleshooting](/macos/troubleshooting).

:::toc[On this page]{depth="3" theme="compact"}
:::

## Fast Triage

:::tabs{default="linux"}

:::tab[Linux]{value="linux"}
```bash
vh status
systemctl status vaulthalla.service
systemctl status vaulthalla-web.service
journalctl -u vaulthalla.service -n 200
```
:::

:::tab[macOS]{value="macos"}
```bash
vh status
sudo launchctl print system/sh.vaulthalla.server | grep -E 'state|last exit'
sudo launchctl print system/sh.vaulthalla.web | grep -E 'state|last exit'
sudo tail -n 200 /Library/Logs/Vaulthalla/vaulthalla.log
```
:::

:::

For vault sync:

```bash
vh vault sync info <vault>
vh vault sync dry-run <vault>
```

For permissions:

```bash
vh user info <user>
vh vault role list <vault>
vh permissions --type vault
```

## CLI Permission Error

On Linux, check:

```bash
id
getent group vaulthalla
ls -l /run/vaulthalla/cli.sock
```

If group membership was just changed, refresh the session with `newgrp vaulthalla` or log out and back in. Then confirm the Vaulthalla user has the expected Linux UID mapping. On macOS, see [vh Says Permission Denied](/macos/troubleshooting#vh-says-permission-denied).

## Web Login Works But Pages Are Empty

Check the core daemon and WebSocket path:

```bash
systemctl status vaulthalla.service
journalctl -u vaulthalla.service -n 200
sudo nginx -t
```

If the dashboard loads but filesystem or vault data does not, check the user's admin role, vault role, and group membership.

If the console keeps showing its reconnecting state and the journal has `Connection limit (websocket_server.max_connections = N) reached`, every WebSocket slot is taken (each open console tab and public share page holds one). Close idle tabs or raise `websocket_server.max_connections`.

## Previews And Media

Start with the basics:

- The user's vault role (or the share link's operations) allows what the file needs. Image and PDF previews need `preview`; originals, video and audio, 3D models, text and STEP models need `download`. A preview-only share link refuses those by design. See [File Previews](/web-console/previews).
- `http_preview_server.enabled` is true and Nginx proxies `/preview`, `/download` and `/upload` to it (`sudo nginx -t`).
- The daemon can read the file: try downloading it as a user with known vault access.

Then search the daemon log for the failing request:

```bash
journalctl -u vaulthalla.service -n 500 | grep -Ei 'HttpHandler|IntegrityRegistry|DerivedStore|HttpServer'
```

### Converter Unavailable

The console says "The 3D converter isn't installed" or "Server-side conversion isn't available", and the HTTP response is `503` with `"code": "converter_unavailable"` and the helper it needs. Install the optional package; no restart is needed:

```bash
sudo apt install vaulthalla-preview-cad      # STEP/STP models
sudo apt install vaulthalla-preview-media    # Convert for playback, posters, media probing
ls -l /usr/lib/vaulthalla/helpers/
```

If the package is installed, check that `preview.derive.helper_dir` (default `/usr/lib/vaulthalla/helpers`) points at it and that its version matches `vaulthalla` exactly. The daemon also reports a helper as unavailable, and logs why once, when:

- The helper, or any directory above it, is not owned by root or is writable by group or others. Packaged helpers always pass; a hand-copied helper may not.
- The helper refused to run because it could not sandbox itself. Helpers require Landlock and seccomp; on a kernel without Landlock (or with it left out of the `lsm=` boot parameter) every conversion reports `converter_unavailable`.

```bash
journalctl -u vaulthalla.service | grep -E 'refusing to run converter helper|refuses to run'
cat /sys/kernel/security/lsm    # must list landlock
```

### STEP Conversion Or Media Transcode Failed

"This model could not be converted" or "The conversion failed" (HTTP `422`, `"code": "conversion_failed"` with a reason) means the helper rejected the file, ran out of a limit, or crashed. The failure is cached: the same file version is not retried until it changes or `preview.derive.failure_ttl_hours` (24 by default) passes, so a malformed or hostile file can't cause a retry storm. Typical reasons are a malformed or unsupported file, or a `preview.derive` limit (memory, CPU time, wall clock, output size) that a large model or long video exceeded. Raise the specific limit if the file is legitimate, then save a new version of the file or wait for the failure to expire.

"The server is busy" (HTTP `503` with `Retry-After`) means the conversion queue (`preview.derive.max_queue`), the render slots, or `http_preview_server.max_connections` are full. It clears on its own.

### Content Unavailable For Cloud Files

A file in an S3/R2 vault whose bytes are only in the bucket (not cached locally) answers `503` with `"code": "content_unavailable"` when the server may not fetch it: `preview.media.remote` is `off`, or the vault's request or price budget refused the fetch. Check the budgets with `vh vault sync info <vault>` and `vh pricing budget status`, or change `preview.media.remote`. File-list thumbnails never fetch remote-only files, so those rows simply have no thumbnail.

### Integrity Failures

Vault files are authenticated with AES-GCM. A stream that fails the check stops, and the log shows `AES-GCM verification FAILED for file:<vault id>:<file id> — streams aborted` (and `Integrity failure serving …` for the request, which answers `500` with `"code": "integrity_failed"`).

- With `preview.media.integrity: optimistic` (the default), a stream starts at once and the whole file is verified once in the background; a failure cuts off every stream of that file version, so a browser may have received part of the file before it stopped.
- With `strict`, nothing is sent until the file has verified, so a corrupt file never starts streaming.

Either way, once a file version has failed, the daemon refuses it until the file changes (a restart verifies it again from scratch). A failure means the stored ciphertext does not match its key and IV: disk corruption, an out-of-band edit of the backing file, or a restore that mixed files and database rows from different points in time. Do not overwrite it blindly; restore the file from a backup and see [Backup And Recovery](/vaults/backup-and-recovery).

### Nginx Buffering On Upgraded Hosts

The managed Nginx site on fresh installs sets `proxy_buffering off` and `proxy_max_temp_file_size 0` on `/preview` and `/download`. Upgrades never rewrite an existing site, so older sites don't have those lines; streaming still works because the daemon sends `X-Accel-Buffering: no` on every streamed response, which tells Nginx not to buffer it. If you run a hand-written site or a different proxy, make sure it doesn't buffer `/download` and `/preview` responses to disk, since those contain decrypted file content.

## S3/R2 Vault Cannot Connect

Inspect the API key and vault:

```bash
vh api-key info <key>
vh vault info <vault>
vh vault sync dry-run <vault> --refresh-index
```

Check:

- Endpoint URL is correct.
- Provider value matches the service.
- Bucket exists.
- Credentials allow required bucket/object operations.
- Region is correct or `auto` is appropriate.
- Request and price budgets are not blocking the operation.

## Sync Stalled

A stalled sync is often protective behavior. Start with:

```bash
vh vault sync info <vault>
vh vault sync dry-run <vault>
```

Common stall causes:

- Request budget exceeded.
- Price budget enforcement denied the run.
- Remote index is stale.
- Manifest conflict repeated.
- Archive-tier object needs provider restore.
- Missing encryption metadata for an encrypted remote object.
- Conflict policy requires operator decision.

Raise only the limit or fix only the condition named in the stall reason.

## Remote Index Is Stale

Options:

```bash
vh vault sync dry-run <vault> --refresh-index
vh vault sync inventory <vault> --file inventory.csv
vh vault sync events <vault> --file s3-events.json
vh vault sync reconcile <vault> --allow-list-scan
```

For large buckets, prefer inventory plus event ingestion over repeated full scans.

## Cost Control Blocks Work

Request budget:

```bash
vh vault sync info <vault>
vh vault sync dry-run <vault>
vh vault sync set <vault> --s3-budget-get 2000
```

Price budget:

```bash
vh pricing budget status
vh pricing budget ledger --limit 50
vh pricing budget set-vault <vault> --mode warn --max-run 1
```

Do not switch to unlimited until a dry-run proves the operation is intentional and bounded by some other control.

## Encrypted S3 Object Cannot Be Read

Check:

- Upstream object metadata includes Vaulthalla encryption metadata.
- The vault key version exists.
- The remote index is current.
- The object was not overwritten outside Vaulthalla without preserving metadata.
- The vault was not switched between encrypted and unencrypted behavior without a migration plan.

If key material may be missing, stop and preserve current PostgreSQL, `/var/lib/vaulthalla`, bucket data, and any key exports before attempting repair.

## Share Link Does Not Work

Check:

- The share is still enabled.
- Sharing is allowed for that kind of link: "Sharing is disabled on this server" (or "Anonymous share links are disabled" / "Email-verified share links are disabled") means the operator turned the matching `sharing` switch off. See [Turning Sharing Off](/sharing#turning-sharing-off).
- The URL was copied at create or rotate time.
- The recipient completed email validation if required.
- Operator email is healthy for email-validated shares.
- The share role includes the needed operation.
- The underlying vault object still exists.

Email checks:

```bash
vh email doctor
vh email history --limit 100
```

## Backup Readiness Looks Wrong

Dashboard backup/recovery indicators are status and policy signals. They do not prove that a database dump, state archive, key export, or bucket backup has run.

Use [Backup And Recovery](/vaults/backup-and-recovery) to build and test a real recovery set.

## Before Manual Repair

Before direct database edits, state deletion, or bucket rewrites:

1. Stop affected services if needed.
2. Back up PostgreSQL.
3. Back up `/etc/vaulthalla`.
4. Back up `/var/lib/vaulthalla`.
5. Back up `/var/lib/swtpm/vaulthalla` if using software TPM.
6. Export vault keys and internal secrets where possible.

Manual repair without recovery material can convert a recoverable fault into data loss.
