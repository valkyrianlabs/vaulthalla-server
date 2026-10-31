---
title: Uploads And Resumable Transfers
navTitle: Uploads
description: How the web console and share links upload files in resumable parts, what reverse proxies and Cloudflare need, and how the server stores, encrypts, commits and expires uploads.
order: 124
status: published
tags:
  - web-console
  - uploads
  - cloudflare
  - operations
---

# Uploads And Resumable Transfers

On servers that offer resumable uploads (capability `http.upload.resumable`), the web console and share links upload
files in parts. Every part the server acknowledges is stored durably and encrypted, so a dropped connection, a busy
server or a daemon restart costs only the parts in flight, not the whole file. Vaulthalla Desktop uses the same
mechanism over its own direct connection, with larger, adaptively sized parts: see
[Direct Device Connections](/admin/direct-connections).

:::toc[On this page]{depth="3" theme="compact"}
:::

## How The Console Uploads

- **Same origin.** The browser uploads to the origin the console was loaded from, under `/upload`. A console opened
  through a reverse proxy or CDN uploads through it. If the console is behind Cloudflare's proxy, every byte goes
  through Cloudflare.
- **Parts of up to 64 MiB.** The server tells the browser the part size it may use. On the web listener this is
  capped by `transfer.http.max_part_bytes` (64 MiB by default). Files go one after another, with up to three parts of
  a file in flight at once.
- **Integrity.** Over HTTPS, each part carries a SHA-256 `Content-Digest`, and the server refuses a part whose bytes
  don't match. Browsers compute digests only on secure pages, so over plain HTTP parts go without one.
- **Retries.** Busy answers, timeouts and dropped connections are retried with backoff (about ten minutes in all). The
  browser then asks the server which bytes it already holds and sends only the gaps.
- **Older servers.** On a server without the capability, the console falls back to the previous whole-file upload.

When some files of a batch fail, the transfers panel names each file and the reason: it already exists, the vault is
full, the vault key changed (upload it again), and so on.

## Resuming After A Reload

A browser can't keep access to a file across a page reload. To resume, reload the console (or reopen it in the same
tab), then choose the same file again and upload it to the same folder. The console recognizes it by target path,
size and modification time, says "Resuming … already on the server", and sends only what's missing.

- Resume records are kept per browser tab (session storage). A different tab, window or browser starts over.
- The server keeps an unfinished upload for `transfer.session_idle_ttl_hours` (24 hours by default) after its last
  part, and at most `transfer.session_max_age_hours` (7 days) after it began. After that, choosing the file again
  starts a new upload.
- A file that changed since (different size or modification time) is uploaded from the start.

## Share Links

Upload links and links that allow uploads use the same resumable parts, with the link's own limits (maximum upload
size, file count, MIME types and extensions) checked when the upload begins. Share uploads only create files: they
never replace an existing one. The share manager drops a share upload that receives nothing for 6 hours.

## Reverse Proxies

All resumable routes live under `/upload`, which `vh setup nginx` and `vh setup caddy` already route to the HTTP
server with request buffering off. No new location or prefix is needed.

- **nginx:** the managed `/upload` location sets `client_max_body_size 0` and turns request and response buffering
  off. It sets no timeouts of its own, so nginx's 60-second defaults apply (`client_body_timeout`,
  `proxy_send_timeout`, `proxy_read_timeout`). They limit the gap between two reads or writes, not the whole request.
  A part is answered as soon as it is written and flushed, and finishing waits at most about five seconds, because
  the server seals files in the background as their parts arrive and finish no longer re-encrypts anything. The
  defaults are enough.
- **Caddy:** the managed `/upload` route streams with `flush_interval -1` and no read or write timeout.
- **Your own proxy:** allow request bodies at least as large as the part size, and stream them instead of buffering
  whole requests to disk.

## Behind Cloudflare

A console served through a proxied (orange-cloud) Cloudflare record works, with these limits:

- **Request body size.** Cloudflare's documented limits cap each request body by plan: 100 MB on Free and Pro, 200 MB
  on Business, 500 MB by default on Enterprise. A larger request is refused with 413, and the console then reports
  the file as failed. The default 64 MiB part (67,108,864 bytes) fits every plan. Behind Free or Pro, keep
  `transfer.http.max_part_bytes` at or below 95,000,000.
- **Response timeout.** Cloudflare gives the origin about 100 seconds to answer a request (error 524 after that).
  Parts and finish requests answer well within it, and a 524 is retried like any other busy answer.
- **Terms of service.** Cloudflare's service-specific terms restrict using the CDN to serve video or a
  disproportionate share of large files without its paid products. Review Cloudflare's terms before routing bulk file
  transfers through its proxy.

For large or frequent transfers, keep them off the proxy: use Vaulthalla Desktop, which connects directly to the
device listener over a DNS-only name or a VPN ([Direct Device Connections](/admin/direct-connections)), or serve the
console under a DNS-only name. See also
[Cloudflare In Front Of The Console](/https#cloudflare-in-front-of-the-console).

## What The Server Does With An Upload

These rules apply to every resumable upload: browser, share link or Desktop.

- **Space is reserved up front.** Creating an upload checks that its files, plus the bytes promised to the vault's
  other open uploads, fit the vault's free space (its quota, or the disk when it has none). Otherwise the upload is
  refused with "insufficient storage" before any data is sent.
- **Larger files.** A file may be up to 68,719,476,704 bytes (about 64 GiB, the limit of the vault's AES-256-GCM
  format), instead of the 8 GiB of the older upload path. `transfer.max_file_bytes` can set a lower limit.
- **Durable on arrival.** A part is acknowledged only after it is written, flushed to disk and recorded in the
  database. It survives dropped connections and daemon restarts. Resending a part with the same bytes is harmless,
  and a part with different bytes for the same range is refused.
- **Encrypted at rest, never plaintext.** Each part is encrypted with the vault's key as it arrives and stored as
  ciphertext in the upload spool (below). Plaintext exists only in bounded memory buffers.
- **Sealed and committed in the background.** As a file's parts arrive in order, the server re-encrypts them into the
  vault's file format. When the last part lands, a small worker pool (`transfer.commit_workers`, 2 by default) commits
  the file, never a request thread. A file becomes visible only once its bytes are durable. Commit state is in the
  database, so a restart resumes it.
- **Preconditions are checked again at commit.** Permissions are re-checked as they are at that moment. A file that
  appeared at the target while the upload ran is reported (already exists, or changed since), never overwritten or
  silently dropped. If the vault key was rotated during the upload, the file fails with "key changed" and must be
  uploaded again.

### The Upload Spool

| Platform | Path |
| --- | --- |
| Linux | `/var/lib/vaulthalla/.upload-spool/<upload id>/` |
| macOS | `/Library/Application Support/Vaulthalla/state/.upload-spool/<upload id>/` |

The spool is mode `0700`, outside the filesystem mount and every vault tree, and holds ciphertext only: stored parts
and the file being sealed. Nothing else in Vaulthalla reads it (not FUSE, snapshots, versions, archives or sync).
State-directory backups can leave `.upload-spool` out: unfinished uploads are not files yet.
While a file is being sealed, it can take up to about twice the size of its parts not yet sealed, on the state
directory's disk, so leave headroom there for large uploads.

Leftovers are cleaned up on their own: an upload expires `transfer.session_idle_ttl_hours` (24) after its last part,
or `transfer.session_max_age_hours` (168) after it began, and the database janitor then deletes its rows and spool
files. Cancelling an upload deletes them at once (files already committed stay). At startup the daemon removes
incomplete part files and spool directories that no longer belong to an upload.

## Settings

The `transfer:` section of `config.yaml` sets part sizes, parts in flight, file and session limits, commit workers and
expiry. Out-of-range values stop the daemon from starting and are refused in the console. See
[Configuration](/reference/configuration#service-endpoints).
