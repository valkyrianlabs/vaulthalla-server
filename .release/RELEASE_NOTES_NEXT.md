<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Vaulthalla moves to the Valkyrian Labs organization

Vaulthalla's source, issues and roadmap now live under Valkyrian Labs LLC on GitHub:
[valkyrianlabs/vaulthalla-server](https://github.com/valkyrianlabs/vaulthalla-server) and
[valkyrianlabs/vaulthalla-desktop](https://github.com/valkyrianlabs/vaulthalla-desktop). Old `vaulthalla/server` links
redirect. Nothing changes for installs: the APT repository, `apt.vaulthalla.sh` and `brew install --cask
vaulthalla/tap/vaulthalla` keep working.

## S3 gateway behind Cloudflare

The S3 gateway now works through a proxied Cloudflare record with the AWS CLI's CRT transfer client. Cloudflare drops
`Content-Length: 0` from GET, HEAD and DELETE requests that the client signed with it, which failed with
`SignatureDoesNotMatch`; the gateway now treats the missing header as `0` when the request had no body. Every gateway
response also carries `Cache-Control: private, no-store`, so a CDN never caches an object or a presigned GET. See
[Behind Cloudflare Or Another CDN](/s3-gateway/setup#behind-cloudflare-or-another-cdn).

## Parallel uploads no longer exhaust the TPM

Under parallel S3 multipart uploads the daemon could log `Esys_Load failed ... out of memory for object contexts`:
several secrets were unsealed at once, and a TPM without a resource manager in front (the managed swtpm) holds only three
transient objects.
TPM operations now run one at a time, each flushing its objects before the next starts, and a TPM that another process
has momentarily filled is retried a few times instead of failing the request.

## Stats history no longer fills the database

The 5-minute trend rollups behind the health dashboard were kept for 365 days whatever `stats_snapshots.retention_days`
said, and on a busy install they grew to gigabytes. Each rollup tier now has its own setting:
`stats_snapshots.rollup_5m_retention_days` (default 30 days; the dashboard reads this tier only for windows up to 7
days) and `stats_snapshots.rollup_1h_retention_days` (default 365 days). Both are also under **Settings → Health
history**. The first daily purge after upgrading deletes the backlog; PostgreSQL keeps the freed space in the table file,
so [reclaim it once](/reference/configuration#reclaiming-disk-space-after-the-first-purge) with `VACUUM (FULL)` or
`pg_repack` during a maintenance window.

## Clients and servers negotiate a protocol version

The server, the web console and Vaulthalla Desktop release on their own schedules, so a client now starts its
WebSocket session with `meta.hello`. It says which protocol versions it speaks; the server answers its product version,
the protocol version the session will use, the features it has (capabilities such as `fs.entry.metadata_version` or
`device.mcp`) and every command it offers. A client that has no version in common with the server gets a clear
`protocol_unsupported` answer naming the server's range instead of failing on a changed shape later. A paired device's
reported app version now stays current in the device list instead of keeping the version it paired with.

An unknown command now carries the error code `unknown_command` (the message is unchanged). The rules for what may
change within a protocol version are in [WebSocket Protocol](/reference/ws-protocol).
