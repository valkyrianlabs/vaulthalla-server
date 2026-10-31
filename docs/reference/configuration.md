---
title: Configuration
description: Reference for the main Vaulthalla configuration areas operators commonly need to understand.
order: 710
status: published
tags:
  - reference
  - configuration
  - operations
---

# Configuration

The main configuration file is:

| Platform | Path |
| --- | --- |
| Linux | `/etc/vaulthalla/config.yaml` |
| macOS | `/Library/Application Support/Vaulthalla/config.yaml` |

The keys are the same on both platforms. Installs write the file only when it is missing and upgrades never overwrite it. The daemon reads it at startup: restart it after an edit (`sudo systemctl restart vaulthalla` on Linux, `sudo launchctl kickstart -k system/sh.vaulthalla.server` on macOS).

Most operators should use CLI setup commands for lifecycle changes and edit `config.yaml` only for settings that are intentionally file-based.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Service Endpoints

Common sections:

```yaml
websocket_server:
  enabled: true
  host: 127.0.0.1
  port: 36969
  max_connections: 1024

http_preview_server:
  enabled: true
  host: 127.0.0.1
  port: 36970
  max_connections: 512
  max_preview_size_mb: 512
```

`websocket_server` is the API the web console (and public share pages) talk to through Nginx's `/ws` route. `max_connections` caps open WebSocket connections across all users and share recipients; past the cap, new connections get `503` with `Retry-After` until one closes, and the daemon logs a warning at most once a minute. Each open console tab holds one connection.

`http_preview_server` serves previews, downloads, media playback and text saves behind Nginx's `/preview`, `/download` and `/upload` routes. `max_connections` caps concurrent connections (each runs on its own thread, so a long video stream never blocks other requests); over the cap, new connections get `503` with `Retry-After`. `max_preview_size_mb` is the largest source file the server will render into an image or PDF preview (the shipped file sets 512; without the key the built-in default is 100). See [Rich Previews](#rich-previews).

The web service itself is managed by `vaulthalla-web.service` and normally listens on localhost for Nginx proxying.

The device listener serves Vaulthalla Desktop directly (TLS 1.3 with pinned keys on both sides; no Nginx):

```yaml
device_server:
  enabled: true
  port: 36972
  remote: false
  max_connections: 256
```

It listens on loopback until `remote` is on. Change `remote` with `vh device remote enable|disable` (super admins),
which rebinds the listener at once and writes the value here; there is no host setting. See
[Paired Devices](/admin/devices).

Resumable uploads (`/upload/sessions`, used by Vaulthalla Desktop and the web console when the server offers them)
keep their state across restarts and resume at the byte:

```yaml
transfer:
  part_default_bytes: 67108864   # 64 MiB
  part_min_bytes: 1048576        # 1 MiB
  max_part_bytes: 536870912      # 512 MiB, device listener
  max_parts_in_flight: 4         # per session
  max_file_bytes: 0              # 0 = only the format limit
  max_session_files: 4096
  commit_workers: 2
  session_idle_ttl_hours: 24
  session_max_age_hours: 168
  http:
    max_part_bytes: 67108864     # web listener
```

Behind Cloudflare Free or Pro keep `http.max_part_bytes` at or below 95000000 (Cloudflare refuses request bodies over
100 MB). Values must satisfy `part_min_bytes <= part_default_bytes <= max_part_bytes <= 4 GiB`, `part_min_bytes <=
http.max_part_bytes <= max_part_bytes`, `max_parts_in_flight` 1 to 16 and `commit_workers` 1 to 8; otherwise the
daemon refuses to start and the console refuses the change. A file may be up to 68719476704 bytes (the AES-GCM
limit of the vault format). Parts are encrypted as they arrive and wait in `<state>/.upload-spool/` (ciphertext
only, outside every vault) until the file is sealed and committed; a session expires `session_idle_ttl_hours` after
its last part and at the latest `session_max_age_hours` after it began, and its spool is then removed.

The S3-compatible gateway is a separate runtime service and is disabled by default:

```yaml
s3_gateway:
  enabled: false
  host: 0.0.0.0
  port: 39000
  require_sigv4: true
  allow_path_style: true
  allow_virtual_hosted_style: true
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

See [S3 Gateway Setup](/s3-gateway/setup) before enabling it on a network interface.

`require_sigv4` should stay enabled outside development. When it is disabled, the gateway accepts a development-only auth context only if `dev.enabled` is true or the configured host is loopback. Production listeners should use real gateway credentials with explicit scope and normal Vaulthalla RBAC.

Clients can use the direct listener, or the managed Nginx dedicated S3 hostname:

```bash
aws --endpoint-url http://127.0.0.1:39000 s3api list-buckets
aws configure set s3.addressing_style path
aws --endpoint-url https://s3.vaulthalla.example.com s3api list-buckets
```

The public S3 hostname is path-style reverse-proxy mode. SigV4 signs ordinary S3 paths such as `/bucket/key`; Nginx preserves the signed URI and marks the request as path-style-only so the router does not infer a bucket from the public host. `s3_gateway.multipart.part_dir` is no longer a valid setting; multipart parts use a Vaulthalla-owned hidden backing path with opaque per-upload directories.

`synthetic_local_request_cost_usd` is used only for S3 gateway credentials with local/cache budget enforcement enabled. It gives pure local buckets, metadata hits, cache hits, and sync-deferred gateway writes/deletes a nominal gateway-local cost for `gateway_credential` budgets without touching provider/vault/global upstream budgets.

## Database

The database section controls PostgreSQL connection shape:

```yaml
database:
  host: localhost
  port: 5432
  name: vaulthalla
  user: vaulthalla
  pool_size: 10
```

Use these setup commands rather than editing secrets directly:

```bash
sudo vh setup db
sudo vh setup remote-db --host <host> --user <user> --database <name> --password-file <path>
vh secret set db-password /path/to/password-file
```

## Authentication

Authentication settings include access-token and refresh-token lifetimes:

```yaml
auth:
  access_token_expiry_minutes: 15
  refresh_token_expiry_days: 30
```

Changing token lifetimes affects web and API sessions. Use short access tokens and rotate secrets deliberately.

Both `max_connections` caps are read for every new connection, so a change made in the web console applies at once; the minimum is 1.

## Sharing

Sharing settings decide which share links can be created and opened:

```yaml
sharing:
  enabled: true                # every share link
  enable_anonymous: true       # public links: anyone with the URL
  enable_email_validated: true # links whose recipients verify an invited email address
```

Turning a switch off also stops links of that kind that were already handed out; turning it back on restores them. `enable_email_validated` was called `enable_public_links` before; the old name is still read, with a deprecation warning, and the new name wins if both are set. See [Sharing](/sharing#turning-sharing-off).

## Vault Defaults

New vaults start from these settings when the request doesn't name its own:

```yaml
vaults:
  s3:
    default_remote_sync_strategy: cache
    default_remote_conflict_policy: ask
```

| Key | Default | Meaning |
| --- | --- | --- |
| `vaults.s3.default_remote_sync_strategy` | `cache` | Sync strategy for a new S3/R2 vault created without `--sync-strategy` (or the web form's choice): `cache` indexes the bucket and fetches files when they are opened, `sync` keeps both sides complete, `mirror` makes one side match the other. |
| `vaults.s3.default_remote_conflict_policy` | `ask` | What a new S3/R2 vault does when a file changed on both sides: `ask`, `keep_local`, `keep_remote` or `keep_newest`. With `ask` the conflict is recorded, that file waits for a decision (`vh sync resolve` or the console's Sync Conflicts page) and everything else keeps syncing; see [Sync](/vaults/sync#resolving-conflicts). |

Existing vaults keep their own settings; change them with `vh vault sync update` or the vault's **Sync** tab. An unknown value is a configuration error and the daemon refuses to start until it is fixed. Before these keys moved here they were `s3_gateway.default_remote_sync_strategy` and `s3_gateway.default_remote_conflict_policy`; the old keys are still read (with a deprecation warning) when the new ones are absent, and an invalid old value is ignored. See [Sync Policies](/vaults/sync).

## Pricing And Storage Rates

Pricing configuration controls whether price-budget checks can estimate provider costs:

```yaml
pricing:
  enabled: true

storage_rates_api:
  remote_refresh_enabled: false
  fail_open: true
```

Remote refresh is opt-in. If you enforce price budgets, review catalog freshness policy and verification requirements in [Price Budgets](/cost-control/price-budgets).

S3 gateway per-key budgets use the same price-budget service and pricing catalogs. Remote-backed gateway operations evaluate global, provider, vault, gateway credential, and gateway credential/vault policies before upstream-costing work. Local-only gateway buckets do not consume remote provider price budgets.

## Sync Audit Retention

Sync event audit settings control how long sync event details are retained:

```yaml
sync:
  event_audit_retention_days: 30
  event_audit_max_entries: 10000
```

Short retention reduces database growth but can remove useful sync troubleshooting context.

## Vault Deletion

```yaml
vaults:
  retention_window: 5m           # restorable this long after a delete; then the data is purged
  tpm_retention_window: 90d      # how long a deleted vault's sealed key is kept
  s3:
    tpm_retention_window: 180d   # key retention for S3 vaults (their data may stay in the bucket)
```

Durations take `s`, `m`, `h`, `d` or `w`. Each deletion records its own deadlines, so a change applies to vaults deleted afterwards. "Delete now" skips `retention_window` but never shortens the key retention window. The section is optional: a missing key keeps the default shown here. Settings saved from the web console apply immediately. See [Deleting And Restoring Vaults](/vaults/deleting-vaults).

## Stats Snapshots

Stats snapshot settings control dashboard trend collection and how long its history is kept:

```yaml
stats_snapshots:
  enabled: true
  runtime_interval_seconds: 60
  vault_interval_seconds: 3600
  retention_days: 30
  rollup_5m_retention_days: 30
  rollup_1h_retention_days: 365
```

| Key | Default | Meaning |
| --- | --- | --- |
| `retention_days` | `30` | Snapshot rows (`stats_snapshot`) and raw samples (`stats_*_sample`) older than this are deleted. Minimum 1. |
| `rollup_5m_retention_days` | `30` | 5-minute trend rollups older than this are deleted. Dashboard windows of up to 7 days read this tier, so a value below 7 shortens those charts. Minimum 1. |
| `rollup_1h_retention_days` | `365` | Hourly trend rollups older than this are deleted. Longer dashboard windows (up to 30 days) read this tier. Never less than `rollup_5m_retention_days`; a smaller value is raised to it. |

The daemon purges once a day, starting shortly after it starts. Every key is optional: a missing key keeps the default shown here. Settings saved from the web console (**Settings → Health history**) apply at the next purge.

Earlier releases kept both rollup tiers for 365 days whatever the config said, so the 5-minute tier could grow to most of the database. The first purge after upgrading deletes that backlog, which can take a minute on a large install.

### Reclaiming Disk Space After The First Purge

PostgreSQL does not return the space of deleted rows to the filesystem: autovacuum marks it reusable for new rows, so the table stops growing, but its file stays the same size. To shrink it once after upgrading, rewrite the table during a maintenance window. Check the size first:

```bash
sudo -u postgres psql vaulthalla -c "SELECT pg_size_pretty(pg_total_relation_size('stats_metric_rollup'));"
```

`VACUUM (FULL)` rewrites the table and its indexes. It takes an exclusive lock, so stats writes from the daemon wait until it finishes, and it needs free disk space for a full copy of the table's remaining rows:

```bash
sudo -u postgres psql vaulthalla -c "VACUUM (FULL, ANALYZE, VERBOSE) stats_metric_rollup;"
```

Where `pg_repack` is installed (the `postgresql-<version>-repack` package, and `CREATE EXTENSION pg_repack;` in the database), it does the same rewrite while holding the exclusive lock only briefly at the start and end:

```bash
sudo -u postgres pg_repack --dbname=vaulthalla --table=public.stats_metric_rollup
```

Vaulthalla never runs either one itself. Use your database's name if it isn't `vaulthalla`. You only need to do this once: later purges remove a day's worth of rows at a time, and new rows reuse that space.

Dashboard backup/recovery readiness indicators should be treated as policy/status signals, not proof that backup work has run.

## Rich Previews

Every key in this section is optional. Existing installs need no edits: a missing key keeps the default shown here, and upgrades never rewrite `config.yaml`. The shipped default config lists the `preview` keys commented out. The daemon reads them at startup, so restart the daemon after changing one.

### Derived Cache And Thumbnails

```yaml
caching:
  max_size_mb: 10240
  thumbnails:
    sizes: [128, 256, 512]
    expiry_days: 30
```

| Key | Default | Meaning |
| --- | --- | --- |
| `caching.max_size_mb` | `10240` | Total size of the derived-artifact cache across all vaults: thumbnails, rendered PDF pages and image previews, video posters, converted STEP models and media transcodes. Least-recently-used artifacts are evicted past this size and regenerated on demand. Derived artifacts are encrypted with the vault key and are not charged to vault quotas. |
| `caching.thumbnails.sizes` | `[128, 256, 512]` | File-list thumbnail sizes in pixels. All sizes are rendered from one decode of the source; sizes outside 16 to 2048 are ignored. |
| `caching.thumbnails.expiry_days` | `30` | Derived artifacts not used for this many days are deleted (and regenerated if needed again). |

`caching.thumbnails.formats` is still accepted but no longer consulted: which files get thumbnails is decided per file type by the daemon (raster images and PDFs).

### Preview Settings

```yaml
preview:
  max_render_pixels: 64000000
  media:
    integrity: optimistic      # optimistic | strict
    remote: hydrate            # hydrate | ranged | off
    hwaccel: auto              # auto | software | vaapi | qsv | nvenc
    transcode: on_demand       # off | on_demand
  derive:
    helper_dir: /usr/lib/vaulthalla/helpers
    max_concurrency: 2
    max_queue: 64
    max_ram_mb: 2048
    max_cpu_seconds: 300
    wall_timeout_seconds: 600
    max_output_mb: 512
    failure_ttl_hours: 24
  text:
    max_edit_bytes: 2097152
```

| Key | Default | Meaning |
| --- | --- | --- |
| `preview.max_render_pixels` | `64000000` | Largest image or PDF page (source pixels, checked from the file header before decoding) the server renders. Progressive JPEGs get half this budget, because their decoder buffers the full resolution. Allowed range 1,000,000 to 1,000,000,000. |
| `preview.media.integrity` | `optimistic` | How streamed bytes (downloads, media, models, text) are authenticated. `optimistic` starts serving at once and verifies the whole file's AES-GCM tag once per file version in the background; if verification fails, every stream of that version is cut off and later requests are refused until the file changes. `strict` verifies before the first byte is sent, which delays the start of large files. |
| `preview.media.remote` | `hydrate` | How the HTTP lanes read a file in an S3/R2 vault whose bytes are not stored locally. `hydrate` fetches the whole object once (counted against the vault's request and price budgets), verifies it and keeps the encrypted local copy. `ranged` fetches only the requested ranges, pinned to the object version; those bytes are not authenticated per range. `off` never fetches: such files answer "content unavailable". File-list thumbnails never fetch remote content under any setting. |
| `preview.media.hwaccel` | `auto` | Encoder for media transcodes. `auto` tries VAAPI, Quick Sync (`qsv`) and NVENC and falls back to software (libx264) on any failure; `software` never uses hardware; `vaapi`, `qsv` and `nvenc` prefer that encoder and still fall back to software. Hardware encoding has not been validated on real GPUs in this release. |
| `preview.media.transcode` | `on_demand` | `on_demand` lets users convert media their browser can't play (needs `vaulthalla-preview-media`). `off` disables server-side transcoding. |
| `preview.derive.helper_dir` | `/usr/lib/vaulthalla/helpers` | Where the optional converter helpers (`vaulthalla-preview-cad`, `vaulthalla-preview-media`) are installed. Set it in `config.yaml` only: the web console and CLI settings writes refuse to change it. A helper runs only if it and every directory above it are owned by root and not writable by group or others; a missing or untrusted helper makes that conversion report "converter unavailable". |
| `preview.derive.max_concurrency` | `2` | Conversions running at once (1 to 64). |
| `preview.derive.max_queue` | `64` | Conversions waiting to run (1 to 100000). Past this, new requests get "busy" until the queue drains. |
| `preview.derive.max_ram_mb` | `2048` | Address-space limit per conversion process (256 MiB minimum). |
| `preview.derive.max_cpu_seconds` | `300` | CPU-time limit per conversion process. |
| `preview.derive.wall_timeout_seconds` | `600` | A conversion still running after this many seconds is killed. |
| `preview.derive.max_output_mb` | `512` | Largest artifact a conversion may produce (for example a GLB or a transcode). |
| `preview.derive.failure_ttl_hours` | `24` | A failed conversion is not retried for this long, or until the file changes (0 to 8760). |
| `preview.text.max_edit_bytes` | `2097152` | Largest text file (and save body) the text editor may save, in bytes (1 KiB to 256 MiB). The web console opens text files up to 2 MiB regardless. |

Numeric values outside their allowed range are clamped. An unknown value for one of the `preview.media` choices is a configuration error, and the daemon refuses to start until it is fixed.

The converters run as separate, sandboxed processes from optional packages; see [Optional Preview Packages](/linux/installation#optional-preview-packages). If previews fail but downloads work, see [General Troubleshooting](/troubleshooting/general-troubleshooting#previews-and-media).

## Operator Email

Operator email sections configure provider and recipients:

```yaml
email:
  enabled: true
  provider: resend
  from: "Vaulthalla <ops@example.com>"
  base_url: "https://vault.example.com"

operator_emails:
  enabled: true
```

See [Operator Emails](/admin/operator-emails).

## Filesystem Mount

```yaml
mount:
  mode: multiuser   # disabled | service_private | multiuser
```

`mount.mode` records which filesystem mount the operator intends. When the key is absent the build's default applies: `multiuser` on Linux (the FUSE mount at `/mnt/vaulthalla`), and `disabled` on macOS, where the server never mounts vaults (Finder access belongs to Vaulthalla Desktop). `service_private` is reserved for a mount only the service account uses and no platform provides it. On macOS, `multiuser` and `service_private` run as `disabled` with a `[config]` warning in the log rather than stopping the daemon. Any other value stops the daemon at startup rather than becoming a different mode. `vh status` shows the configured mode and the actual state side by side. See [Filesystem Access](/vaults/filesystem-access).

## Development Settings

Development settings are not production controls:

```yaml
dev:
  enabled: false
```

Do not enable development behavior on production hosts unless a maintainer-specific procedure requires it.
