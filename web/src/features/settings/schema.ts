// The config.yaml editor's view of core's Config JSON (core/src/config/Config.cpp to_json/from_json). Keys the schema
// doesn't know still render (generically) and round-trip, so a newer daemon's settings are never hidden or dropped.

export type FieldKind =
  | { kind: 'bool' }
  | { kind: 'int'; unit?: string; min?: number; max?: number }
  | { kind: 'port' }
  | { kind: 'text'; mono?: boolean; placeholder?: string }
  | { kind: 'optionalText'; mono?: boolean; placeholder?: string }
  | { kind: 'enum'; options: { value: string; label: string }[] }
  | { kind: 'bytes' } // integer bytes
  | { kind: 'megabytes' } // integer MB
  | { kind: 'sizeString' } // "50MB" / "1GB"
  | { kind: 'intervalString' } // "24h" / "1d"
  | { kind: 'durationString' } // "30s" / "5m" / "12h" / "90d" / "2w"
  | { kind: 'decimal'; unit?: string }
  | { kind: 'tags'; numeric?: boolean; mono?: boolean }
  | { kind: 'lines'; placeholder?: string }
  | { kind: 'logLevel' }

export interface FieldDef {
  key: string
  label: string
  hint?: string
  type: FieldKind
  restart?: boolean
}

export interface GroupDef {
  key: string
  label: string
  fields: FieldDef[]
}

export interface SectionDef {
  key: string
  label: string
  description: string
  // How a change takes effect, when we know it.
  applies?: string
  restart?: boolean
  warning?: string
  // Managed on another page.
  managedAt?: { href: string; label: string }
  fields: FieldDef[]
  groups?: GroupDef[]
}

const int = (unit?: string, min?: number, max?: number): FieldKind => ({ kind: 'int', unit, min, max })
const bool: FieldKind = { kind: 'bool' }
const host: FieldKind = { kind: 'text', mono: true, placeholder: '0.0.0.0' }

export const LOG_LEVELS = ['trace', 'debug', 'info', 'warn', 'error', 'critical', 'off']

const SUBSYSTEMS = [
  'vaulthalla',
  'filesystem',
  'crypto',
  'cloud',
  'auth',
  'websocket',
  'http',
  'shell',
  'db',
  'sync',
  'thumb',
  'storage',
  'types',
  'runtime',
]

export const SECTIONS: SectionDef[] = [
  {
    key: 'websocket_server',
    label: 'Console API',
    description: 'The WebSocket server the web console and its clients talk to.',
    applies: 'The connection cap applies to new connections right away; the rest after the daemon restarts.',
    warning: 'Turning this off or moving it disconnects this console.',
    fields: [
      { key: 'enabled', label: 'Enabled', type: bool, restart: true },
      { key: 'host', label: 'Listen address', type: host, restart: true },
      { key: 'port', label: 'Port', type: { kind: 'port' }, restart: true },
      {
        key: 'max_connections',
        label: 'Max connections',
        hint: 'Open console and share sockets; more are refused until one closes.',
        type: int(undefined, 1, 1_000_000),
      },
      { key: 'max_upload_size_bytes', label: 'Max upload size', type: { kind: 'bytes' }, restart: true },
    ],
  },
  {
    key: 'http_preview_server',
    label: 'Preview & download server',
    description: 'Serves file previews, thumbnails and HTTP downloads.',
    applies: 'The connection cap applies to new connections right away; the rest after the daemon restarts.',
    fields: [
      { key: 'enabled', label: 'Enabled', type: bool, restart: true },
      { key: 'host', label: 'Listen address', type: host, restart: true },
      { key: 'port', label: 'Port', type: { kind: 'port' }, restart: true },
      {
        key: 'max_connections',
        label: 'Max connections',
        hint: 'Each connection (a preview, download or media stream) has its own thread; more get 503.',
        type: int(undefined, 1, 1_000_000),
      },
      { key: 'max_preview_size_bytes', label: 'Largest file to preview', type: { kind: 'bytes' }, restart: true },
    ],
  },
  {
    key: 's3_gateway',
    label: 'S3 gateway',
    description: 'The S3-compatible endpoint. Keys, buckets and budgets are on the S3 gateway page.',
    applies:
      'Changing Enabled starts or stops the gateway right away; listener settings apply the next time it starts.',
    fields: [
      { key: 'enabled', label: 'Enabled', type: bool },
      { key: 'host', label: 'Listen address', type: host, restart: true },
      { key: 'port', label: 'Port', type: { kind: 'port' }, restart: true },
      { key: 'max_connections', label: 'Max connections', type: int(undefined, 1) },
      { key: 'max_body_size_bytes', label: 'Max request body', type: { kind: 'bytes' } },
      { key: 'require_sigv4', label: 'Require SigV4 signatures', hint: 'Keep on outside development.', type: bool },
      { key: 'allow_path_style', label: 'Path-style requests', type: bool },
      { key: 'allow_virtual_hosted_style', label: 'Virtual-hosted-style requests', type: bool },
      {
        key: 'default_bucket_mode',
        label: 'Default mode for new buckets',
        type: {
          kind: 'enum',
          options: [
            { value: 'local', label: 'Local' },
            { value: 'remote_cache', label: 'Remote cache' },
            { value: 'remote_proxy', label: 'Remote proxy' },
          ],
        },
      },
      { key: 'default_api_exclusive', label: 'New buckets are gateway-only', type: bool },
    ],
    groups: [
      {
        key: 'multipart',
        label: 'Multipart uploads',
        fields: [
          { key: 'min_part_size_mb', label: 'Minimum part size', type: int('MB', 5) },
          { key: 'abort_after_days', label: 'Abort unfinished uploads after', type: int('days', 1) },
        ],
      },
      {
        key: 'synthetic_local_request_cost_usd',
        label: 'Synthetic local request cost',
        fields: [
          { key: 'list', label: 'LIST', type: { kind: 'decimal', unit: 'USD' } },
          { key: 'head', label: 'HEAD', type: { kind: 'decimal', unit: 'USD' } },
          { key: 'get', label: 'GET', type: { kind: 'decimal', unit: 'USD' } },
          { key: 'put', label: 'PUT', type: { kind: 'decimal', unit: 'USD' } },
          { key: 'delete', label: 'DELETE', type: { kind: 'decimal', unit: 'USD' } },
          { key: 'copy', label: 'COPY', type: { kind: 'decimal', unit: 'USD' } },
          { key: 'downloaded_gb', label: 'Per GB downloaded', type: { kind: 'decimal', unit: 'USD' } },
          { key: 'uploaded_gb', label: 'Per GB uploaded', type: { kind: 'decimal', unit: 'USD' } },
        ],
      },
    ],
  },
  {
    // device_server.remote is the only switch operators change (ws device.remote.enable|disable); it is managed with the
    // listener's live status on the Devices page, so this editor never writes the section (port included).
    key: 'device_server',
    label: 'Device listener',
    description: 'Vaulthalla Desktop’s mutual-TLS endpoint: remote connections, listener status and the server key.',
    managedAt: { href: '/devices/all#remote-connections', label: 'Devices' },
    fields: [],
  },
  {
    key: 'caching',
    label: 'Cache & thumbnails',
    description: 'Local cache size and thumbnail generation.',
    fields: [{ key: 'max_size_mb', label: 'Cache size limit', type: { kind: 'megabytes' } }],
    groups: [
      {
        key: 'thumbnails',
        label: 'Thumbnails',
        fields: [
          {
            key: 'formats',
            label: 'File types',
            hint: 'Extensions that get thumbnails.',
            type: { kind: 'tags', mono: true },
          },
          { key: 'sizes', label: 'Sizes', hint: 'Pixel widths to render.', type: { kind: 'tags', numeric: true } },
          { key: 'expiry_days', label: 'Keep thumbnails for', type: int('days', 1) },
        ],
      },
    ],
  },
  {
    key: 'auth',
    label: 'Sign-in sessions',
    description: 'How long access and refresh tokens last.',
    fields: [
      { key: 'access_token_expiry_minutes', label: 'Access token lifetime', type: int('minutes', 1) },
      { key: 'refresh_token_expiry_days', label: 'Refresh token lifetime', type: int('days', 1) },
    ],
  },
  {
    key: 'sharing',
    label: 'Sharing',
    description: 'Which share links can be made and opened.',
    applies:
      'Applies right away, to new links and to links already handed out (they stop opening while their kind is off and work again when it is turned back on).',
    fields: [
      { key: 'enabled', label: 'Sharing', hint: 'Off: no link can be created or opened. Links are kept.', type: bool },
      { key: 'enable_anonymous', label: 'Anyone-with-the-link shares', type: bool },
      {
        key: 'enable_email_validated',
        label: 'Verified-email shares',
        hint: 'Links whose recipients confirm an invited address.',
        type: bool,
      },
    ],
  },
  {
    key: 'vaults',
    label: 'Vaults',
    description:
      'Defaults new vaults start with (existing vaults keep theirs; change those on each vault’s Sync tab), and how long a deleted vault stays restorable. Its encryption key is kept for the key retention window either way.',
    applies: 'Retention windows apply to vaults deleted after the change.',
    fields: [
      { key: 'retention_window', label: 'Restorable for', type: { kind: 'durationString' } },
      {
        key: 'tpm_retention_window',
        label: 'Keep encryption keys for',
        hint: 'Even when a vault is deleted now. Export keys you still need with `vh vault keys export`.',
        type: { kind: 'durationString' },
      },
    ],
    groups: [
      {
        key: 's3',
        label: 'S3/R2 vaults',
        fields: [
          {
            key: 'default_remote_sync_strategy',
            label: 'Sync strategy',
            hint: 'Cache indexes the bucket and fetches files when they are opened.',
            type: {
              kind: 'enum',
              options: [
                { value: 'cache', label: 'Cache' },
                { value: 'sync', label: 'Sync' },
                { value: 'mirror', label: 'Mirror' },
              ],
            },
          },
          {
            key: 'default_remote_conflict_policy',
            label: 'On conflict',
            hint: 'Default for new S3 vaults. Ask records a file changed on both sides as a sync conflict and keeps syncing everything else; that file waits for a decision on the Sync Conflicts page or with vh sync resolve.',
            type: {
              kind: 'enum',
              options: [
                { value: 'keep_local', label: 'Keep local' },
                { value: 'keep_remote', label: 'Keep remote' },
                { value: 'keep_newest', label: 'Keep newest' },
                { value: 'ask', label: 'Ask' },
              ],
            },
          },
          {
            key: 'tpm_retention_window',
            label: 'Keep encryption keys for',
            hint: 'Longer by default: data kept in the bucket stays encrypted with this key.',
            type: { kind: 'durationString' },
          },
        ],
      },
    ],
  },
  {
    key: 'sync',
    label: 'Sync history',
    description: 'How much sync event detail is kept for troubleshooting.',
    fields: [
      { key: 'event_audit_retention_days', label: 'Keep events for', type: int('days', 7) },
      { key: 'event_audit_max_entries', label: 'Keep at most', type: int('events', 1000) },
    ],
  },
  {
    key: 'pricing',
    label: 'Price catalog',
    description: 'S3 price estimates used by cost control.',
    fields: [{ key: 'enabled', label: 'Price estimates', type: bool }],
    groups: [
      {
        key: 'storage_rates_api',
        label: 'Remote rates catalog',
        fields: [
          { key: 'remote_refresh_enabled', label: 'Refresh from the rates API', type: bool },
          { key: 'base_url', label: 'Rates API URL', type: { kind: 'text', mono: true } },
          { key: 'timeout_ms', label: 'Request timeout', type: int('ms', 100) },
          { key: 'cache_ttl_seconds', label: 'Cache catalog for', type: int('seconds', 60) },
          { key: 'refresh_interval_seconds', label: 'Refresh every', type: int('seconds', 60) },
          { key: 'fail_open', label: 'Use the bundled catalog when the API fails', type: bool },
          { key: 'signature_warning_only', label: 'Only warn on signature problems', type: bool },
          {
            key: 'signature_public_key_path',
            label: 'Signature public key',
            type: { kind: 'optionalText', mono: true, placeholder: 'Not set' },
          },
          {
            key: 'fallback_artifact_base_urls',
            label: 'Fallback catalog URLs',
            hint: 'One URL per line.',
            type: { kind: 'lines', placeholder: 'https://…' },
          },
          { key: 'prefer_full_catalog', label: 'Prefer the full catalog', type: bool },
          { key: 'use_remote_estimator_for_debug', label: 'Use the remote estimator (debug)', type: bool },
        ],
      },
    ],
  },
  {
    key: 'stats_snapshots',
    label: 'Health history',
    description: 'Snapshots behind the health trends.',
    fields: [
      { key: 'enabled', label: 'Record snapshots', type: bool },
      { key: 'runtime_interval_seconds', label: 'Runtime snapshot every', type: int('seconds', 1) },
      { key: 'gauge_observation_interval_seconds', label: 'Sample gauges every', type: int('seconds', 1, 60) },
      { key: 'vault_interval_seconds', label: 'Vault snapshot every', type: int('seconds', 300) },
      { key: 'retention_days', label: 'Keep snapshots for', type: int('days', 1) },
    ],
  },
  {
    key: 'services',
    label: 'Background services',
    description: 'Database cleanup and connection housekeeping.',
    restart: true,
    applies: 'Applies after the daemon restarts.',
    fields: [],
    groups: [
      {
        key: 'db_sweeper',
        label: 'Database sweeper',
        fields: [{ key: 'sweep_interval_minutes', label: 'Sweep every', type: int('minutes', 5) }],
      },
      {
        key: 'connection_lifecycle_manager',
        label: 'Connections',
        fields: [
          { key: 'idle_timeout_minutes', label: 'Close idle connections after', type: int('minutes', 5) },
          {
            key: 'unauthenticated_timeout_seconds',
            label: 'Close unauthenticated connections after',
            type: int('seconds', 30),
          },
          { key: 'sweep_interval_seconds', label: 'Check every', type: int('seconds', 15) },
        ],
      },
    ],
  },
  {
    key: 'auditing',
    label: 'Audit & retention',
    description: 'Audit log rotation and how long records are kept.',
    restart: true,
    applies: 'Audit log rotation settings apply after the daemon restarts.',
    fields: [],
    groups: [
      {
        key: 'audit_log',
        label: 'Audit log',
        fields: [
          { key: 'retention_days', label: 'Keep logs for', type: int('days', 1) },
          { key: 'rotate_max_size', label: 'Rotate at', type: { kind: 'sizeString' } },
          { key: 'rotate_interval', label: 'Rotate every', type: { kind: 'intervalString' } },
          {
            key: 'compression',
            label: 'Compression',
            type: {
              kind: 'enum',
              options: [
                { value: 'zstd', label: 'zstd' },
                { value: 'gzip', label: 'gzip' },
                { value: 'none', label: 'None' },
              ],
            },
          },
          { key: 'max_retained_logs_size', label: 'Total size limit', type: { kind: 'sizeString' } },
          {
            key: 'strict_retention',
            label: 'Always keep the full retention period',
            hint: 'Even past the size limit.',
            type: bool,
          },
        ],
      },
      {
        key: 'encryption_waivers',
        label: 'Encryption waivers',
        fields: [{ key: 'retention_days', label: 'Keep for', type: int('days', 1) }],
      },
      {
        key: 'files_trashed',
        label: 'Trash',
        fields: [{ key: 'retention_days', label: 'Keep trashed files for', type: int('days', 1) }],
      },
    ],
  },
  {
    key: 'logging',
    label: 'Logging',
    description: 'Log verbosity for the console output, the log file and each subsystem.',
    restart: true,
    applies: 'Applies after the daemon restarts.',
    fields: [],
    groups: [
      {
        key: 'levels',
        label: 'Levels',
        fields: [
          { key: 'console_log_level', label: 'Console', type: { kind: 'logLevel' } },
          { key: 'file_log_level', label: 'Log file', type: { kind: 'logLevel' } },
        ],
      },
      {
        key: 'levels.subsystem_levels',
        label: 'Subsystems',
        fields: SUBSYSTEMS.map(key => ({ key, label: key, type: { kind: 'logLevel' } as FieldKind })),
      },
    ],
  },
  {
    key: 'database',
    label: 'Database',
    description:
      'PostgreSQL connection. The password is sealed and managed with `vh setup db` / `vh secret`, not here.',
    restart: true,
    applies: 'Applies after the daemon restarts.',
    warning: 'A wrong value here stops the daemon from starting. Prefer `vh setup db` or `vh setup remote-db`.',
    fields: [
      { key: 'host', label: 'Host', type: { kind: 'text', mono: true } },
      { key: 'port', label: 'Port', type: { kind: 'port' } },
      { key: 'name', label: 'Database', type: { kind: 'text', mono: true } },
      { key: 'user', label: 'User', type: { kind: 'text', mono: true } },
      { key: 'pool_size', label: 'Connection pool size', type: int(undefined, 1) },
    ],
  },
  {
    key: 'email',
    label: 'Email delivery',
    description: 'Provider, sender and secrets for operator email.',
    managedAt: { href: '/notifications', label: 'Notifications' },
    fields: [],
  },
  {
    key: 'operator_emails',
    label: 'Operator emails',
    description: 'Recipients, alerts, weekly recap and security notices.',
    managedAt: { href: '/notifications', label: 'Notifications' },
    fields: [],
  },
  {
    key: 'dev',
    label: 'Development',
    description: 'Maintainer-only behaviour.',
    warning: 'Don’t enable development behaviour on a production host.',
    fields: [
      { key: 'enabled', label: 'Development mode', type: bool },
      { key: 'init_r2_test_vault', label: 'Create the R2 test vault at startup', type: bool },
    ],
  },
]
