// Upstream control plane (#237) and event-driven sync (#96): what ops::upstream (core/include/ops/Upstream.hpp)
// returns over upstream.*. Field names are the C++ struct member names; times are the daemon's
// "YYYY-MM-DD HH:MM:SS+00" strings (or null). The daemon owns every decision; these are display shapes only.

export type BucketState = 'managed' | 'adopted' | 'unmanaged' | 'protected'
export type Versioning = 'unversioned' | 'enabled' | 'suspended' | 'unknown'
export type BucketMode = 'existing' | 'create' | 'adopt'
export type ForeignObjects = 'import' | 'ignore'

export const BUCKET_STATES: BucketState[] = ['managed', 'adopted', 'unmanaged', 'protected']

// NeedsConfirmation codes (data.code) the upstream ops raise; resend with the matching flag once a person accepts.
export const UPSTREAM_CODES = {
  unprotect: 'upstream_unprotect', // resend with confirm: true
  destructiveLifecycle: 'upstream_destructive_lifecycle', // accept_destructive: true
  adoption: 'upstream_adoption', // provision.accept_adoption: true
  cleanup: 'upstream_cleanup', // a fresh confirm_token from the preflight
} as const

export interface Capability {
  name: string // buckets.list | buckets.create | lifecycle | events.notifications | events.queues | …
  ok: boolean
  probed: boolean // false: not checkable without side effects, `ok` is a best guess
  detail: string
}

export interface AccountIdentity {
  provider: string // aws-s3 | cloudflare-r2
  account_ref: string
  principal: string
}

export interface Capabilities {
  identity: AccountIdentity
  items: Capability[]
  checked_at: string | number | null
}

export interface UpstreamApiKey {
  api_key_id: number
  name: string
  provider: string
  admin_enabled?: boolean
  provider_account_id?: string | null
  has_provider_token?: boolean
  admin_validated_at?: string | null
}

export interface AdminStatus {
  api_key: UpstreamApiKey | null
  supported: boolean
  enabled: boolean
  has_provider_token: boolean
  account_ref: string | null
  capabilities: Capabilities | null
  unsupported_reason: string
}

export interface BucketRow {
  name: string
  region: string | null
  state: BucketState
  ownership: 'managed' | 'adopted' | 'unmanaged' | string
  provisioning_state: string
  is_protected: boolean
  protection_reason: string | null
  protected_by: string | null
  protected_at: string | null
  vault_id: number | null
  vault_name: string | null
  events_state: string | null
  listed: boolean
  last_seen_at: string | null
}

export interface Inventory {
  api_key_id: number | null
  provider: string
  account_ref: string
  buckets: BucketRow[]
  next_token: string
}

export interface LifecycleRule {
  id: string
  enabled: boolean
  prefix: string
  abort_incomplete_multipart_days: number | null
  expire_current_days: number | null
  expire_noncurrent_days: number | null
  foreign: boolean
}

export interface NotificationRule {
  id: string
  destination: string
  destination_name: string
  events: string[]
  prefix: string
  suffix: string
  foreign: boolean
}

export interface BucketConfiguration {
  bucket: string
  region: string | null
  versioning: Versioning
  object_lock: boolean | null
  lifecycle: LifecycleRule[]
  notifications: NotificationRule[]
  lifecycle_readable: boolean
  notifications_readable: boolean
  warnings: string[]
}

export interface Inspection {
  bucket: BucketRow
  config: BucketConfiguration
  supported_lifecycle_fields: string[] // abort_incomplete_multipart_days | expire_current_days | expire_noncurrent_days
}

export interface LifecyclePatch {
  abort_incomplete_multipart_days?: number // 0 = remove
  expire_current_days?: number // 0 = remove; destructive
  expire_noncurrent_days?: number // 0 = remove; destructive; AWS only
  prefix?: string
  clear?: boolean
  accept_destructive?: boolean
}

export interface AdmissionReport {
  bucket: BucketRow
  objects_scanned: number
  bytes_scanned: number
  truncated: boolean
  has_vaulthalla_manifest: boolean
  manifest_vault_id: number | null
  sampled: number
  sampled_vaulthalla_encrypted: number
  sampled_plaintext: number
  sample_keys: string[]
  versioning: Versioning
  object_lock: boolean | null
  blockers: string[]
  warnings: string[]
  recommended_encrypt_upstream: boolean | null
}

// storage.vault.add `provision` (ops::upstream::Provision). mode 'existing' = today's behaviour, no admin calls.
export interface Provision {
  mode: BucketMode
  region?: string
  generate_name?: boolean
  lifecycle?: LifecyclePatch
  events?: boolean
  events_prefix?: string
  accept_adoption?: boolean
}

export interface ChannelStatus {
  provider: string
  account_ref: string
  region: string
  queue_name: string
  state: string // provisioning | active | degraded | failed | removed
  last_poll_at: string | null
  last_message_at: string | null
  last_error_at: string | null
  last_error: string | null
  backlog: number | null
  consecutive_failures: number
}

export interface EventStatus {
  vault_id: number
  vault_name: string
  bucket: string
  supported: boolean
  unsupported_reason: string
  state: string // none | pending | active | failed | removing | removed
  baseline_state: string // none | pending | running | done
  foreign_objects: ForeignObjects | string
  last_error: string | null
  rule_ids: string[]
  foreign_rules: number
  channel: ChannelStatus | null
  inbox_pending: number
  inbox_applied: number
  inbox_failed: number
  inbox_done_24h: number
  inbox_self_24h: number
  last_event_at: string | null
}

export interface CleanupPlan {
  bucket: BucketRow
  objects: number
  versions: number
  delete_markers: number
  bytes: number
  truncated: boolean
  versioning: Versioning
  object_lock: boolean | null
  sample_keys: string[]
  blockers: string[]
  confirm_token: string
  expires_at: string | number
}

export interface CleanupResult {
  outcome: 'deleted' | 'emptied' | 'partial' | 'refused' | string
  deleted: number
  failed: number
  bucket_deleted: boolean
  errors: string[]
}

export interface AuditEntry {
  id: number
  at: string
  user_name: string | null
  action: string
  provider: string
  account_ref: string
  bucket: string
  outcome: 'ok' | 'refused' | 'failed' | 'partial' | string
  api_key_id: number | null
  vault_id: number | null
  // What the action recorded (free-form per action); { raw } when the stored text is not JSON.
  detail: Record<string, unknown>
}

// Providers with an admin adapter (matches s3_provider_from_string spellings in core).
export const ADMIN_PROVIDERS = ['AWS', 'Cloudflare R2'] as const
export const supportsAdmin = (provider: string | null | undefined) => provider === 'AWS' || provider === 'Cloudflare R2'
