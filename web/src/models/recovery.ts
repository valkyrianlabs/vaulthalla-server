// File recovery: local snapshots, local versions and provider (S3) object versions. What ops::recovery
// (core/include/ops/Recovery.hpp, model core/include/recovery/Model.hpp) returns over recovery.* and vault.recovery.*,
// as core/include/ops/RecoveryJson.hpp serializes it: field names are the C++ member names, optionals are null, times
// are the daemon's timestamp strings (null when never set), enums are their text form. Money is a decimal string in an
// ISO currency, never a JSON number; unknown money is null, never "0". The daemon owns every decision; these are
// display shapes only.

export type RecoveryMode = 'off' | 'local_snapshots' | 'provider_versioning'
export type RecoveryBackend = 'local_snapshot' | 'local_version' | 'provider_version'
export type RecoveryPointKind = 'file' | 'directory'
export type RecoveryItemAction = 'create' | 'overwrite' | 'skip' | 'conflict' | 'remove' | 'unavailable'
export type RecoveryCostBasis = 'observed' | 'scenario' | 'illustrative'
export type RecoveryConfidence = 'high' | 'medium' | 'low' | 'none'
export type RecoveryTime = string | null

// NeedsConfirmation codes (data.code) the recovery ops raise; resend with the matching member once a person accepts.
export const RECOVERY_CODES = {
  versioningDisclosure: 'recovery_versioning_disclosure', // disclosure_token from vault.recovery.disclosure
  versioningUnpriced: 'recovery_versioning_unpriced', // accept_unpriced: true
  retentionShorten: 'recovery_retention_shorten', // accept_retention_shortening: true
  versioningSuspend: 'recovery_versioning_suspend', // confirm: true
  bucketAdoption: 'upstream_adoption', // accept_adoption: true
  pointDelete: 'recovery_point_delete', // confirm: true
  restoreConfirm: 'recovery_restore', // a fresh plan (and its token)
  planExpired: 'recovery_plan_expired', // plan again
  unverifiedVersion: 'recovery_unverified_version', // accept_unverified: true
} as const

export interface Money {
  amount: string // decimal string, e.g. "12.50"
  currency: string // ISO currency, e.g. "USD"
}

export interface RecoveryEncryption {
  encrypted: boolean
  key_version: number // 0 when not encrypted
  key_available: boolean
  key_current: boolean
}

export interface RecoveryRetention {
  // snapshot | keep_last:<n> | max_age_days:<n> | provider_days:<n> | indefinite | unknown
  policy: string
  expires_at: RecoveryTime
  note: string | null
}

export interface RecoveryPoint {
  id: string // snap-<id> | lv-<id> | pv-<id>
  backend: RecoveryBackend
  vault_id: number
  path: string
  original_entry_id: number | null
  kind: RecoveryPointKind
  name: string | null
  created_at: RecoveryTime
  valid_from: RecoveryTime
  valid_until: RecoveryTime
  size_bytes: number | null
  content_hash: string | null
  encryption: RecoveryEncryption
  retention: RecoveryRetention
  estimated_monthly_cost: Money | null
  is_current: boolean
  is_delete_marker: boolean
  origin: string | null // provider: vaulthalla | observed
  reason: string | null // local versions: overwrite | truncate | delete | download | restore | conflict
  upstream_state: string | null // local versions: none | pending | sent | skipped
  storage_class: string | null
  file_count: number | null
  restorable: boolean
  unavailable_reason: string | null
}

export interface RecoveryPointDetail {
  point: RecoveryPoint
  members: RecoveryPoint[] // snapshot: its file generations (first page)
  members_truncated: boolean
  created_by: string | null
  skipped: string[]
}

export interface RecoveryPlanItem {
  source_id: string
  source_path: string
  destination_path: string
  action: RecoveryItemAction
  size_bytes: number | null
  destination_source_id: string | null
  method: string // local_copy | local_reseal | provider_copy | provider_transfer | none
  notes: string[]
}

export interface RecoveryRequestEstimate {
  get_requests: number
  head_requests: number
  put_requests: number
  copy_requests: number
  list_requests: number
  download_bytes: number
  upload_bytes: number
  cost: Money | null
  unpriced_reason: string | null
}

export interface RecoveryPlan {
  id: number
  vault_id: number
  token: string
  source_label: string
  point_in_time: boolean
  at: RecoveryTime
  // true only for a local snapshot; a point-in-time plan is a timestamp-based reconstruction, never atomic.
  atomic: boolean
  consistency_note: string
  destination: string | null
  prune: boolean
  items: RecoveryPlanItem[]
  creates: number
  overwrites: number
  skips: number
  conflicts: number
  removals: number
  unavailable: number
  estimate: RecoveryRequestEstimate
  warnings: string[]
  blockers: string[] // non-empty: restore refused
  created_at: RecoveryTime
  expires_at: RecoveryTime
  state: string // planned | running | done | partial | failed | expired
}

export interface RecoveryItemOutcome {
  destination_path: string
  outcome: string // restored | skipped | conflict | failed | removed | unavailable
  error: string | null
}

export interface RecoveryRestoreResult {
  plan_id: number
  state: string // done | partial | failed
  items: RecoveryItemOutcome[]
  restored: number
  skipped: number
  conflicts: number
  failed: number
  removed: number
  unavailable: number
}

export interface ProviderRetention {
  indefinite: boolean
  days: number | null // null when indefinite
  value: string // "30d" | "indefinite"
}

export interface LocalVersioningPolicy {
  enabled: boolean
  keep_last: number | null
  max_age_days: number | null
  quota_bytes: number | null
}

export interface ProviderVersioningState {
  supported: boolean
  unsupported_reason: string
  provider: string | null
  bucket: string | null
  region: string | null
  storage_class: string | null
  bucket_state: string // managed | adopted | unmanaged | protected | unknown
  status: string // unversioned | enabled | suspended | unknown
  enabled_by_vaulthalla: boolean
  enabled_at: RecoveryTime
  settles_at: RecoveryTime
  checked_at: RecoveryTime
  settled: boolean
  object_lock: boolean | null
  mfa_delete: boolean | null
  retention_mode: string // unset | days | indefinite
  retention_days: number | null
  foreign_noncurrent_rules: string[]
  effective_noncurrent_days: number | null
  warnings: string[]
}

export interface RecoveryBacklog {
  pending_versions: number
  pending_bytes: number
  oldest_pending_at: RecoveryTime
  failing: number
  last_error: string | null
}

export interface RecoveryStoreUsage {
  count: number
  stored_bytes: number
  plaintext_bytes: number
}

export interface RecoveryStatus {
  vault_id: number
  mode: RecoveryMode
  snapshot_quota_bytes: number | null
  cost_alert_monthly: Money | null
  local_versioning: LocalVersioningPolicy
  provider: ProviderVersioningState
  snapshots: RecoveryStoreUsage
  versions: RecoveryStoreUsage
  backlog: RecoveryBacklog
  retained_key_versions: number[]
  warnings: string[]
}

export interface CostFigure {
  expected: Money | null // null: not estimable (see reason)
  low: Money | null
  high: Money | null
  basis: RecoveryCostBasis
  reason: string | null
}

export interface AccumulationPoint {
  month: number
  noncurrent_bytes: number
  monthly_cost: CostFigure
}

export interface RetentionScenario {
  retention: string // "30d" | "90d" | "365d" | "indefinite"
  steady_noncurrent_bytes: number
  monthly_cost: CostFigure
  notes: string[]
}

export interface CostAssumption {
  kind: string // observed | illustrative | provider_rule
  text: string
}

export interface CostCatalog {
  version: string | null
  source: string | null
  verified: boolean
  stale: boolean
  age_seconds: number | null
  note: string | null
}

export interface CostObservation {
  window_days: number
  first_day: string | null
  last_day: string | null
  sufficient: boolean
  put_requests: number
  copy_requests: number
  delete_requests: number
  get_requests: number
  list_requests: number
  first_put_objects: number
  overwrite_objects: number
  deleted_objects: number
  overwritten_bytes: number
  deleted_bytes: number
  uploaded_bytes: number
  overwritten_bytes_per_day: string // decimal string
}

export interface CostCurrent {
  objects: number
  bytes: number
  monthly_storage: Money | null // context only: never part of the versioning surcharge
}

export interface CostHistory {
  known_noncurrent_versions: number
  known_noncurrent_bytes: number
  delete_markers: number
  unknown_size_versions: number
  unaccounted_history: boolean
  inventoried_at: RecoveryTime
}

export interface CostAlert {
  threshold: Money | null
  exceeded: boolean
}

export interface RecoveryCostReport {
  phase: 'pre_activation' | 'active'
  vault_id: number
  priced: boolean
  unpriced_reason: string | null
  provider: string | null
  bucket: string | null
  region: string | null
  storage_class: string | null
  currency: string | null
  catalog: CostCatalog
  confidence: RecoveryConfidence
  confidence_reasons: string[]
  observation: CostObservation
  current: CostCurrent
  history: CostHistory
  pre_activation_monthly: CostFigure
  current_month_to_date: CostFigure
  current_month_projected: CostFigure
  projected_monthly: CostFigure
  accumulation: AccumulationPoint[]
  scenarios: RetentionScenario[]
  recovery_per_gb: CostFigure
  recovery_per_object: CostFigure
  unmodeled: string[]
  assumptions: CostAssumption[]
  retention: string | null
  alert: CostAlert
  computed_at: RecoveryTime
}

export interface RecoveryDisclosure {
  report: RecoveryCostReport
  consequences: string[]
  required_acknowledgements: string[] // NeedsConfirmation codes the enable will ask for
  token: string // vault.recovery.update disclosure_token
  expires_at: RecoveryTime
}

// Request members (ws payloads), as the RecoveryJson readers accept them.
export type ProviderRetentionInput = string | number | { indefinite?: boolean; days?: number }

export interface RecoveryUpdate {
  mode?: RecoveryMode
  provider_retention?: ProviderRetentionInput
  snapshot_quota_bytes?: number // 0 = no snapshot quota
  cost_alert_monthly?: string // decimal string; "" clears it
  local_versioning?: {
    enabled?: boolean
    keep_last?: number | null
    max_age_days?: number | null
    quota_bytes?: number | null
  }
  disclosure_token?: string
  accept_unpriced?: boolean
  accept_retention_shortening?: boolean
  accept_adoption?: boolean
}
