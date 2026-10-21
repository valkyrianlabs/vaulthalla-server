import { PriceBudgetLedgerEntry } from '@/models/pricing/priceBudgetLedger'
import { PriceNotification } from '@/models/pricing/priceNotification'
import { PriceOverride } from '@/models/pricing/priceOverride'
import {
  asBoolean,
  asDateValue,
  asDecimalString,
  asNullableDecimalString,
  asNullableNumber,
  asNullableString,
  asNumber,
  asString,
  asStringArray,
  isRecord,
} from '@/models/pricing/common'

export type PriceBudgetScope = 'global' | 'provider' | 'vault' | 'gateway_credential' | 'gateway_credential_vault'
export type PriceBudgetMode = 'off' | 'report' | 'warn' | 'enforce'
export type PriceBudgetWindow = 'per_run' | 'daily' | 'monthly'
export type PriceBudgetConfidence = 'none' | 'low' | 'medium' | 'high' | string

function asScope(value: unknown): PriceBudgetScope {
  if (
    value === 'provider'
    || value === 'vault'
    || value === 'gateway_credential'
    || value === 'gateway_credential_vault'
  ) {
    return value
  }
  return 'global'
}

function asMode(value: unknown): PriceBudgetMode {
  return value === 'off' || value === 'warn' || value === 'enforce' ? value : 'report'
}

function asWindow(value: unknown): PriceBudgetWindow {
  if (value === 'monthly' || value === 'month') return 'monthly'
  if (value === 'daily' || value === 'day') return 'daily'
  return 'per_run'
}

export interface PriceBudgetPolicyPayload {
  scope: PriceBudgetScope
  provider_key?: string | null
  vault_id?: number | null
  gateway_credential_id?: number | null
  mode: PriceBudgetMode
  currency: string
  max_run_cost?: string | null
  max_daily_cost?: string | null
  max_monthly_cost?: string | null
  require_verified_catalog: boolean
  allow_stale_catalog: boolean
  max_catalog_age_seconds?: number | null
}

export class PriceBudgetPolicy implements PriceBudgetPolicyPayload {
  id: number | null = null
  scope: PriceBudgetScope = 'global'
  provider_key: string | null = null
  vault_id: number | null = null
  gateway_credential_id: number | null = null
  mode: PriceBudgetMode = 'report'
  currency = 'USD'
  max_run_cost: string | null = null
  max_daily_cost: string | null = null
  max_monthly_cost: string | null = null
  require_verified_catalog = true
  allow_stale_catalog = false
  max_catalog_age_seconds: number | null = 43200
  is_active = true

  constructor(input: unknown = {}) {
    const data = isRecord(input) ? input : {}
    this.id = asNullableNumber(data.id)
    this.scope = asScope(data.scope)
    this.provider_key = asNullableString(data.provider_key)
    this.vault_id = asNullableNumber(data.vault_id)
    this.gateway_credential_id = asNullableNumber(data.gateway_credential_id)
    this.mode = asMode(data.mode)
    this.currency = asString(data.currency, 'USD')
    this.max_run_cost = asNullableDecimalString(data.max_run_cost)
    this.max_daily_cost = asNullableDecimalString(data.max_daily_cost)
    this.max_monthly_cost = asNullableDecimalString(data.max_monthly_cost)
    this.require_verified_catalog = asBoolean(data.require_verified_catalog, true)
    this.allow_stale_catalog = asBoolean(data.allow_stale_catalog)
    this.max_catalog_age_seconds = asNullableNumber(data.max_catalog_age_seconds)
    this.is_active = asBoolean(data.is_active, true)
  }

  static from(input: unknown): PriceBudgetPolicy {
    return new PriceBudgetPolicy(input)
  }

  toPayload(): PriceBudgetPolicyPayload {
    return {
      scope: this.scope,
      provider_key: this.provider_key,
      vault_id: this.vault_id,
      gateway_credential_id: this.gateway_credential_id,
      mode: this.mode,
      currency: this.currency,
      max_run_cost: this.max_run_cost,
      max_daily_cost: this.max_daily_cost,
      max_monthly_cost: this.max_monthly_cost,
      require_verified_catalog: this.require_verified_catalog,
      allow_stale_catalog: this.allow_stale_catalog,
      max_catalog_age_seconds: this.max_catalog_age_seconds,
    }
  }
}

export class PriceBudgetWindowCheck {
  policy_id: number | null = null
  scope: PriceBudgetScope = 'global'
  mode: PriceBudgetMode = 'report'
  window: PriceBudgetWindow = 'per_run'
  currency = 'USD'
  limit: string | null = null
  used_before = '0'
  remaining_before = '0'
  requested = '0'
  exceeded = false

  constructor(input: unknown = {}) {
    const data = isRecord(input) ? input : {}
    this.policy_id = asNullableNumber(data.policy_id)
    this.scope = asScope(data.scope)
    this.mode = asMode(data.mode)
    this.window = asWindow(data.window)
    this.currency = asString(data.currency, 'USD')
    this.limit = asNullableDecimalString(data.limit)
    this.used_before = asDecimalString(data.used_before)
    this.remaining_before = asDecimalString(data.remaining_before)
    this.requested = asDecimalString(data.requested)
    this.exceeded = asBoolean(data.exceeded)
  }

  static from(input: unknown): PriceBudgetWindowCheck {
    return new PriceBudgetWindowCheck(input)
  }
}

export class PriceBudgetDecision {
  allowed = true
  stalled = false
  warnings: string[] = []
  exceeded_policy_id: number | null = null
  exceeded_scope: string | null = null
  limit: string | null = null
  used_before: string | null = null
  remaining_before: string | null = null
  requested: string | null = null
  currency = 'USD'
  reason: string | null = null
  policies: PriceBudgetPolicy[] = []
  checks: PriceBudgetWindowCheck[] = []
  blocking_checks: PriceBudgetWindowCheck[] = []
  blocking_policy_ids: number[] = []
  primary_blocking_check: PriceBudgetWindowCheck | null = null
  primary_blocking_scope: string | null = null
  primary_blocking_window: string | null = null

  constructor(input: unknown = {}) {
    const data = isRecord(input) ? input : {}
    this.allowed = asBoolean(data.allowed, true)
    this.stalled = asBoolean(data.stalled)
    this.warnings = asStringArray(data.warnings)
    this.exceeded_policy_id = asNullableNumber(data.exceeded_policy_id)
    this.exceeded_scope = asNullableString(data.exceeded_scope)
    this.limit = asNullableDecimalString(data.limit)
    this.used_before = asNullableDecimalString(data.used_before)
    this.remaining_before = asNullableDecimalString(data.remaining_before)
    this.requested = asNullableDecimalString(data.requested)
    this.currency = asString(data.currency, 'USD')
    this.reason = asNullableString(data.reason)
    this.policies = Array.isArray(data.policies) ? data.policies.map(PriceBudgetPolicy.from) : []
    this.checks = Array.isArray(data.checks) ? data.checks.map(PriceBudgetWindowCheck.from) : []
    this.blocking_checks = Array.isArray(data.blocking_checks) ? data.blocking_checks.map(PriceBudgetWindowCheck.from) : []
    this.blocking_policy_ids = Array.isArray(data.blocking_policy_ids)
      ? data.blocking_policy_ids.map(asNumber).filter(id => id > 0)
      : []
    this.primary_blocking_check = isRecord(data.primary_blocking_check) ? PriceBudgetWindowCheck.from(data.primary_blocking_check) : null
    this.primary_blocking_scope = asNullableString(data.primary_blocking_scope)
    this.primary_blocking_window = asNullableString(data.primary_blocking_window)
  }

  static from(input: unknown): PriceBudgetDecision {
    return new PriceBudgetDecision(input)
  }
}

export class S3PriceEstimate {
  available = false
  supported = false
  stale = false
  estimated_cost: string | null = null
  currency: string | null = null
  price_profile_id: string | null = null
  catalog_version: string | null = null
  catalog_source: string | null = null
  catalog_verified = false
  catalog_age_seconds: number | null = null
  confidence_level: string | null = null
  estimate_mode: string | null = null
  free_tier_policy: string | null = null
  free_tiers_applied: boolean | null = null
  unknowns: string[] = []
  breakdown: unknown = []
  unavailable_reason: string | null = null

  constructor(input: unknown = {}) {
    const data = isRecord(input) ? input : {}
    this.available = asBoolean(data.available)
    this.supported = asBoolean(data.supported)
    this.stale = asBoolean(data.stale)
    this.estimated_cost = asNullableDecimalString(data.estimated_cost)
    this.currency = asNullableString(data.currency)
    this.price_profile_id = asNullableString(data.price_profile_id)
    this.catalog_version = asNullableString(data.catalog_version)
    this.catalog_source = asNullableString(data.catalog_source)
    this.catalog_verified = asBoolean(data.catalog_verified)
    this.catalog_age_seconds = asNullableNumber(data.catalog_age_seconds)
    this.confidence_level = asNullableString(data.confidence_level)
    this.estimate_mode = asNullableString(data.estimate_mode)
    this.free_tier_policy = asNullableString(data.free_tier_policy)
    this.free_tiers_applied = typeof data.free_tiers_applied === 'boolean' ? data.free_tiers_applied : null
    this.unknowns = asStringArray(data.unknowns)
    this.breakdown = data.breakdown ?? []
    this.unavailable_reason = asNullableString(data.unavailable_reason)
  }

  static from(input: unknown): S3PriceEstimate {
    return new S3PriceEstimate(input)
  }
}

export class PriceBudgetTrendStats {
  scope: PriceBudgetScope = 'global'
  provider_key: string | null = null
  vault_id: number | null = null
  gateway_credential_id: number | null = null
  policy_id: number | null = null
  currency = 'USD'
  window_type: 'day' | 'month' | string = 'month'
  window_start: number | string | null = null
  window_end: number | string | null = null
  committed_cost = '0'
  reserved_cost = '0'
  total_cost = '0'
  limit: string | null = null
  remaining: string | null = null
  percent_used = 0
  projected_window_cost: string | null = null
  projected_overage: string | null = null
  predicted_exhaustion_at: number | string | null = null
  confidence: PriceBudgetConfidence = 'none'
  recent_daily_average = '0'
  recent_7d_average = '0'
  recent_30d_average = '0'
  warnings: string[] = []

  constructor(input: unknown = {}) {
    const data = isRecord(input) ? input : {}
    this.scope = asScope(data.scope)
    this.provider_key = asNullableString(data.provider_key)
    this.vault_id = asNullableNumber(data.vault_id)
    this.gateway_credential_id = asNullableNumber(data.gateway_credential_id)
    this.policy_id = asNullableNumber(data.policy_id)
    this.currency = asString(data.currency, 'USD')
    this.window_type = asString(data.window_type, 'month')
    this.window_start = asDateValue(data.window_start)
    this.window_end = asDateValue(data.window_end)
    this.committed_cost = asDecimalString(data.committed_cost)
    this.reserved_cost = asDecimalString(data.reserved_cost)
    this.total_cost = asDecimalString(data.total_cost)
    this.limit = asNullableDecimalString(data.limit)
    this.remaining = asNullableDecimalString(data.remaining)
    this.percent_used = asNumber(data.percent_used)
    this.projected_window_cost = asNullableDecimalString(data.projected_window_cost)
    this.projected_overage = asNullableDecimalString(data.projected_overage)
    this.predicted_exhaustion_at = asDateValue(data.predicted_exhaustion_at)
    this.confidence = asString(data.confidence, 'none')
    this.recent_daily_average = asDecimalString(data.recent_daily_average)
    this.recent_7d_average = asDecimalString(data.recent_7d_average)
    this.recent_30d_average = asDecimalString(data.recent_30d_average)
    this.warnings = asStringArray(data.warnings)
  }

  static from(input: unknown): PriceBudgetTrendStats {
    return new PriceBudgetTrendStats(input)
  }
}

// What pricing.budget.preflight reads: the vault and an optional run id (the daemon plans the sync itself).
export interface PriceBudgetPreflightPayload {
  vault_id: number
  run_uuid?: string
}

export class PriceBudgetPreflightResult {
  decision = new PriceBudgetDecision()
  estimate = new S3PriceEstimate()
  plan: Record<string, number> = {}

  constructor(input: unknown = {}) {
    const data = isRecord(input) ? input : {}
    this.decision = PriceBudgetDecision.from(data.decision)
    this.estimate = S3PriceEstimate.from(data.estimate)
    this.plan = isRecord(data.plan) ? Object.fromEntries(Object.entries(data.plan).map(([key, value]) => [key, asNumber(value)])) : {}
  }

  static from(input: unknown): PriceBudgetPreflightResult {
    return new PriceBudgetPreflightResult(input)
  }
}

export class PriceBudgetStatus {
  policies: PriceBudgetPolicy[] = []
  ledger: PriceBudgetLedgerEntry[] = []
  trends: PriceBudgetTrendStats[] = []
  notifications: PriceNotification[] = []
  overrides: PriceOverride[] = []

  constructor(input: unknown = {}) {
    const data = isRecord(input) ? input : {}
    this.policies = Array.isArray(data.policies) ? data.policies.map(PriceBudgetPolicy.from) : []
    this.ledger = Array.isArray(data.ledger) ? data.ledger.map(PriceBudgetLedgerEntry.from) : []
    this.trends = Array.isArray(data.trends) ? data.trends.map(PriceBudgetTrendStats.from) : []
    this.notifications = Array.isArray(data.notifications) ? data.notifications.map(PriceNotification.from) : []
    this.overrides = Array.isArray(data.overrides) ? data.overrides.map(PriceOverride.from) : []
  }

  static from(input: unknown): PriceBudgetStatus {
    return new PriceBudgetStatus(input)
  }
}
