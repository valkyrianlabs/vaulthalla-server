import {
  asDateValue,
  asDecimalString,
  asNullableDecimalString,
  asNullableNumber,
  asNullableString,
  asNumber,
  asString,
  isRecord,
} from '@/models/pricing/common'

export type PriceOverrideStatus = 'requested' | 'approved' | 'denied' | 'expired' | 'used' | 'cancelled'

function asOverrideStatus(value: unknown): PriceOverrideStatus {
  return value === 'approved' || value === 'denied' || value === 'expired' || value === 'used' || value === 'cancelled'
    ? value
    : 'requested'
}

function asNumberArray(value: unknown): number[] {
  return Array.isArray(value) ? value.map(item => asNumber(item, Number.NaN)).filter(Number.isFinite) : []
}

export interface PriceOverrideRequestPayload {
  vault_id: number
  run_uuid?: string | null
  reason?: string | null
  // The enforce policies to override; the server refuses an empty or missing list.
  policy_ids: number[]
  estimated_cost?: string | null
  currency?: string
  ttl_minutes?: number
}

export class PriceOverride {
  id = 0
  run_uuid: string | null = null
  vault_id = 0
  requested_by: number | null = null
  approved_by: number | null = null
  status: PriceOverrideStatus = 'requested'
  reason: string | null = null
  scope = 'single_run'
  policy_ids: number[] = []
  estimated_cost: string | null = null
  currency = 'USD'
  expires_at: number | string | null = null
  created_at: number | string | null = null
  decided_at: number | string | null = null
  used_at: number | string | null = null

  constructor(input: unknown = {}) {
    const data = isRecord(input) ? input : {}
    this.id = asNumber(data.id)
    this.run_uuid = asNullableString(data.run_uuid)
    this.vault_id = asNumber(data.vault_id)
    this.requested_by = asNullableNumber(data.requested_by)
    this.approved_by = asNullableNumber(data.approved_by)
    this.status = asOverrideStatus(data.status)
    this.reason = asNullableString(data.reason)
    this.scope = asString(data.scope, 'single_run')
    this.policy_ids = asNumberArray(data.policy_ids)
    this.estimated_cost = asNullableDecimalString(data.estimated_cost)
    this.currency = asString(data.currency, 'USD')
    this.expires_at = asDateValue(data.expires_at)
    this.created_at = asDateValue(data.created_at)
    this.decided_at = asDateValue(data.decided_at)
    this.used_at = asDateValue(data.used_at)
  }

  static from(input: unknown): PriceOverride {
    return new PriceOverride(input)
  }

  estimatedCostText(): string {
    return `${asDecimalString(this.estimated_cost)} ${this.currency}`
  }
}
