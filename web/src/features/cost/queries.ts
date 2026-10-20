'use client'

import { useMemo } from 'react'
import { useWs, invalidate } from '@/lib/query'
import { api } from '@/lib/session'
import { notify } from '@/components/ui/Toast'
import { useSession } from '@/lib/session'
import { isSuperAdminUser } from '@/lib/permissions'
import {
  toLedger,
  toNotification,
  toNotificationSummary,
  toOverride,
  toStats,
  toStatus,
  type BudgetPolicy,
  type PriceNotification,
} from '@/features/cost/model'

// Core gates system-wide price budgets, operator email and settings on User::isSuperAdmin().
export const useIsSuperAdmin = () => isSuperAdminUser(useSession(state => state.user))

export const PRICING_COMMANDS = [
  'stats.pricing.budget',
  'pricing.budget.status',
  'pricing.budget.policy.list',
  'pricing.budget.ledger.list',
  'pricing.budget.override.list',
  'pricing.notifications.list',
] as const

export const refreshPricing = () => invalidate(...PRICING_COMMANDS)

export const useBudgetStats = (enabled: boolean) =>
  useWs('stats.pricing.budget', {}, { enabled, refetchInterval: 60_000, select: data => toStats(data.stats) })

export const useBudgetStatus = (enabled: boolean) =>
  useWs('pricing.budget.status', { limit: 50, include_inactive: true }, { enabled, select: data => toStatus(data) })

export const useBudgetLedger = (enabled: boolean, limit = 100) =>
  useWs('pricing.budget.ledger.list', { limit }, { enabled, select: data => (data.ledger ?? []).map(toLedger) })

export const useOverrides = (enabled: boolean) =>
  useWs(
    'pricing.budget.override.list',
    { limit: 50, include_expired: true },
    { enabled, select: data => (data.overrides ?? []).map(toOverride) },
  )

export const useNotifications = (enabled: boolean, includeAcknowledged = false) =>
  useWs(
    'pricing.notifications.list',
    { limit: 50, include_acknowledged: includeAcknowledged },
    { enabled, select: data => (data.notifications ?? []).map(toNotification) },
  )

// The newest `limit` open alerts plus core's summary of all of them: the badge count and tone come from the summary,
// so a short page never hides an older, worse alert (#172).
export const useOpenAlerts = (enabled: boolean, limit: number, refetchInterval?: number) =>
  useWs(
    'pricing.notifications.list',
    { limit, include_acknowledged: false },
    {
      enabled,
      refetchInterval,
      select: data => ({
        items: (data.notifications ?? []).map(toNotification),
        summary: toNotificationSummary(data.summary),
      }),
    },
  )

export interface VaultLite {
  id: number
  name: string
  type: string
}

export const useVaultLookup = (enabled = true) => {
  const query = useWs('storage.vault.list', null, { enabled, retry: false, staleTime: 60_000 })
  return useMemo(() => {
    const vaults: VaultLite[] = (query.data?.vaults ?? []).map(v => ({ id: v.id, name: v.name, type: String(v.type) }))
    const byId = new Map(vaults.map(v => [v.id, v]))
    return {
      vaults,
      s3: vaults.filter(v => v.type === 's3'),
      name: (id: number | null | undefined) => (id ? (byId.get(id)?.name ?? `Vault ${id}`) : null),
      pending: query.isPending && enabled,
      error: query.error,
    }
  }, [query.data, query.isPending, query.error, enabled])
}

export const findPolicy = (
  policies: BudgetPolicy[],
  target: {
    scope: string
    provider_key?: string | null
    vault_id?: number | null
    gateway_credential_id?: number | null
  },
) => {
  const matches = policies.filter(
    p =>
      p.scope === target.scope
      && (p.provider_key ?? null) === (target.provider_key ?? null)
      && (p.vault_id ?? null) === (target.vault_id ?? null)
      && (p.gateway_credential_id ?? null) === (target.gateway_credential_id ?? null),
  )
  return matches.find(p => p.is_active) ?? matches[0] ?? null
}

export const ackNotification = async (n: PriceNotification) => {
  try {
    await api.send('pricing.notifications.ack', { notification_id: n.id, vault_id: n.vault_id })
    await invalidate('pricing.notifications.list', 'stats.pricing.budget', 'pricing.budget.status')
  } catch (error) {
    notify.error(error, 'Could not acknowledge the alert')
  }
}
