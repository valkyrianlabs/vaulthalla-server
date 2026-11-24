'use client'

import { useMemo } from 'react'
import { useWs, invalidate } from '@/lib/query'
import { useCan } from '@/lib/permissions'
import type { Command } from '@/lib/ws/client'
import { toLedger, toPolicy, toTrend } from '@/features/cost/model'
import {
  toAssignment,
  toBucket,
  toCredential,
  toDefaultRole,
  toOverride,
  toProfile,
  toSelectedVault,
  toStatus,
} from '@/features/gateway/model'

export const useGatewayPerms = () => ({
  view: useCan({ permission: 'admin.s3_gateway.view' }),
  any: useCan({ prefix: 'admin.s3_gateway' }),
  credentials: useCan({ permission: 'admin.s3_gateway.manage_credentials' }),
  assignPrincipal: useCan({ permission: 'admin.s3_gateway.assign_principal' }),
  buckets: useCan({ permission: 'admin.s3_gateway.manage_buckets' }),
  budgets: useCan({ permission: 'admin.s3_gateway.manage_budgets' }),
})

const CREDENTIAL_SCOPE: Command[] = [
  's3.gateway.credentials.list',
  's3.gateway.credentials.defaultRole.get',
  's3.gateway.credentials.selectedVaults.list',
  's3.gateway.credentials.defaultRole.overrides.list',
  's3.gateway.credentials.roles.list',
  's3.gateway.credentials.roles.overrides.list',
]
export const refreshCredentials = () => invalidate(...CREDENTIAL_SCOPE)
export const refreshBuckets = () => invalidate('s3.gateway.buckets.list', 'storage.vault.list')
// A profile change can alter what a key creates and the sync settings of the buckets created from it.
export const refreshProfiles = () =>
  invalidate('s3.gateway.upstreamProfiles.list', 's3.gateway.credentials.list', 's3.gateway.buckets.list', 'storage.vault.list')
export const refreshGatewayBudgets = () =>
  invalidate('s3.gateway.budget.policy.list', 's3.gateway.budget.status', 's3.gateway.budget.ledger.list')
export const refreshGateway = () =>
  invalidate(
    's3.gateway.status',
    ...CREDENTIAL_SCOPE,
    's3.gateway.buckets.list',
    's3.gateway.upstreamProfiles.list',
    's3.gateway.budget.policy.list',
    's3.gateway.budget.status',
    's3.gateway.budget.ledger.list',
  )

export const useGatewayStatus = (enabled: boolean) =>
  useWs('s3.gateway.status', null, { enabled, refetchInterval: 30_000, select: data => toStatus(data.status) })

export const useGatewayCredentials = (enabled = true) =>
  useWs(
    's3.gateway.credentials.list',
    { include_disabled: true },
    { enabled, select: data => (data.credentials ?? []).map(toCredential) },
  )

export const useUpstreamProfiles = (enabled = true) =>
  useWs('s3.gateway.upstreamProfiles.list', null, {
    enabled,
    select: data => ({
      profiles: (data.profiles ?? []).map(toProfile),
      default_profile: data.default_profile ?? null,
      reapply_default: data.reapply_default ?? null,
    }),
  })

export const useBuckets = (enabled = true) =>
  useWs('s3.gateway.buckets.list', null, { enabled, select: data => (data.buckets ?? []).map(toBucket) })

export const useGatewayPolicies = (enabled = true) =>
  useWs(
    's3.gateway.budget.policy.list',
    { include_inactive: true },
    { enabled, select: data => (data.policies ?? []).map(toPolicy) },
  )

export const useGatewayBudgetStatus = (enabled = true) =>
  useWs(
    's3.gateway.budget.status',
    { limit: 50 },
    { enabled, select: data => ({ trends: (data.trends ?? []).map(toTrend) }) },
  )

export const useGatewayLedger = (enabled = true) =>
  useWs('s3.gateway.budget.ledger.list', { limit: 100 }, { enabled, select: data => (data.ledger ?? []).map(toLedger) })

export const useDefaultRole = (credentialId: number) =>
  useWs(
    's3.gateway.credentials.defaultRole.get',
    { credential_id: credentialId },
    { select: data => toDefaultRole(data.default_role) },
  )

export const useSelectedVaults = (credentialId: number, enabled: boolean) =>
  useWs(
    's3.gateway.credentials.selectedVaults.list',
    { credential_id: credentialId },
    { enabled, select: data => (data.selected_vaults ?? data.vaults ?? []).map(toSelectedVault) },
  )

export const useDefaultOverrides = (credentialId: number, enabled: boolean) =>
  useWs(
    's3.gateway.credentials.defaultRole.overrides.list',
    { credential_id: credentialId },
    { enabled, select: data => (data.overrides ?? []).map(toOverride) },
  )

export const useRoleAssignments = (credentialId: number, enabled: boolean) =>
  useWs(
    's3.gateway.credentials.roles.list',
    { credential_id: credentialId },
    { enabled, select: data => (data.roles ?? data.assignments ?? []).map(toAssignment) },
  )

export const useVaultOverrides = (credentialId: number, vaultId: number | null) =>
  useWs(
    's3.gateway.credentials.roles.overrides.list',
    { credential_id: credentialId, vault_id: vaultId ?? 0 },
    { enabled: Boolean(vaultId), select: data => (data.overrides ?? []).map(toOverride) },
  )

export interface Option {
  id: number
  name: string
  hint?: string
}

export const useVaultOptions = () => {
  const q = useWs('storage.vault.list', null, { retry: false, staleTime: 60_000 })
  return useMemo(
    () => ({
      list: (q.data?.vaults ?? []).map(v => ({ id: v.id, name: v.name, type: String(v.type) })),
      name: (id: number | null | undefined) => {
        if (!id) return null
        return q.data?.vaults.find(v => v.id === id)?.name ?? `Vault ${id}`
      },
      pending: q.isPending,
    }),
    [q.data, q.isPending],
  )
}

export const useVaultRoleOptions = (enabled = true) => {
  const q = useWs('roles.vault.list', null, { enabled, staleTime: 5 * 60_000 })
  return useMemo(
    () => (q.data?.roles ?? []).map(r => ({ id: r.id, name: r.name, hint: r.description ?? undefined })),
    [q.data],
  )
}

export const useFsPermissionOptions = (enabled = true) => {
  const q = useWs('permissions.list', null, { enabled, staleTime: 10 * 60_000 })
  return useMemo(
    () =>
      (q.data?.permissions ?? [])
        .map(p => (p as unknown as { qualified?: string }).qualified ?? '')
        .filter(q => q.startsWith('vault.fs.'))
        .sort(),
    [q.data],
  )
}

export const useUserOptions = (enabled: boolean) => {
  const q = useWs('auth.users.list', null, { enabled, staleTime: 60_000 })
  return useMemo(
    () => (q.data?.users ?? []).map(u => ({ id: u.id, name: u.name, hint: u.email ?? undefined })),
    [q.data],
  )
}
