'use client'

import React, { useEffect, useMemo } from 'react'
import dynamic from 'next/dynamic'
import Link from 'next/link'
import { FormProvider, useForm } from 'react-hook-form'
import { useWs, useWsMutation } from '@/lib/query'
import { Panel } from '@/components/ui/Panel'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { EmptyState, InlineError } from '@/components/ui/State'
import { notify } from '@/components/ui/Toast'
import { HardDriveIcon, SackDollarIcon } from '@/components/ui/icons'
import { formatDateTime, formatDuration, formatInt, formatMoney, formatRelative, titleCase } from '@/lib/format'
import { isWsError } from '@/lib/ws/errors'
import { STATS_POLL_MS, useCurrentVault } from '@/features/vaults/VaultShell'
import { realTimestamp } from '@/features/vaults/model'
import { syncFormDefaults, syncPayload, type SyncFormValues } from '@/features/vaults/syncPolicy'
import { RequestGuardrailFields, SyncPolicyFields } from '@/features/vaults/sync/SyncPolicyFields'
import { Metric, MetricGrid, StatusBadge } from '@/features/vaults/overview/blocks'
import type { PricingStats, SyncHealthStats } from '@/features/vaults/overview/types'

const RecoveryCostPanel = dynamic(() => import('@/features/recovery/RecoveryCostPanel'), { ssr: false })

export const VaultSync = () => {
  const vault = useCurrentVault()
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
      <div className="min-w-0 space-y-4">
        {vault.type === 's3' ? (
          <>
            <SyncPolicyForm />
            <RecoveryCostPanel vaultId={vault.id} />
          </>
        ) : (
          <div className="panel">
            <EmptyState
              icon={HardDriveIcon}
              title="Local vaults don’t sync to a bucket"
              description="Sync policy and S3 request guardrails apply to S3 vaults. This vault stores its files on this server."
            />
          </div>
        )}
      </div>
      <div className="min-w-0 space-y-4">
        <SyncStatus />
        <CostSummary />
      </div>
    </div>
  )
}

const SyncPolicyForm = () => {
  const vault = useCurrentVault()
  const defaults = useMemo(() => ({ sync: syncFormDefaults(vault.sync) }), [vault.sync])
  const form = useForm<{ sync: SyncFormValues }>({ defaultValues: defaults })
  const { reset, handleSubmit, formState } = form

  // A refetch of the vault (after a save, or another admin's change) resets an untouched form to the server's values.
  useEffect(() => {
    if (!formState.isDirty) reset(defaults)
  }, [defaults, formState.isDirty, reset])

  const save = useWsMutation('storage.vault.update', {
    toPayload: (values: { sync: SyncFormValues }) => ({ id: vault.id, sync: syncPayload(values.sync) }),
    invalidates: ['storage.vault.get', 'stats.vault.sync'],
    onSuccess: () => {
      notify.success('Sync settings saved')
    },
  })

  return (
    <FormProvider {...form}>
      <form
        className="space-y-4"
        onSubmit={handleSubmit(async values => {
          try {
            await save.mutateAsync(values)
            reset(values)
          } catch {
            // Rendered below.
          }
        })}>
        <Panel title="Sync policy" description="How this vault and its bucket stay in step.">
          <SyncPolicyFields />
        </Panel>
        <Panel title="Request guardrails" description="Per-run S3 request limits. A run that would go over stops and says so.">
          <RequestGuardrailFields />
        </Panel>
        <InlineError error={save.error && !isWsError(save.error, 'needs_confirmation') ? save.error : null} />
        <div className="flex items-center justify-end gap-2">
          {formState.isDirty ? <span className="mr-auto text-xs text-fg-subtle">Unsaved changes</span> : null}
          <Button variant="ghost" disabled={!formState.isDirty || save.isPending} onClick={() => reset(defaults)}>
            Discard
          </Button>
          <Button type="submit" variant="primary" disabled={!formState.isDirty} loading={save.isPending}>
            Save sync settings
          </Button>
        </div>
      </form>
    </FormProvider>
  )
}

const SyncStatus = () => {
  const vault = useCurrentVault()
  const sync = useWs('stats.vault.sync', { vault_id: vault.id }, {
    refetchInterval: STATS_POLL_MS,
    retry: false,
    select: d => d.stats as unknown as SyncHealthStats,
  })
  return (
    <Panel title="Sync status" actions={sync.data ? <StatusBadge status={sync.data.overall_status} /> : null}>
      {sync.isPending ? (
        <div className="skeleton h-24" />
      ) : sync.error || !sync.data ? (
        <p className="text-sm text-fg-subtle">{isWsError(sync.error, 'denied') ? 'Your role can’t read sync status for this vault.' : 'Sync status is not available.'}</p>
      ) : (
        <MetricGrid className="sm:grid-cols-2">
          <Metric label="State" value={sync.data.current_state ? titleCase(sync.data.current_state) : null} />
          <Metric label="Interval" value={typeof sync.data.sync_interval_seconds === 'number' ? formatDuration(sync.data.sync_interval_seconds) : null} />
          <Metric
            label="Last success"
            value={realTimestamp(sync.data.last_success_at) ? formatRelative(sync.data.last_success_at) : null}
            hint={realTimestamp(sync.data.last_success_at) ? formatDateTime(sync.data.last_success_at) : undefined}
          />
          <Metric label="Errors 24h" value={sync.data.error_count_24h != null ? formatInt(sync.data.error_count_24h) : null} />
        </MetricGrid>
      )}
    </Panel>
  )
}

interface PolicyRow {
  id?: number | null
  scope?: string
  mode?: string
  currency?: string
  max_run_cost?: string | null
  max_daily_cost?: string | null
  max_monthly_cost?: string | null
  is_active?: boolean
  provider_key?: string | null
  vault_id?: number | null
}

// A read-only summary of the price budget that applies to this vault. Editing lives at /cost.
const CostSummary = () => {
  const vault = useCurrentVault()
  const pricing = useWs('stats.vault.pricing', { vault_id: vault.id }, {
    refetchInterval: STATS_POLL_MS,
    retry: false,
    select: d => d.stats as unknown as PricingStats,
  })
  const policies = useWs('pricing.budget.policy.list', { vault_id: vault.id }, {
    retry: false,
    select: d => ((d as { policies?: PolicyRow[] }).policies ?? []).filter(p => p.is_active !== false),
  })
  const currency = pricing.data?.currency || 'USD'

  return (
    <Panel
      title="Cost"
      actions={
        <Button asChild size="sm" variant="ghost">
          <Link href={`/cost?vault=${vault.id}`}>
            <SackDollarIcon aria-hidden />
            Cost control
          </Link>
        </Button>
      }>
      {pricing.data ? (
        <MetricGrid className="sm:grid-cols-2">
          <Metric label="Spend this month" value={pricing.data.current_monthly_spend != null ? formatMoney(pricing.data.current_monthly_spend, currency) : null} />
          <Metric label="Projected" value={pricing.data.projected_monthly_spend != null ? formatMoney(pricing.data.projected_monthly_spend, currency) : null} />
          <Metric label="Blocked syncs 24h" value={pricing.data.blocked_syncs_24h != null ? formatInt(pricing.data.blocked_syncs_24h) : null} />
          <Metric label="Pending overrides" value={pricing.data.pending_overrides != null ? formatInt(pricing.data.pending_overrides) : null} />
        </MetricGrid>
      ) : pricing.isPending ? (
        <div className="skeleton h-16" />
      ) : (
        <p className="text-sm text-fg-subtle">Spend is not available{isWsError(pricing.error, 'denied') ? ' to your role' : ''}.</p>
      )}

      <h3 className="mt-5 mb-2 text-[11px] font-medium tracking-wide text-fg-subtle uppercase">Budget policies</h3>
      {policies.isPending ? (
        <div className="skeleton h-10" />
      ) : policies.error ? (
        <p className="text-sm text-fg-subtle">{isWsError(policies.error, 'denied') ? 'Your role can’t read budget policies.' : 'Budget policies are not available.'}</p>
      ) : policies.data?.length ? (
        <ul className="divide-y divide-line/60 rounded-control border border-line">
          {policies.data.map((p, i) => (
            <li key={p.id ?? i} className="px-3 py-2 text-sm">
              <div className="flex items-center justify-between gap-2">
                <span className="text-fg">{p.scope === 'vault' ? 'This vault' : p.scope === 'provider' ? `Provider ${p.provider_key ?? ''}` : titleCase(p.scope ?? 'policy')}</span>
                <Badge tone={p.mode === 'enforce' ? 'accent' : 'neutral'}>{titleCase(p.mode ?? 'report')}</Badge>
              </div>
              <div className="mt-0.5 text-xs text-fg-subtle tabular">
                {[
                  p.max_monthly_cost != null ? `${formatMoney(p.max_monthly_cost, p.currency || currency)}/month` : null,
                  p.max_daily_cost != null ? `${formatMoney(p.max_daily_cost, p.currency || currency)}/day` : null,
                  p.max_run_cost != null ? `${formatMoney(p.max_run_cost, p.currency || currency)}/run` : null,
                ]
                  .filter(Boolean)
                  .join(' · ') || 'No caps set'}
              </div>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-fg-subtle">
          No budget applies to this vault yet.{' '}
          <Link href={`/cost?vault=${vault.id}`} className="text-accent-text hover:underline">
            Set one
          </Link>
          .
        </p>
      )}
    </Panel>
  )
}
