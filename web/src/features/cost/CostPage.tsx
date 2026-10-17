'use client'

import { replaceQuery } from '@/lib/url'
import React from 'react'
import dynamic from 'next/dynamic'
import { useSearchParams } from 'next/navigation'
import { PageHeader } from '@/components/ui/Panel'
import { Button } from '@/components/ui/Button'
import { EmptyState, QueryState, Skeleton } from '@/components/ui/State'
import { StatGrid, StatTile } from '@/components/ui/Stat'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/Tabs'
import { ArrowsRotateIcon } from '@/components/ui/icons'
import { formatInt } from '@/lib/format'
import { useIsFetching } from '@tanstack/react-query'
import { Money, Section } from '@/features/cost/bits'
import { AlertsSection, OverridesSection } from '@/features/cost/alerts'
import { LedgerTable, TrendTable } from '@/features/cost/tables'
import { ProviderVersioningCard } from '@/features/cost/ProviderVersioningCard'
import {
  refreshPricing,
  useBudgetLedger,
  useBudgetStats,
  useBudgetStatus,
  useIsSuperAdmin,
  useVaultLookup,
} from '@/features/cost/queries'

const PoliciesTab = dynamic(() => import('@/features/cost/PoliciesTab').then(m => m.PoliciesTab), { ssr: false })
const PreflightTab = dynamic(() => import('@/features/cost/PreflightTab').then(m => m.PreflightTab), { ssr: false })

const TABS = ['overview', 'budgets', 'dry-run', 'ledger'] as const
type Tab = (typeof TABS)[number]

export const CostPage = () => {
  const allowed = useIsSuperAdmin()
  const params = useSearchParams()
  const focusVault = Number(params.get('vault')) || null
  const requested = params.get('tab') as Tab | null
  const tab: Tab =
    requested && TABS.includes(requested) ? requested
    : focusVault ? 'budgets'
    : 'overview'

  const stats = useBudgetStats(allowed)
  const status = useBudgetStatus(allowed)
  const ledger = useBudgetLedger(allowed && tab === 'ledger')
  const lookup = useVaultLookup(allowed)
  const fetching = useIsFetching({
    predicate: q => String(q.queryKey[0]).startsWith('pricing.') || q.queryKey[0] === 'stats.pricing.budget',
  })

  const setTab = (next: string) => replaceQuery(next === 'budgets' ? { tab: next } : { tab: next, vault: null })

  const header = (
    <PageHeader
      title="Cost control"
      description="Budgets for S3 provider spend: what syncs may cost, what they did cost, and what to do when a budget runs out."
      actions={
        allowed ?
          <Button variant="secondary" onClick={() => void refreshPricing()} loading={fetching > 0}>
            {fetching > 0 ? null : <ArrowsRotateIcon aria-hidden />}
            Refresh
          </Button>
        : null
      }
    />
  )

  if (!allowed)
    return (
      <>
        {header}
        <EmptyState
          className="panel"
          title="You don't have access to this"
          description="System-wide cost control is for super admins. Vault owners can see a vault's budget on the vault itself."
        />
      </>
    )

  const s = stats.data
  return (
    <>
      {header}
      {stats.isPending ?
        <StatGrid className="mb-6 xl:grid-cols-6">
          {Array.from({ length: 6 }, (_, i) => (
            <Skeleton key={i} className="rounded-card h-[74px]" />
          ))}
        </StatGrid>
      : <StatGrid className="mb-6 xl:grid-cols-6">
          <StatTile label="Active budgets" value={s ? formatInt(s.active_policies, '') || null : undefined} />
          <StatTile label="Blocked syncs (24 h)" value={s ? formatInt(s.blocked_syncs_24h, '') || null : undefined} />
          <StatTile label="Open alerts" value={s ? formatInt(s.unacknowledged_notifications, '') || null : undefined} />
          <StatTile label="Pending overrides" value={s ? formatInt(s.pending_overrides, '') || null : undefined} />
          <StatTile
            label="Spend this month"
            value={s?.current_monthly_spend ? <Money value={s.current_monthly_spend} currency={s.currency} /> : null}
            hint={s && !s.current_monthly_spend ? 'Needs a monthly budget' : 'Within monthly budgets'}
          />
          <StatTile
            label="Projected month"
            value={
              s?.projected_monthly_spend ? <Money value={s.projected_monthly_spend} currency={s.currency} /> : null
            }
            hint={s && !s.projected_monthly_spend ? 'Not enough data yet' : undefined}
          />
        </StatGrid>
      }
      {stats.error ?
        <p className="text-fg-subtle -mt-3 mb-5 text-xs">Budget statistics are unavailable right now.</p>
      : null}

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList aria-label="Cost control sections">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="budgets">Budgets</TabsTrigger>
          <TabsTrigger value="dry-run">Dry run</TabsTrigger>
          <TabsTrigger value="ledger">Ledger</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-8">
          <Section
            id="spend"
            title="Budget windows"
            description="Spend so far in each budgeted day or month, and where it is heading.">
            <QueryState query={status}>
              {data => <TrendTable trends={data.trends} vaultName={lookup.name} />}
            </QueryState>
          </Section>
          <AlertsSection enabled={allowed} vaultName={lookup.name} />
          <OverridesSection enabled={allowed} vaultName={lookup.name} />
          <ProviderVersioningCard vaults={lookup.s3} pending={lookup.pending} />
        </TabsContent>

        <TabsContent value="budgets">
          <QueryState query={status}>
            {data => (
              <PoliciesTab
                policies={data.policies}
                s3Vaults={lookup.s3}
                vaultsPending={lookup.pending}
                focusVaultId={focusVault}
              />
            )}
          </QueryState>
        </TabsContent>

        <TabsContent value="dry-run">
          <PreflightTab s3Vaults={lookup.s3} vaultsPending={lookup.pending} />
        </TabsContent>

        <TabsContent value="ledger">
          <Section
            id="ledger"
            title="Ledger"
            description="Every reservation and charge budgets recorded, newest first.">
            <QueryState query={ledger}>{rows => <LedgerTable ledger={rows} vaultName={lookup.name} />}</QueryState>
          </Section>
        </TabsContent>
      </Tabs>
    </>
  )
}
