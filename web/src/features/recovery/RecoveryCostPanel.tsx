'use client'

import React from 'react'
import Link from 'next/link'
import { Panel, DefinitionList } from '@/components/ui/Panel'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'
import { GearIcon, TriangleExclamationIcon } from '@/components/ui/icons'
import { useWs } from '@/lib/query'
import { formatBytes, formatInt } from '@/lib/format'
import { isWsError } from '@/lib/ws/errors'
import type { RecoveryCostReport } from '@/models/recovery'
import {
  Accumulation,
  Assumptions,
  computedAt,
  ConfidenceAndCatalog,
  CurrentStorage,
  FigureValue,
  NotModelled,
  ObservationList,
  RecoveryOperations,
  ScenarioTable,
} from '@/features/recovery/costParts'
import { moneyText, Notice, retentionChoiceLabel, SubHeading, timeText } from '@/features/recovery/shared'

// The vault's provider-versioning cost panel (lazy, Sync & cost tab): recovery.costs, phase-aware, in the same four
// separated sections as `vh recovery costs`. Estimates from the price catalog and this vault's counters, never invoices.
const RecoveryCostPanel = ({ vaultId }: { vaultId: number }) => {
  const costs = useWs(
    'recovery.costs',
    { vault_id: vaultId },
    { retry: false, staleTime: 60_000, select: d => d.costs },
  )
  return (
    <Panel
      id="recovery-costs"
      title="Provider versioning cost"
      description="Estimates, not provider invoices."
      actions={
        <Button asChild size="sm" variant="ghost">
          <Link href={`/vaults/${vaultId}/settings#recovery`}>
            <GearIcon aria-hidden />
            Recovery settings
          </Link>
        </Button>
      }>
      {costs.isPending ?
        <div className="flex justify-center py-6">
          <Spinner className="size-5" label="Loading" />
        </div>
      : costs.error || !costs.data ?
        <p className="text-fg-subtle text-sm" data-testid="recovery-costs-unavailable">
          {isWsError(costs.error, 'denied') ?
            'Your role can’t view this vault’s cost estimates.'
          : `Recovery cost estimates are unavailable${costs.error instanceof Error ? `: ${costs.error.message}` : '.'}`}
        </p>
      : <CostBody report={costs.data} />}
    </Panel>
  )
}

const CostBody = ({ report }: { report: RecoveryCostReport }) => {
  const active = report.phase === 'active'
  return (
    <div className="space-y-6" data-testid="recovery-costs" data-phase={report.phase}>
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone="neutral">Estimates, not provider invoices</Badge>
        <Badge tone={active ? 'accent' : 'neutral'}>{active ? 'Versioning active' : 'Versioning not enabled'}</Badge>
        <span className="text-fg-subtle text-xs">{computedAt(report)}</span>
      </div>

      {!report.priced ?
        <Notice tone="warn" icon={TriangleExclamationIcon} title="Costs cannot be estimated" role="note">
          {report.unpriced_reason ?? 'No price catalog entry applies to this bucket.'}
        </Notice>
      : null}

      {active && report.alert.exceeded ?
        <Notice tone="danger" icon={TriangleExclamationIcon} title="Over the cost alert" role="alert">
          The projected monthly versioning cost is over the alert threshold of{' '}
          {moneyText(report.alert.threshold, 'not set')}. Alerts don’t block writes or turn versioning off.
        </Notice>
      : null}

      <section>
        <SubHeading>1 · Versioning surcharge</SubHeading>
        {active ?
          <>
            <DefinitionList
              items={[
                ['Month to date', <FigureValue key="mtd" figure={report.current_month_to_date} />],
                ['Projected this month', <FigureValue key="p" figure={report.current_month_projected} />],
                ['Next 30 days', <FigureValue key="f" figure={report.projected_monthly} />],
                ['Retention', report.retention ? retentionChoiceLabel(report.retention) : 'Not set'],
                ['Cost alert', moneyText(report.alert.threshold, 'not set')],
              ]}
            />
            <div className="mt-4">
              <SubHeading>Version history held</SubHeading>
              <DefinitionList
                items={[
                  [
                    'Known replaced versions',
                    `${formatInt(report.history.known_noncurrent_versions)} (${formatBytes(report.history.known_noncurrent_bytes)})`,
                  ],
                  ['Delete markers', formatInt(report.history.delete_markers)],
                  ['Versions of unknown size', formatInt(report.history.unknown_size_versions)],
                  ['Inventoried', timeText(report.history.inventoried_at)],
                ]}
              />
              {report.history.unaccounted_history ?
                <p className="text-warn mt-2 text-xs">
                  The bucket holds versions from before Vaulthalla started measuring; their size and cost aren’t fully
                  accounted for here.
                </p>
              : null}
            </div>
          </>
        : <>
            <p className="text-fg-muted mb-2 text-sm">Enabling provider versioning would add about:</p>
            <FigureValue figure={report.pre_activation_monthly} large />
            <div className="mt-4">
              <ScenarioTable scenarios={report.scenarios} chosen={report.retention} />
            </div>
          </>
        }
        <div className="mt-4">
          <SubHeading>Write activity driving growth</SubHeading>
          <ObservationList report={report} />
        </div>
        {active && report.accumulation.length ?
          <div className="mt-4">
            <SubHeading>Projected history over 12 months</SubHeading>
            <Accumulation points={report.accumulation} />
          </div>
        : null}
      </section>

      <section>
        <SubHeading>2 · Current object storage (context, not part of the surcharge)</SubHeading>
        <CurrentStorage report={report} />
      </section>

      <section>
        <SubHeading>3 · Recovery operations</SubHeading>
        <RecoveryOperations report={report} />
      </section>

      <section>
        <SubHeading>4 · Not modelled</SubHeading>
        <NotModelled report={report} />
        <div className="mt-3">
          <Assumptions report={report} />
        </div>
      </section>

      <ConfidenceAndCatalog report={report} />
    </div>
  )
}

export default RecoveryCostPanel
