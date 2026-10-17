'use client'

import React from 'react'
import { cn } from '@/util/cn'
import { Badge } from '@/components/ui/Badge'
import { DefinitionList } from '@/components/ui/Panel'
import { Sparkline } from '@/components/ui/Stat'
import { DASH, formatBytes, formatDuration, formatInt } from '@/lib/format'
import type { Tone } from '@/lib/tone'
import type { AccumulationPoint, CostFigure, RecoveryCostReport, RetentionScenario } from '@/models/recovery'
import {
  BASIS_LABEL,
  BASIS_TONE,
  BulletList,
  moneyText,
  retentionChoiceLabel,
  SubHeading,
  timeText,
} from '@/features/recovery/shared'

// The cost report pieces the disclosure dialog and the vault's recovery cost panel share. The report is computed by
// the daemon from the signed price catalog and this vault's own counters; nothing here adds figures up or fills gaps.

export const BasisBadge = ({ basis }: { basis: CostFigure['basis'] }) => (
  <Badge tone={BASIS_TONE[basis] ?? 'neutral'}>{BASIS_LABEL[basis] ?? basis}</Badge>
)

// One estimated amount: expected, its range and what it is based on. Unknown is "cannot be estimated", never $0.00.
export const FigureValue = ({
  figure,
  large = false,
  showBasis = true,
  testId,
}: {
  figure: CostFigure | null | undefined
  large?: boolean
  showBasis?: boolean
  testId?: string
}) => {
  if (!figure || !figure.expected)
    return (
      <span className="text-fg-subtle text-sm" data-testid={testId}>
        Cannot be estimated{figure?.reason ? `: ${figure.reason}` : ''}
      </span>
    )
  const range =
    (
      figure.low
      && figure.high
      && (figure.low.amount !== figure.expected.amount || figure.high.amount !== figure.expected.amount)
    ) ?
      `${moneyText(figure.low)} – ${moneyText(figure.high)}`
    : null
  return (
    <span className="inline-flex flex-wrap items-baseline gap-x-2 gap-y-1" data-testid={testId}>
      <span className={cn('tabular text-fg font-semibold', large ? 'text-xl' : 'text-sm')}>
        {moneyText(figure.expected)}
        <span className="text-fg-subtle text-xs font-normal"> / month</span>
      </span>
      {range ?
        <span className="text-fg-subtle tabular text-xs">range {range}</span>
      : null}
      {showBasis ?
        <BasisBadge basis={figure.basis} />
      : null}
      {figure.reason ?
        <span className="text-fg-subtle text-xs">{figure.reason}</span>
      : null}
    </span>
  )
}

const CONFIDENCE_TONE: Record<string, Tone> = { high: 'accent', medium: 'neutral', low: 'warn', none: 'unknown' }

export const ConfidenceAndCatalog = ({ report }: { report: RecoveryCostReport }) => (
  <div className="space-y-2 text-sm">
    <div className="flex flex-wrap items-center gap-2">
      <span className="text-fg-subtle">Confidence</span>
      <Badge tone={CONFIDENCE_TONE[report.confidence] ?? 'unknown'}>{report.confidence}</Badge>
      <span className="text-fg-subtle">Price catalog</span>
      <Badge tone={report.catalog.verified ? 'neutral' : 'warn'}>
        {report.catalog.verified ? 'Verified' : 'Not verified'}
      </Badge>
      {report.catalog.stale ?
        <Badge tone="warn">Stale</Badge>
      : null}
      <span className="text-fg-subtle text-xs">
        {[
          report.catalog.version ? `version ${report.catalog.version}` : null,
          report.catalog.source,
          report.catalog.age_seconds !== null ? `updated ${formatDuration(report.catalog.age_seconds)} ago` : null,
        ]
          .filter(Boolean)
          .join(' · ') || 'no catalog details'}
      </span>
    </div>
    {report.catalog.note ?
      <p className="text-fg-subtle text-xs">{report.catalog.note}</p>
    : null}
    <BulletList items={report.confidence_reasons} className="text-fg-subtle text-xs" />
  </div>
)

export const ObservationList = ({ report }: { report: RecoveryCostReport }) => {
  const o = report.observation
  if (!o.window_days)
    return (
      <p className="text-fg-subtle text-sm">
        No write activity has been measured for this vault yet, so the figures below use illustrative assumptions, not
        your workload.
      </p>
    )
  return (
    <>
      <DefinitionList
        items={[
          [
            'Measured',
            `${formatInt(o.window_days)} day${o.window_days === 1 ? '' : 's'} (${o.first_day ?? DASH} → ${o.last_day ?? DASH})`,
          ],
          ['Overwritten', `${formatBytes(o.overwritten_bytes)} in ${formatInt(o.overwrite_objects)} objects`],
          ['Deleted', `${formatBytes(o.deleted_bytes)} in ${formatInt(o.deleted_objects)} objects`],
          ['Overwritten per day', formatBytes(Number(o.overwritten_bytes_per_day))],
          ['Uploaded', `${formatBytes(o.uploaded_bytes)} (${formatInt(o.first_put_objects)} new objects)`],
          [
            'Requests',
            `${formatInt(o.put_requests)} PUT · ${formatInt(o.copy_requests)} COPY · ${formatInt(o.delete_requests)} DELETE · ${formatInt(o.get_requests)} GET · ${formatInt(o.list_requests)} LIST`,
          ],
        ]}
      />
      {!o.sufficient ?
        <p className="text-warn mt-2 text-xs">
          Fewer than 7 days measured: the estimate is a wide range with low confidence.
        </p>
      : null}
    </>
  )
}

export const CurrentStorage = ({ report }: { report: RecoveryCostReport }) => (
  <DefinitionList
    items={[
      ['Current objects', `${formatInt(report.current.objects)} (${formatBytes(report.current.bytes)})`],
      [
        'Their monthly storage',
        report.current.monthly_storage ?
          `${moneyText(report.current.monthly_storage)} (already billed today; not part of the versioning surcharge)`
        : 'Cannot be estimated',
      ],
    ]}
  />
)

export const RecoveryOperations = ({ report }: { report: RecoveryCostReport }) => (
  <DefinitionList
    items={[
      ['Restoring 1 GB', <FigureValue key="gb" figure={report.recovery_per_gb} showBasis={false} />],
      ['Restoring one object', <FigureValue key="obj" figure={report.recovery_per_object} showBasis={false} />],
    ]}
  />
)

const fixAmount = (figure: CostFigure) => (figure.expected ? moneyText(figure.expected) : 'cannot be estimated')

export const ScenarioTable = ({ scenarios, chosen }: { scenarios: RetentionScenario[]; chosen?: string | null }) =>
  scenarios.length ?
    <div className="rounded-control border-line overflow-x-auto border">
      <table className="w-full text-sm" data-testid="recovery-scenarios">
        <thead className="text-fg-subtle bg-surface-1 text-left text-xs">
          <tr>
            <th className="px-3 py-2 font-medium">Retention</th>
            <th className="px-3 py-2 font-medium">History kept (steady state)</th>
            <th className="px-3 py-2 font-medium">Monthly</th>
            <th className="px-3 py-2 font-medium">Basis</th>
          </tr>
        </thead>
        <tbody className="divide-line/60 divide-y">
          {scenarios.map(s => (
            <tr key={s.retention} className={cn(s.retention === chosen && 'bg-accent-soft')}>
              <td className="text-fg px-3 py-2">
                {retentionChoiceLabel(s.retention)}
                {s.retention === chosen ?
                  <span className="text-accent-text ml-1.5 text-xs">chosen</span>
                : null}
                {s.notes.length ?
                  <p className="text-fg-subtle mt-0.5 text-xs">{s.notes.join(' ')}</p>
                : null}
              </td>
              <td className="tabular px-3 py-2">
                {s.retention === 'indefinite' ? 'grows without limit' : formatBytes(s.steady_noncurrent_bytes)}
              </td>
              <td className="tabular px-3 py-2">
                {fixAmount(s.monthly_cost)}
                {s.monthly_cost.expected && s.monthly_cost.low && s.monthly_cost.high ?
                  <span className="text-fg-subtle block text-xs">
                    {moneyText(s.monthly_cost.low)} – {moneyText(s.monthly_cost.high)}
                  </span>
                : null}
              </td>
              <td className="text-fg-subtle px-3 py-2 text-xs">
                {BASIS_LABEL[s.monthly_cost.basis] ?? s.monthly_cost.basis}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  : <p className="text-fg-subtle text-sm">No retention scenarios were computed.</p>

// History accumulation over 12 months (what indefinite retention, or the time before retention kicks in, piles up).
export const Accumulation = ({ points }: { points: AccumulationPoint[] }) => {
  if (!points.length) return <p className="text-fg-subtle text-sm">No growth projection was computed.</p>
  const last = points[points.length - 1]
  return (
    <div className="space-y-2">
      <Sparkline values={points.map(p => p.noncurrent_bytes)} height={40} />
      <div className="rounded-control border-line overflow-x-auto border">
        <table className="w-full text-sm" data-testid="recovery-accumulation">
          <thead className="text-fg-subtle bg-surface-1 text-left text-xs">
            <tr>
              <th className="px-3 py-1.5 font-medium">Month</th>
              <th className="px-3 py-1.5 font-medium">Version history held</th>
              <th className="px-3 py-1.5 font-medium">Its monthly cost</th>
            </tr>
          </thead>
          <tbody className="divide-line/60 divide-y">
            {points.map(p => (
              <tr key={p.month}>
                <td className="tabular px-3 py-1.5">{p.month}</td>
                <td className="tabular px-3 py-1.5">{formatBytes(p.noncurrent_bytes)}</td>
                <td className="tabular px-3 py-1.5">{fixAmount(p.monthly_cost)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="text-fg-subtle text-xs">
        After {last.month} months: {formatBytes(last.noncurrent_bytes)} of version history,{' '}
        {fixAmount(last.monthly_cost)} per month ({BASIS_LABEL[last.monthly_cost.basis] ?? last.monthly_cost.basis}).
      </p>
    </div>
  )
}

const ASSUMPTION_TITLE: Record<string, string> = {
  observed: 'From your measured workload',
  illustrative: 'Illustrative assumptions (not your data)',
  provider_rule: 'Provider billing rules',
}

export const Assumptions = ({ report }: { report: RecoveryCostReport }) => {
  const groups = new Map<string, string[]>()
  for (const a of report.assumptions) groups.set(a.kind, [...(groups.get(a.kind) ?? []), a.text])
  if (!groups.size) return null
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {[...groups.entries()].map(([kind, texts]) => (
        <div key={kind}>
          <SubHeading>{ASSUMPTION_TITLE[kind] ?? kind}</SubHeading>
          <BulletList items={texts} className="text-fg-muted text-xs" />
        </div>
      ))}
    </div>
  )
}

export const NotModelled = ({ report }: { report: RecoveryCostReport }) =>
  report.unmodeled.length ?
    <BulletList items={report.unmodeled} className="text-fg-muted" />
  : <p className="text-fg-subtle text-sm">Nothing listed.</p>

export const computedAt = (report: RecoveryCostReport) => `Computed ${timeText(report.computed_at)}`
