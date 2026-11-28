'use client'

// The health Overview's "Needs attention" and "Silenced" lists (design/health/findings.md §11). Severity and counts
// stay the server's truth; each finding shows its state, and accounts with admin.stats.manage get Acknowledge,
// Silence, Turn back on and the finding's remedies.

import React, { useState } from 'react'
import dynamic from 'next/dynamic'
import Link from 'next/link'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Panel } from '@/components/ui/Panel'
import { notify } from '@/components/ui/Toast'
import { ArrowUpRightFromSquareIcon, BellIcon, CheckIcon, EyeSlashIcon } from '@/components/ui/icons'
import { formatDateTime, formatRelative } from '@/lib/format'
import { HealthBadge, SeverityIcon } from '@/features/health/components'
import { asSeverity, healthHref } from '@/features/health/model'
import { FINDINGS_COPY as C } from '@/features/health/findings/copy'
import { controlsFor, splitFindings, stateText, type Finding, type HealthFindings, type SilencedRow } from '@/features/health/findings/model'
import { useAcknowledge, useTurnBackOn } from '@/features/health/findings/queries'
import type { SilenceTarget } from '@/features/health/findings/SilenceDialog'

const SilenceDialog = dynamic(() => import('@/features/health/findings/SilenceDialog'), { ssr: false })

const Note = ({ text }: { text: string | null | undefined }) =>
  text ? <p className="mt-1 text-xs break-words whitespace-pre-line text-fg-subtle">{C.note(text)}</p> : null

const FindingRow = ({
  finding,
  canManage,
  busy,
  onAcknowledge,
  onSilence,
  onTurnBackOn,
}: {
  finding: Finding
  canManage: boolean
  busy: boolean
  onAcknowledge: (f: Finding) => void
  onSilence: (f: Finding) => void
  onTurnBackOn: (f: Finding) => void
}) => {
  const controls = controlsFor(finding, canManage)
  const any = controls.acknowledge || controls.silence || controls.turnBackOn || controls.remedies.length > 0
  return (
    <li className="flex items-start gap-3 px-1 py-3" data-testid="health-finding" data-class={finding.class} data-state={finding.state}>
      <SeverityIcon severity={finding.severity} className="mt-0.5" />
      <div className="min-w-0 flex-1">
        <Link href={healthHref(finding.href)} className="text-sm hover:underline">
          <span className="mr-2 font-medium text-fg">{finding.title || finding.class_title}</span>
          <span className="text-fg-muted">{finding.message}</span>
        </Link>
        <p className="mt-0.5 text-xs text-fg-subtle" data-testid="health-finding-state">
          {stateText(finding)}
        </p>
        <Note text={finding.state === 'active' ? null : finding.mark?.note} />
        {any ? (
          <div className="mt-2 flex flex-wrap gap-2">
            {controls.acknowledge ? (
              <Button size="sm" variant="secondary" disabled={busy} onClick={() => onAcknowledge(finding)} title={C.acknowledgeHint}>
                <CheckIcon aria-hidden />
                {C.acknowledge}
              </Button>
            ) : null}
            {controls.silence ? (
              <Button size="sm" variant="ghost" disabled={busy} onClick={() => onSilence(finding)}>
                <EyeSlashIcon aria-hidden />
                {C.silence}
              </Button>
            ) : null}
            {controls.turnBackOn ? (
              <Button size="sm" variant="ghost" disabled={busy} onClick={() => onTurnBackOn(finding)}>
                <BellIcon aria-hidden />
                {C.turnBackOn}
              </Button>
            ) : null}
            {controls.remedies.map(remedy => (
              <Button key={remedy.id + remedy.href} size="sm" variant="link" asChild>
                <Link href={remedy.href}>
                  {remedy.label}
                  <ArrowUpRightFromSquareIcon aria-hidden />
                </Link>
              </Button>
            ))}
          </div>
        ) : null}
      </div>
    </li>
  )
}

const SilencedItem = ({
  row,
  canManage,
  busy,
  onTurnBackOn,
}: {
  row: SilencedRow
  canManage: boolean
  busy: boolean
  onTurnBackOn: (row: SilencedRow) => void
}) => (
  <li className="flex items-start gap-3 px-1 py-3" data-testid="health-silence" data-class={row.class}>
    <SeverityIcon severity={row.severity} className="mt-0.5" />
    <div className="min-w-0 flex-1">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium text-fg">{row.title}</span>
        <Badge tone={row.activeNow ? 'neutral' : 'unknown'}>{row.activeNow ? C.activeNow : C.notActiveNow}</Badge>
      </div>
      <p className="mt-0.5 text-xs text-fg-subtle">
        {stateText({ state: 'silenced', mark: row.mark })}
        <span title={formatDateTime(row.mark.set_at)}> · {C.silencedAt(formatRelative(row.mark.set_at))}</span>
      </p>
      <Note text={row.mark.note} />
    </div>
    {canManage ? (
      <Button size="sm" variant="secondary" disabled={busy} onClick={() => onTurnBackOn(row)} className="shrink-0">
        <BellIcon aria-hidden />
        {C.turnBackOn}
      </Button>
    ) : null}
  </li>
)

export const FindingsPanel = ({ health }: { health: HealthFindings }) => {
  const { attention, silenced } = splitFindings(health)
  const [silencing, setSilencing] = useState<SilenceTarget | null>(null)
  const acknowledge = useAcknowledge()
  const turnBackOn = useTurnBackOn()
  const canManage = health.can_manage
  const busyFor = (cls: string, subject: string) =>
    (acknowledge.isPending && acknowledge.variables?.class === cls && (acknowledge.variables.subject ?? '') === subject) ||
    (turnBackOn.isPending && turnBackOn.variables?.class === cls && (turnBackOn.variables.subject ?? '') === subject)

  const target = (cls: string, subject: string) => ({ class: cls, ...(subject ? { subject } : {}) })

  const onAcknowledge = (f: Finding) =>
    acknowledge.mutate(target(f.class, f.subject), {
      onSuccess: () => notify.success(C.acknowledgedToast, f.title || f.class_title),
      onError: error => notify.error(error, C.acknowledgeFailed),
    })
  const onTurnBackOn = (cls: string, subject: string, title: string) =>
    turnBackOn.mutate(target(cls, subject), {
      onSuccess: () => notify.success(C.turnedBackOnToast(title)),
      onError: error => notify.error(error, C.turnBackOnFailed),
    })

  const counted = health.error_count + health.warning_count > 0
  if (!attention.length && !silenced.length) return null

  return (
    <>
      {attention.length || counted ? (
        <Panel
          title={
            <span className="inline-flex items-center gap-2">
              {C.attentionTitle}
              <HealthBadge severity={asSeverity(health.overall_status)} errors={health.error_count} warnings={health.warning_count} />
            </span>
          }
          id="health-attention"
          bodyClassName="px-3 pb-1 pt-0">
          {attention.length ? (
            <ul className="divide-y divide-line">
              {attention.map(f => (
                <FindingRow
                  key={`${f.class}|${f.subject}`}
                  finding={f}
                  canManage={canManage}
                  busy={busyFor(f.class, f.subject)}
                  onAcknowledge={onAcknowledge}
                  onSilence={finding => setSilencing({ class: finding.class, subject: finding.subject, title: finding.class_title || finding.title })}
                  onTurnBackOn={finding => onTurnBackOn(finding.class, finding.subject, finding.class_title || finding.title)}
                />
              ))}
            </ul>
          ) : (
            <p className="px-1 py-3 text-sm text-fg-subtle">{C.attentionAllSilenced}</p>
          )}
        </Panel>
      ) : null}

      {silenced.length ? (
        <Panel title={C.silencedTitle} description={C.silencedDescription} id="health-silenced" bodyClassName="px-3 pb-1 pt-0">
          <ul className="divide-y divide-line">
            {silenced.map(row => (
              <SilencedItem
                key={row.key}
                row={row}
                canManage={canManage}
                busy={busyFor(row.class, row.subject)}
                onTurnBackOn={r => onTurnBackOn(r.class, r.subject, r.title)}
              />
            ))}
          </ul>
        </Panel>
      ) : null}

      {silencing ? <SilenceDialog target={silencing} open onOpenChange={open => !open && setSilencing(null)} /> : null}
    </>
  )
}
