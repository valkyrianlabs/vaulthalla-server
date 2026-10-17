'use client'

import React, { useCallback, useEffect, useId, useRef, useState } from 'react'
import { Dialog, DialogContent } from '@/components/ui/Dialog'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Checkbox } from '@/components/ui/Choice'
import { confirm } from '@/components/ui/Confirm'
import { DefinitionList } from '@/components/ui/Panel'
import { InlineError } from '@/components/ui/State'
import { Spinner } from '@/components/ui/Spinner'
import { notify } from '@/components/ui/Toast'
import { CircleInfoIcon, RotateLeftIcon, TriangleExclamationIcon } from '@/components/ui/icons'
import { api } from '@/lib/session'
import { invalidate, queryClient } from '@/lib/query'
import { DASH, formatBytes, formatInt } from '@/lib/format'
import type { Payload } from '@/lib/ws/client'
import type { WsError } from '@/lib/ws/errors'
import {
  RECOVERY_CODES,
  type RecoveryItemAction,
  type RecoveryPlan,
  type RecoveryRequestEstimate,
  type RecoveryRestoreResult,
} from '@/models/recovery'
import {
  ACTION_LABEL,
  ACTION_TONE,
  BulletList,
  METHOD_LABEL,
  moneyText,
  needsCode,
  Notice,
  sizeText,
  SubHeading,
  timeText,
} from '@/features/recovery/shared'

export type PlanRequest = Payload<'recovery.plan'>

// Never render thousands of rows in a dialog; the counts above the table are complete.
const ROW_CAP = 500

const ATOMIC_FALSE_NOTE =
  'This is a timestamp-based reconstruction from per-object version times, not an atomic snapshot.'

// Restore preview (lazy): plans first (read-only), shows exactly what would change, then restores with the plan's
// token. Overwrites and removals need RESTORE typed; versions Vaulthalla didn't write need a separate acknowledgement;
// an expired plan is planned again and shown before anything runs.
const RestorePreviewDialog = ({
  request,
  onClose,
  onRestored,
}: {
  request: PlanRequest
  onClose: () => void
  onRestored?: (result: RecoveryRestoreResult) => void
}) => {
  const [plan, setPlan] = useState<RecoveryPlan | null>(null)
  const [planning, setPlanning] = useState(true)
  const [planError, setPlanError] = useState<unknown>(null)
  const [replanned, setReplanned] = useState(false)
  const [restoring, setRestoring] = useState(false)
  const [restoreError, setRestoreError] = useState<unknown>(null)
  const [unverified, setUnverified] = useState<WsError | null>(null)
  const [result, setResult] = useState<RecoveryRestoreResult | null>(null)
  const requestRef = useRef(request)

  const makePlan = useCallback(async () => {
    setPlanning(true)
    setPlanError(null)
    try {
      const data = await api.send('recovery.plan', requestRef.current)
      setPlan(data.plan)
      return data.plan
    } catch (e) {
      setPlanError(e)
      return null
    } finally {
      setPlanning(false)
    }
  }, [])

  useEffect(() => {
    void makePlan()
  }, [makePlan])

  const restore = async (acceptUnverified: boolean) => {
    if (!plan) return
    setRestoreError(null)
    if (!acceptUnverified) {
      const destructive = plan.overwrites + plan.removals
      const ok = await confirm(
        destructive > 0 ?
          {
            title: 'Overwrite current files?',
            description: `${[
              plan.overwrites ?
                `${formatInt(plan.overwrites)} existing file${plan.overwrites === 1 ? '' : 's'} will be replaced`
              : null,
              plan.removals ?
                `${formatInt(plan.removals)} file${plan.removals === 1 ? '' : 's'} will be removed`
              : null,
            ]
              .filter(Boolean)
              .join(
                ' and ',
              )}. The current contents become a new recovery point only if local versioning or provider versioning keeps them.`,
            confirmLabel: 'Restore',
            tone: 'danger',
            typeToConfirm: 'RESTORE',
          }
        : {
            title: 'Restore now?',
            description: `${formatInt(plan.creates)} item${plan.creates === 1 ? '' : 's'} will be created. Nothing existing is overwritten or removed.`,
            confirmLabel: 'Restore',
            tone: 'primary',
          },
      )
      if (!ok) return
    }
    setRestoring(true)
    try {
      const data = await api.send('recovery.restore', {
        plan_id: plan.id,
        token: plan.token,
        ...(acceptUnverified ? { accept_unverified: true } : {}),
      })
      setUnverified(null)
      setResult(data.result)
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['fs'] }),
        queryClient.invalidateQueries({ predicate: q => String(q.queryKey[0]).startsWith('fs.') }),
        invalidate('recovery.list', 'vault.recovery.status', 'recovery.costs'),
      ])
      const r = data.result
      if (r.state === 'done') notify.success('Restore finished', `${formatInt(r.restored)} restored`)
      else notify.info(`Restore ${r.state}`, 'Some items were not restored; see the details.')
      onRestored?.(r)
    } catch (e) {
      if (needsCode(e, RECOVERY_CODES.unverifiedVersion)) setUnverified(e)
      else if (needsCode(e, RECOVERY_CODES.planExpired) || needsCode(e, RECOVERY_CODES.restoreConfirm)) {
        // The plan (or its token) is no longer valid: plan again and show the fresh preview. Nothing ran.
        setUnverified(null)
        const fresh = await makePlan()
        if (fresh) {
          setReplanned(true)
          notify.info('The plan expired', 'Here is a fresh preview. Review it and restore again.')
        }
      } else setRestoreError(e)
    } finally {
      setRestoring(false)
    }
  }

  const blocked = Boolean(plan && plan.blockers.length)
  const nothing = Boolean(plan && plan.creates + plan.overwrites + plan.removals === 0)
  const expired = Boolean(
    plan && (plan.state === 'expired' || (plan.expires_at && Date.parse(plan.expires_at) < Date.now())),
  )

  return (
    <Dialog open onOpenChange={o => !o && onClose()}>
      <DialogContent
        size="xl"
        title={result ? 'Restore result' : 'Restore preview'}
        description={plan ? plan.source_label : 'Working out what a restore would change. Nothing is changed yet.'}
        data-testid="restore-preview"
        footer={
          result ?
            <Button variant="primary" onClick={onClose}>
              Done
            </Button>
          : <>
              <Button variant="ghost" onClick={onClose}>
                Cancel
              </Button>
              {expired ?
                <Button onClick={() => void makePlan()} loading={planning}>
                  Plan again
                </Button>
              : null}
              <Button
                variant={plan && plan.overwrites + plan.removals > 0 ? 'danger-solid' : 'primary'}
                disabled={!plan || blocked || nothing || planning || expired || Boolean(unverified)}
                loading={restoring}
                onClick={() => void restore(false)}
                data-testid="restore-confirm">
                <RotateLeftIcon aria-hidden />
                {plan ?
                  `Restore ${formatInt(plan.creates + plan.overwrites + plan.removals)} item${plan.creates + plan.overwrites + plan.removals === 1 ? '' : 's'}`
                : 'Restore'}
              </Button>
            </>
        }>
        {result ?
          <RestoreResultView result={result} />
        : planning && !plan ?
          <div className="flex justify-center py-12">
            <Spinner className="size-6" label="Planning the restore" />
          </div>
        : planError && !plan ?
          <div className="space-y-3">
            <InlineError error={planError} />
            <Button onClick={() => void makePlan()}>Try again</Button>
          </div>
        : plan ?
          <PlanView plan={plan} replanned={replanned} />
        : null}

        {unverified && !result ?
          <UnverifiedAck
            error={unverified}
            busy={restoring}
            onAccept={() => void restore(true)}
            onCancel={() => setUnverified(null)}
          />
        : null}
        {planError && plan ?
          <InlineError error={planError} className="mt-3" />
        : null}
        <InlineError error={restoreError} className="mt-3" />
      </DialogContent>
    </Dialog>
  )
}

const COUNT_KEYS: { key: keyof RecoveryPlan; action: RecoveryItemAction; label: string }[] = [
  { key: 'creates', action: 'create', label: 'Create' },
  { key: 'overwrites', action: 'overwrite', label: 'Overwrite' },
  { key: 'removals', action: 'remove', label: 'Remove' },
  { key: 'skips', action: 'skip', label: 'Skip (unchanged)' },
  { key: 'conflicts', action: 'conflict', label: 'Conflict' },
  { key: 'unavailable', action: 'unavailable', label: 'Unavailable' },
]

const PlanView = ({ plan, replanned }: { plan: RecoveryPlan; replanned: boolean }) => (
  <div className="space-y-4">
    {replanned ?
      <Notice tone="info" icon={CircleInfoIcon} role="status">
        The previous plan expired, so this is a fresh plan. Check it again before restoring.
      </Notice>
    : null}

    <Notice
      tone={plan.atomic ? 'info' : 'warn'}
      icon={plan.atomic ? CircleInfoIcon : TriangleExclamationIcon}
      title={plan.atomic ? 'Atomic snapshot' : 'Not an atomic snapshot'}
      role="note"
      testId="restore-consistency">
      {plan.atomic ? null : <p className="text-fg font-medium">{ATOMIC_FALSE_NOTE}</p>}
      {plan.consistency_note && plan.consistency_note !== ATOMIC_FALSE_NOTE ?
        <p className={plan.atomic ? undefined : 'mt-1'}>{plan.consistency_note}</p>
      : null}
    </Notice>

    {plan.blockers.length ?
      <Notice
        tone="danger"
        icon={TriangleExclamationIcon}
        title="This restore can’t run"
        role="alert"
        testId="restore-blockers">
        <BulletList items={plan.blockers} />
      </Notice>
    : null}
    {plan.warnings.length ?
      <Notice tone="warn" icon={TriangleExclamationIcon} title="Warnings" role="note">
        <BulletList items={plan.warnings} />
      </Notice>
    : null}

    <DefinitionList
      items={[
        ['Restoring', plan.source_label],
        ...(plan.point_in_time ? ([['As of', timeText(plan.at)]] as [React.ReactNode, React.ReactNode][]) : []),
        [
          'Destination',
          plan.destination ? <span className="font-mono text-xs">{plan.destination}</span> : 'Original locations',
        ],
        ...(plan.point_in_time ?
          ([['Files created since then', plan.prune ? 'Removed' : 'Left in place']] as [
            React.ReactNode,
            React.ReactNode,
          ][])
        : []),
        ['Estimated provider cost', <EstimateText key="e" estimate={plan.estimate} />],
        ['Plan valid until', timeText(plan.expires_at)],
      ]}
    />

    <div className="flex flex-wrap gap-2" data-testid="restore-counts">
      {COUNT_KEYS.map(c => (
        <Badge key={c.key} tone={(plan[c.key] as number) > 0 ? ACTION_TONE[c.action] : 'neutral'}>
          {c.label}: {formatInt(plan[c.key] as number)}
        </Badge>
      ))}
    </div>

    <ItemsTable plan={plan} />
  </div>
)

const EstimateText = ({ estimate }: { estimate: RecoveryRequestEstimate }) => {
  const requests =
    estimate.get_requests
    + estimate.head_requests
    + estimate.put_requests
    + estimate.copy_requests
    + estimate.list_requests
  if (!requests && !estimate.download_bytes && !estimate.upload_bytes && !estimate.cost)
    return <span className="text-fg-subtle">No provider requests (local restore)</span>
  return (
    <span>
      {estimate.cost ?
        <span className="tabular text-fg">{moneyText(estimate.cost)}</span>
      : <span className="text-fg-subtle">
          cannot be estimated{estimate.unpriced_reason ? `: ${estimate.unpriced_reason}` : ''}
        </span>
      }
      <span className="text-fg-subtle block text-xs">
        {[
          estimate.copy_requests ? `${formatInt(estimate.copy_requests)} COPY` : null,
          estimate.get_requests ? `${formatInt(estimate.get_requests)} GET` : null,
          estimate.put_requests ? `${formatInt(estimate.put_requests)} PUT` : null,
          estimate.head_requests ? `${formatInt(estimate.head_requests)} HEAD` : null,
          estimate.list_requests ? `${formatInt(estimate.list_requests)} LIST` : null,
          estimate.download_bytes ? `${formatBytes(estimate.download_bytes)} down` : null,
          estimate.upload_bytes ? `${formatBytes(estimate.upload_bytes)} up` : null,
        ]
          .filter(Boolean)
          .join(' · ')}
      </span>
    </span>
  )
}

const ItemsTable = ({ plan }: { plan: RecoveryPlan }) => {
  const rows = plan.items.slice(0, ROW_CAP)
  if (!plan.items.length) return <p className="text-fg-subtle text-sm">The plan has no items.</p>
  return (
    <div>
      <SubHeading>Items</SubHeading>
      <div className="rounded-control border-line max-h-[22rem] overflow-auto border">
        <table className="w-full text-sm" data-testid="restore-items">
          <thead className="text-fg-subtle bg-surface-1 sticky top-0 text-left text-xs">
            <tr>
              <th className="px-3 py-2 font-medium">Action</th>
              <th className="px-3 py-2 font-medium">Destination</th>
              <th className="hidden px-3 py-2 font-medium md:table-cell">Source</th>
              <th className="px-3 py-2 font-medium">Size</th>
              <th className="hidden px-3 py-2 font-medium sm:table-cell">Method</th>
            </tr>
          </thead>
          <tbody className="divide-line/60 divide-y">
            {rows.map((item, i) => (
              <tr key={`${item.source_id}-${item.destination_path}-${i}`} data-action={item.action}>
                <td className="px-3 py-2 align-top">
                  <Badge tone={ACTION_TONE[item.action] ?? 'neutral'}>{ACTION_LABEL[item.action] ?? item.action}</Badge>
                </td>
                <td className="px-3 py-2 align-top">
                  <span className="font-mono text-xs break-all">{item.destination_path}</span>
                  {item.notes.length ?
                    <span className="text-fg-subtle block text-xs">{item.notes.join(' ')}</span>
                  : null}
                </td>
                <td className="hidden px-3 py-2 align-top md:table-cell">
                  <span className="font-mono text-xs break-all">{item.source_path}</span>
                  <span className="text-fg-faint block font-mono text-[11px]">{item.source_id}</span>
                </td>
                <td className="tabular px-3 py-2 align-top">{sizeText(item.size_bytes)}</td>
                <td className="text-fg-subtle hidden px-3 py-2 align-top text-xs sm:table-cell">
                  {METHOD_LABEL[item.method] ?? item.method ?? DASH}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {plan.items.length > ROW_CAP ?
        <p className="text-fg-subtle mt-1.5 text-xs">
          Showing the first {formatInt(ROW_CAP)} of {formatInt(plan.items.length)} items; the counts above cover all of
          them.
        </p>
      : null}
    </div>
  )
}

const UnverifiedAck = ({
  error,
  busy,
  onAccept,
  onCancel,
}: {
  error: WsError
  busy: boolean
  onAccept: () => void
  onCancel: () => void
}) => {
  const id = useId()
  const [ack, setAck] = useState(false)
  return (
    <div className="mt-4" data-testid="restore-unverified">
      <Notice tone="warn" icon={TriangleExclamationIcon} title="This version wasn’t written by Vaulthalla" role="alert">
        <p>{error.message}</p>
        <p className="mt-1">
          Vaulthalla can’t verify its contents or encryption metadata. It may have been written by another application
          or directly in the bucket.
        </p>
        <label htmlFor={id} className="text-fg mt-3 flex items-start gap-2.5">
          <Checkbox id={id} className="mt-0.5" checked={ack} onCheckedChange={setAck} />
          <span>I understand and want to restore this unverified version anyway.</span>
        </label>
        <div className="mt-3 flex flex-wrap gap-2">
          <Button size="sm" variant="ghost" onClick={onCancel}>
            Don’t restore it
          </Button>
          <Button size="sm" variant="danger" disabled={!ack} loading={busy} onClick={onAccept}>
            Restore the unverified version
          </Button>
        </div>
      </Notice>
    </div>
  )
}

const OUTCOME_TONE: Record<string, 'ok' | 'warn' | 'danger' | 'neutral' | 'unknown'> = {
  restored: 'ok',
  removed: 'ok',
  skipped: 'neutral',
  conflict: 'warn',
  failed: 'danger',
  unavailable: 'unknown',
}

const RestoreResultView = ({ result }: { result: RecoveryRestoreResult }) => {
  const notRestored = result.items.filter(i => i.outcome !== 'restored' && i.outcome !== 'removed')
  return (
    <div className="space-y-4" data-testid="restore-result">
      <div className="flex flex-wrap items-center gap-2">
        <Badge
          tone={
            result.state === 'done' ? 'ok'
            : result.state === 'partial' ?
              'warn'
            : 'danger'
          }
          dot>
          {result.state === 'done' ?
            'Done'
          : result.state === 'partial' ?
            'Partly done'
          : 'Failed'}
        </Badge>
        <span className="text-fg-muted tabular text-sm">
          {formatInt(result.restored)} restored · {formatInt(result.removed)} removed · {formatInt(result.skipped)}{' '}
          skipped · {formatInt(result.conflicts)} conflicts · {formatInt(result.failed)} failed ·{' '}
          {formatInt(result.unavailable)} unavailable
        </span>
      </div>
      {result.conflicts ?
        <Notice tone="warn" role="note">
          A conflict means the destination changed after the plan was made, so it was left alone. Plan again to include
          it.
        </Notice>
      : null}
      {notRestored.length ?
        <div className="rounded-control border-line max-h-[22rem] overflow-auto border">
          <table className="w-full text-sm">
            <thead className="text-fg-subtle bg-surface-1 sticky top-0 text-left text-xs">
              <tr>
                <th className="px-3 py-2 font-medium">Outcome</th>
                <th className="px-3 py-2 font-medium">Destination</th>
                <th className="px-3 py-2 font-medium">Detail</th>
              </tr>
            </thead>
            <tbody className="divide-line/60 divide-y">
              {notRestored.slice(0, ROW_CAP).map((item, i) => (
                <tr key={`${item.destination_path}-${i}`}>
                  <td className="px-3 py-2 align-top">
                    <Badge tone={OUTCOME_TONE[item.outcome] ?? 'unknown'}>{item.outcome}</Badge>
                  </td>
                  <td className="px-3 py-2 align-top font-mono text-xs break-all">{item.destination_path}</td>
                  <td className="text-fg-subtle px-3 py-2 align-top text-xs">{item.error ?? DASH}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      : <p className="text-fg-subtle text-sm">Every item was restored.</p>}
    </div>
  )
}

export default RestorePreviewDialog
