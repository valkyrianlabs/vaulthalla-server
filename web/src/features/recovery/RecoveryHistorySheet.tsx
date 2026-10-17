'use client'

import React, { useId, useMemo, useState } from 'react'
import dynamic from 'next/dynamic'
import { Dialog, SheetContent } from '@/components/ui/Dialog'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Checkbox } from '@/components/ui/Choice'
import { confirm } from '@/components/ui/Confirm'
import { Field, Input } from '@/components/ui/Field'
import { EmptyState, InlineError } from '@/components/ui/State'
import { Spinner } from '@/components/ui/Spinner'
import { notify } from '@/components/ui/Toast'
import { Tooltip } from '@/components/ui/Tooltip'
import {
  ArrowsRotateIcon,
  CalendarClockIcon,
  ClockIcon,
  PlusIcon,
  RotateLeftIcon,
  TrashIcon,
} from '@/components/ui/icons'
import { api } from '@/lib/session'
import { invalidate, queryClient, useWs, wsKey } from '@/lib/query'
import { formatInt, formatRelative } from '@/lib/format'
import { isWsError } from '@/lib/ws/errors'
import type { RecoveryBackend, RecoveryPoint } from '@/models/recovery'
import {
  BACKEND_HINT,
  BACKEND_LABEL,
  moneyText,
  pointTime,
  REASON_LABEL,
  retentionLabel,
  sizeText,
  timeText,
} from '@/features/recovery/shared'
import type { PlanRequest } from '@/features/recovery/RestorePreviewDialog'

const RestorePreviewDialog = dynamic(() => import('@/features/recovery/RestorePreviewDialog'), { ssr: false })

export interface RecoveryTarget {
  path: string
  name: string
  kind: 'file' | 'dir'
}

const BACKENDS: RecoveryBackend[] = ['local_snapshot', 'local_version', 'provider_version']

// "Recovery history" for one file or folder (lazy, from Files). Lists every recovery point the daemon lets this
// account read for the path, grouped by where it lives, with restore and (for local points) delete.
const RecoveryHistorySheet = ({
  vaultId,
  isS3,
  target,
  onClose,
}: {
  vaultId: number
  isS3: boolean
  target: RecoveryTarget
  onClose: () => void
}) => {
  const payload = useMemo(() => ({ vault_id: vaultId, path: target.path }), [vaultId, target.path])
  const list = useWs('recovery.list', payload, { retry: false, staleTime: 0 })
  // Only to know whether snapshots can be created here; reading it may be refused (vault policy view).
  const status = useWs('vault.recovery.status', { vault_id: vaultId }, { retry: false })
  const [refreshing, setRefreshing] = useState(false)
  const [refreshError, setRefreshError] = useState<unknown>(null)
  const [restore, setRestore] = useState<PlanRequest | null>(null)

  const checkProvider = async () => {
    setRefreshing(true)
    setRefreshError(null)
    try {
      const data = await api.send('recovery.list', { ...payload, refresh_provider: true })
      queryClient.setQueryData(wsKey('recovery.list', payload), data)
    } catch (e) {
      setRefreshError(e)
    } finally {
      setRefreshing(false)
    }
  }

  const groups = useMemo(() => {
    const points = list.data?.points ?? []
    return BACKENDS.map(backend => ({
      backend,
      points: points
        .filter(p => p.backend === backend)
        .sort((a, b) => Date.parse(pointTime(b) ?? '') - Date.parse(pointTime(a) ?? '') || 0),
    })).filter(g => g.points.length || (g.backend === 'provider_version' && isS3))
  }, [list.data, isS3])

  const mode = status.data?.status.mode ?? null
  const total = list.data?.points.length ?? 0

  return (
    <Dialog open onOpenChange={o => !o && onClose()}>
      <SheetContent
        title={`Recovery history: ${target.name}`}
        description={
          target.kind === 'dir' ?
            'Recovery points for this folder and what is inside it.'
          : 'Earlier versions of this file.'
        }
        width="max-w-2xl"
        data-testid="recovery-history">
        <div className="space-y-5">
          {/* Point in time reconstructs from provider versions: S3 vaults only (the daemon refuses it elsewhere). */}
          {target.kind === 'dir' && isS3 ?
            <PointInTimeForm path={target.path} onPlan={req => setRestore({ vault_id: vaultId, ...req })} />
          : null}

          <SnapshotCreate vaultId={vaultId} target={target} mode={mode} />

          {isS3 ?
            <div className="rounded-control border-line bg-surface-1 border px-3 py-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="text-fg text-sm font-medium">Provider versions</p>
                <Button
                  size="sm"
                  variant="secondary"
                  loading={refreshing}
                  onClick={() => void checkProvider()}
                  data-testid="recovery-check-provider">
                  {refreshing ? null : <ArrowsRotateIcon aria-hidden />}
                  Check provider for versions
                </Button>
              </div>
              <p className="text-fg-subtle mt-1 text-xs">
                Asks the bucket which versions it holds for this path. Only metadata is listed (no file contents are
                downloaded), and the LIST requests count against this vault’s request budget.
              </p>
              <InlineError error={refreshError} className="mt-2" />
            </div>
          : null}

          {list.isPending ?
            <div className="flex justify-center py-10">
              <Spinner className="size-6" label="Loading recovery points" />
            </div>
          : list.error ?
            isWsError(list.error, 'denied', 'not_found') ?
              <EmptyState
                title="No recovery points you can see"
                description="Your role can’t read recovery points for this path."
              />
            : <InlineError error={list.error} />
          : total === 0 && !groups.length ?
            <EmptyState
              icon={ClockIcon}
              title="No recovery points yet"
              description="Snapshots, local versions and provider versions of this path will show up here."
            />
          : groups.map(g => (
              <section
                key={g.backend}
                aria-label={BACKEND_LABEL[g.backend]}
                data-testid={`recovery-group-${g.backend}`}>
                <div className="mb-2 flex items-baseline justify-between gap-2">
                  <h3 className="text-fg text-sm font-semibold">
                    {BACKEND_LABEL[g.backend]}{' '}
                    <span className="text-fg-subtle font-normal">({formatInt(g.points.length)})</span>
                  </h3>
                </div>
                <p className="text-fg-subtle -mt-1 mb-2 text-xs">{BACKEND_HINT[g.backend]}</p>
                {g.points.length ?
                  <ul className="space-y-2">
                    {g.points.map(p => (
                      <PointRow
                        key={p.id}
                        point={p}
                        onRestore={destination =>
                          setRestore({ recovery_id: p.id, ...(destination ? { destination } : {}) })
                        }
                      />
                    ))}
                  </ul>
                : <p className="text-fg-subtle text-sm">
                    None recorded yet. Use “Check provider for versions” to list what the bucket holds.
                  </p>
                }
              </section>
            ))
          }
        </div>
      </SheetContent>
      {restore ?
        <RestorePreviewDialog request={restore} onClose={() => setRestore(null)} />
      : null}
    </Dialog>
  )
}

const SnapshotCreate = ({
  vaultId,
  target,
  mode,
}: {
  vaultId: number
  target: RecoveryTarget
  mode: string | null
}) => {
  const id = useId()
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  // Unknown mode (status not readable): offer it and let the daemon decide.
  const off = mode !== null && mode !== 'local_snapshots'

  const create = async () => {
    setBusy(true)
    setError(null)
    try {
      const data = await api.send('recovery.snapshot.create', {
        vault_id: vaultId,
        path: target.path,
        ...(name.trim() ? { name: name.trim() } : {}),
      })
      await invalidate('recovery.list', 'vault.recovery.status')
      notify.success(
        'Snapshot created',
        data.detail.skipped.length ? `${data.detail.skipped.length} entries were skipped` : undefined,
      )
      setOpen(false)
      setName('')
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }

  if (!open)
    return (
      <div className="flex justify-end">
        <Tooltip content={off ? 'Snapshots are off for this vault (Vault settings → Recovery)' : null} side="left">
          <Button
            size="sm"
            variant="secondary"
            disabled={off}
            onClick={() => setOpen(true)}
            data-testid="recovery-snapshot-open">
            <PlusIcon aria-hidden />
            Create snapshot
          </Button>
        </Tooltip>
      </div>
    )
  return (
    <div className="rounded-control border-line bg-surface-1 space-y-3 border px-3 py-3">
      <Field
        label="Snapshot name"
        htmlFor={`${id}-name`}
        hint={`Optional. Captures ${target.kind === 'dir' ? 'every file under this folder' : 'this file'} as it is now.`}>
        <Input
          id={`${id}-name`}
          value={name}
          maxLength={200}
          onChange={e => setName(e.target.value)}
          placeholder="e.g. before cleanup"
        />
      </Field>
      <InlineError error={error} />
      <div className="flex justify-end gap-2">
        <Button size="sm" variant="ghost" onClick={() => setOpen(false)}>
          Cancel
        </Button>
        <Button size="sm" variant="primary" loading={busy} onClick={() => void create()}>
          Create snapshot
        </Button>
      </div>
    </div>
  )
}

// datetime-local is the browser's local time; the daemon gets epoch seconds.
const toEpoch = (value: string) => {
  const ms = new Date(value).getTime()
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : null
}

const PointInTimeForm = ({ path, onPlan }: { path: string; onPlan: (req: Omit<PlanRequest, 'vault_id'>) => void }) => {
  const id = useId()
  const [at, setAt] = useState('')
  const [prune, setPrune] = useState(false)
  const [destination, setDestination] = useState('')
  const epoch = at ? toEpoch(at) : null
  const future = epoch !== null && epoch * 1000 > Date.now()
  const offset = -new Date().getTimezoneOffset() / 60
  return (
    <div className="rounded-control border-line bg-surface-1 border px-3 py-3" data-testid="recovery-point-in-time">
      <p className="text-fg flex items-center gap-2 text-sm font-medium">
        <CalendarClockIcon className="size-4" aria-hidden />
        Restore this folder to a point in time
      </p>
      <p className="text-fg-subtle mt-1 text-xs">
        Rebuilds each file as it was at that moment from its own version history. It is a reconstruction from per-file
        times, not an atomic snapshot. You see a preview before anything changes.
      </p>
      <div className="mt-3 grid gap-3 sm:grid-cols-2">
        <Field
          label="As of"
          htmlFor={`${id}-at`}
          hint={`Your local time (UTC${offset >= 0 ? '+' : ''}${offset}).`}
          error={future ? 'Choose a time in the past' : undefined}>
          <Input id={`${id}-at`} type="datetime-local" step={1} value={at} onChange={e => setAt(e.target.value)} />
        </Field>
        <Field label="Restore into" htmlFor={`${id}-dest`} hint="Empty restores over the original paths.">
          <Input
            id={`${id}-dest`}
            className="font-mono"
            placeholder={path}
            value={destination}
            onChange={e => setDestination(e.target.value)}
          />
        </Field>
      </div>
      <label htmlFor={`${id}-prune`} className="text-fg-muted mt-3 flex items-start gap-2.5 text-sm">
        <Checkbox id={`${id}-prune`} className="mt-0.5" checked={prune} onCheckedChange={setPrune} />
        <span>
          Also remove files that didn’t exist at that time
          <span className="text-fg-subtle block text-xs">Off: files created since then are left in place.</span>
        </span>
      </label>
      <div className="mt-3 flex justify-end">
        <Button
          size="sm"
          variant="primary"
          disabled={epoch === null || future}
          onClick={() =>
            epoch !== null
            && onPlan({ path, at: epoch, prune, ...(destination.trim() ? { destination: destination.trim() } : {}) })
          }>
          Preview restore
        </Button>
      </div>
    </div>
  )
}

const keyBadge = (p: RecoveryPoint) => {
  if (!p.encryption.encrypted) return null
  if (!p.encryption.key_available)
    return (
      <Badge tone="danger" title="The encryption key version this was sealed with isn’t held by this vault any more.">
        Key {p.encryption.key_version} unavailable
      </Badge>
    )
  if (!p.encryption.key_current)
    return (
      <Badge tone="neutral" title="Sealed with an earlier key version; a restore re-encrypts it with the current key.">
        Older key ({p.encryption.key_version})
      </Badge>
    )
  return null
}

const PointRow = ({
  point: p,
  onRestore,
}: {
  point: RecoveryPoint
  onRestore: (destination: string | null) => void
}) => {
  const id = useId()
  const [restoring, setRestoring] = useState(false)
  const [destination, setDestination] = useState('')
  const [deleting, setDeleting] = useState(false)
  const deletable = p.backend !== 'provider_version'
  const pending = p.upstream_state === 'pending'
  const when = pointTime(p)

  const remove = async () => {
    const ok = await confirm({
      title: p.backend === 'local_snapshot' ? 'Delete this snapshot?' : 'Delete this version?',
      description:
        p.backend === 'local_snapshot' ?
          `“${p.name ?? p.id}” is removed for good. Files it shares with other snapshots or versions stay with them.`
        : `This earlier version from ${timeText(when)} is removed for good.`,
      confirmLabel: 'Delete',
      tone: 'danger',
    })
    if (!ok) return
    setDeleting(true)
    try {
      await api.send('recovery.point.delete', { recovery_id: p.id, confirm: true })
      await invalidate('recovery.list', 'vault.recovery.status')
      notify.success(p.backend === 'local_snapshot' ? 'Snapshot deleted' : 'Version deleted')
    } catch (e) {
      notify.error(e)
    } finally {
      setDeleting(false)
    }
  }

  return (
    <li className="rounded-control border-line border px-3 py-2.5" data-testid="recovery-point" data-recovery-id={p.id}>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-fg text-sm font-medium">
            {p.name ? `${p.name} · ` : ''}
            <span title={timeText(when)}>{timeText(when)}</span>
            <span className="text-fg-subtle ml-1.5 text-xs font-normal">{formatRelative(when)}</span>
          </p>
          <div className="mt-1 flex flex-wrap gap-1.5">
            {p.is_current ?
              <Badge tone="accent">Current</Badge>
            : null}
            {p.is_delete_marker ?
              <Badge tone="warn" title="The provider recorded a deletion here.">
                Delete marker
              </Badge>
            : null}
            {pending ?
              <Badge tone="info" title="Waiting to be uploaded to the provider.">
                Pending upload
              </Badge>
            : null}
            {p.origin === 'observed' ?
              <Badge tone="warn" title="Found in the bucket; not written by Vaulthalla.">
                Not written by Vaulthalla
              </Badge>
            : null}
            {p.storage_class ?
              <Badge tone="neutral">{p.storage_class}</Badge>
            : null}
            {keyBadge(p)}
            {!p.restorable ?
              <Badge tone="unknown">Not restorable</Badge>
            : null}
          </div>
        </div>
        <div className="flex shrink-0 gap-1.5">
          <Button
            size="sm"
            variant="secondary"
            disabled={!p.restorable}
            onClick={() => setRestoring(v => !v)}
            aria-expanded={restoring}
            data-testid="recovery-restore-open">
            <RotateLeftIcon aria-hidden />
            Restore…
          </Button>
          {deletable ?
            <Tooltip
              content={pending ? 'Waiting to be uploaded to the provider; it can be deleted once it is sent' : null}
              side="left">
              <Button
                size="sm"
                variant="ghost"
                aria-label="Delete"
                disabled={pending}
                loading={deleting}
                onClick={() => void remove()}>
                <TrashIcon aria-hidden />
              </Button>
            </Tooltip>
          : null}
        </div>
      </div>

      <p className="text-fg-subtle mt-1.5 text-xs">
        {[
          p.kind === 'directory' && p.file_count !== null ? `${formatInt(p.file_count)} files` : null,
          sizeText(p.size_bytes),
          p.reason ? (REASON_LABEL[p.reason] ?? p.reason) : null,
          retentionLabel(p.retention.policy)
            + (p.retention.expires_at ? ` (until ${timeText(p.retention.expires_at)})` : ''),
          p.backend === 'provider_version' ? `Monthly cost: ${moneyText(p.estimated_monthly_cost)}` : null,
        ]
          .filter(Boolean)
          .join(' · ')}
      </p>
      {p.retention.note ?
        <p className="text-fg-subtle mt-0.5 text-xs">{p.retention.note}</p>
      : null}
      {!p.restorable && p.unavailable_reason ?
        <p className="text-fg-muted mt-1 text-xs">{p.unavailable_reason}</p>
      : null}

      {restoring ?
        <div className="border-line mt-3 space-y-3 border-t pt-3">
          <Field
            label="Restore to"
            htmlFor={`${id}-dest`}
            hint="Empty restores over the original path. Enter another vault path to restore a copy there.">
            <Input
              id={`${id}-dest`}
              className="font-mono"
              placeholder={p.path}
              value={destination}
              onChange={e => setDestination(e.target.value)}
            />
          </Field>
          <div className="flex justify-end">
            <Button
              size="sm"
              variant="primary"
              onClick={() => onRestore(destination.trim() || null)}
              data-testid="recovery-plan">
              Preview restore
            </Button>
          </div>
        </div>
      : null}
    </li>
  )
}

export default RecoveryHistorySheet
