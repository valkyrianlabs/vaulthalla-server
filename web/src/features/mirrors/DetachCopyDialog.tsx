'use client'

import React, { useId, useState } from 'react'
import Link from 'next/link'
import { useWs, useWsMutation } from '@/lib/query'
import { formatBytes, formatDateTime } from '@/lib/format'
import { useSession } from '@/lib/session'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { confirm } from '@/components/ui/Confirm'
import { Dialog, DialogClose, DialogContent } from '@/components/ui/Dialog'
import { Field, Input, Select } from '@/components/ui/Field'
import { Meter } from '@/components/ui/Stat'
import { Skeleton } from '@/components/ui/State'
import { notify } from '@/components/ui/Toast'
import { TriangleExclamationIcon, VaultIcon } from '@/components/ui/icons'
import { useUserNames } from '@/features/vaults/hooks'
import { CopyButton, PeerError } from '@/features/peers/parts'
import { MIRROR_COPY as C } from '@/features/mirrors/copy'
import { MIRROR_READS, SKIP_TEXT, copyProgress, peerName, type CopyJob, type MirroredVault } from '@/features/mirrors/model'

// How many skipped files the dialog lists; the copy button carries every one the server listed.
const SHOWN_SKIPPED = 50
// The copy's progress while it runs.
const COPY_POLL_MS = 1_500

// Detach a copy (mirror.detach.copy {vault_id, name, owner}): a new, separate vault written from the copy held here,
// which stays as it is. The newest job (mirror.detach.copy.get) decides what shows: a running one its progress (entries
// and bytes) and Cancel (mirror.detach.copy.cancel), one this dialog started its outcome with the files left out,
// otherwise the form (name, owner). Loaded with next/dynamic, mounted while open.
export default function DetachCopyDialog({
  row,
  open,
  onOpenChange,
}: {
  row: MirroredVault
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const ids = useId()
  const me = useSession(state => state.user)
  const { users, canList } = useUserNames()
  const peer = peerName(row)
  const [name, setName] = useState('')
  const [owner, setOwner] = useState('')
  // The job this dialog started (or found running): its outcome stays shown once it ends.
  const [followed, setFollowed] = useState<number | null>(null)

  const job = useWs('mirror.detach.copy.get', { vault_id: row.vault_id }, {
    enabled: open,
    staleTime: 0,
    select: d => d.copy,
    refetchInterval: q => (q.state.data?.copy?.state === 'running' ? COPY_POLL_MS : false),
  })
  const start = useWsMutation<'mirror.detach.copy', void>('mirror.detach.copy', {
    toPayload: () => ({ vault_id: row.vault_id, name: name.trim() || null, owner: owner || null }),
    invalidates: [...MIRROR_READS, 'storage.vault.list'],
    onSuccess: data => {
      setFollowed(data.copy.id)
      notify.success(C.copyStarted(data.copy.name))
    },
  })
  const cancel = useWsMutation<'mirror.detach.copy.cancel', void>('mirror.detach.copy.cancel', {
    toPayload: () => ({ vault_id: row.vault_id }),
    invalidates: [...MIRROR_READS, 'storage.vault.list'],
  })

  // Until the read catches up with the copy just started, the start's answer stands in for it.
  const read = job.data ?? null
  const j = followed !== null && start.data && (!read || read.id < followed) ? start.data.copy : read
  const shown: CopyJob | null = j && (j.state === 'running' || j.id === followed) ? j : null
  const askCancel = async () => {
    if (!shown) return
    const ok = await confirm({ title: C.copyCancelTitle(shown.name), description: C.copyCancelBody, confirmLabel: C.copyCancel, cancelLabel: C.keepGoing, tone: 'danger' })
    if (ok) cancel.mutate()
  }
  const again = () => {
    setFollowed(null)
    setName('')
    start.reset()
  }

  const footer =
    shown?.state === 'running' ?
      <>
        <DialogClose asChild>
          <Button variant="ghost">{C.done}</Button>
        </DialogClose>
        <Button variant="danger" loading={cancel.isPending || shown.cancel_requested} onClick={() => void askCancel()} data-testid="mirror-copy-cancel">
          {shown.cancel_requested ? C.copyCancelling : C.copyCancel}
        </Button>
      </>
    : shown ?
      <>
        <Button variant="ghost" onClick={again} data-testid="mirror-copy-again">
          {C.copyAgain}
        </Button>
        <DialogClose asChild>
          <Button variant="secondary">{C.done}</Button>
        </DialogClose>
      </>
    : <>
        <DialogClose asChild>
          <Button variant="ghost">{C.keepGoing}</Button>
        </DialogClose>
        <Button variant="primary" loading={start.isPending} disabled={job.isLoading} onClick={() => start.mutate()} data-testid="mirror-copy-start">
          {C.copyStart}
        </Button>
      </>

  return (
    <Dialog open={open} onOpenChange={next => (start.isPending ? undefined : onOpenChange(next))}>
      <DialogContent
        title={C.copyTitle(row.vault_name)}
        description={shown ? undefined : C.copyBody(peer, row.role === 'mirror')}
        size="lg"
        footer={footer}
        data-testid="mirror-copy-dialog">
        {job.isLoading ?
          <div className="space-y-2" aria-busy="true" aria-label={C.copyLoading}>
            <Skeleton />
            <Skeleton className="w-2/3" />
          </div>
        : shown ?
          <CopyOutcome job={shown} />
        : <div className="space-y-4" data-testid="mirror-copy-form">
            <p className="text-sm text-fg-muted">{C.copyWhat}</p>
            {j ? <p className="text-xs text-fg-subtle">{C.copyLast(j.name, formatDateTime(j.finished_at ?? j.updated_at))}</p> : null}
            <Field label={C.copyName} htmlFor={`${ids}-name`} hint={C.copyNameHint(row.vault_name)}>
              <Input id={`${ids}-name`} value={name} autoComplete="off" placeholder={`${row.vault_name} copy`} onChange={e => setName(e.target.value)} data-testid="mirror-copy-name" />
            </Field>
            <Field label={C.copyOwner} htmlFor={`${ids}-owner`} hint={C.copyOwnerHint}>
              {canList ?
                <Select id={`${ids}-owner`} value={owner} onChange={e => setOwner(e.target.value)} data-testid="mirror-copy-owner">
                  <option value="">{C.detachOwnerMe(me?.name ?? '')}</option>
                  {users
                    .filter(u => u.name !== me?.name)
                    .map(u => (
                      <option key={u.id} value={u.name}>
                        {u.name}
                      </option>
                    ))}
                </Select>
              : <Input id={`${ids}-owner`} value={owner} placeholder={C.detachOwnerMe(me?.name ?? '')} onChange={e => setOwner(e.target.value)} data-testid="mirror-copy-owner" />}
            </Field>
            <PeerError error={start.error} fallback={C.copyFailed} />
          </div>
        }
        {job.error ? <PeerError error={job.error} fallback={C.loadFailed} className="mt-3" /> : null}
        <PeerError error={cancel.error} fallback={C.copyCancelFailed} className="mt-3" />
      </DialogContent>
    </Dialog>
  )
}

const CopyOutcome = ({ job }: { job: CopyJob }) => {
  const progress = copyProgress(job, formatBytes)
  const skippedList = job.skipped.map(s => s.path).join('\n')
  return (
    <div className="space-y-4" data-testid="mirror-copy-job" aria-live="polite">
      {job.state === 'running' ?
        <div className="space-y-2">
          <Badge tone="info" dot>
            <span data-testid="mirror-copy-state">{C.copyRunning}</span>
          </Badge>
          <p className="text-sm text-fg-muted">{C.copyRunningBody(job.name)}</p>
          <Meter ratio={progress.ratio} label={C.copyRunning} />
          <p className="text-xs text-fg-subtle tabular" data-testid="mirror-copy-progress">
            {progress.text}
          </p>
        </div>
      : job.state === 'finished' ?
        <div className="space-y-2">
          <Badge tone="ok" dot>
            <span data-testid="mirror-copy-state">{C.copyFinished}</span>
          </Badge>
          <p className="text-sm text-fg">{C.copyFinishedBody(job.name)}</p>
          <p className="text-xs text-fg-subtle tabular">{progress.text}</p>
          {job.vault_id ?
            <Button variant="secondary" size="sm" asChild>
              <Link href={`/vaults/${job.vault_id}`}>
                <VaultIcon aria-hidden />
                {C.copyOpen}
              </Link>
            </Button>
          : null}
        </div>
      : job.state === 'failed' ?
        <div className="space-y-2">
          <Badge tone="danger" dot>
            <span data-testid="mirror-copy-state">{C.copyFailedState}</span>
          </Badge>
          <p className="text-sm text-fg-muted">{C.copyFailedBody(job.error)}</p>
        </div>
      : <div className="space-y-2">
          <Badge tone="neutral" dot>
            <span data-testid="mirror-copy-state">{C.copyCancelledState}</span>
          </Badge>
          <p className="text-sm text-fg-muted">{C.copyCancelledBody}</p>
        </div>
      }

      {job.state === 'finished' || job.skipped_count ?
        job.skipped_count ?
          <div className="rounded-control border border-warn-line bg-warn-soft p-3" data-testid="mirror-copy-skipped">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="flex items-center gap-2 text-sm font-semibold text-warn">
                <TriangleExclamationIcon className="size-4 shrink-0" aria-hidden />
                {C.copySkippedTitle(job.skipped_count)}
              </p>
              {job.skipped.length ? <CopyButton text={skippedList} label={C.copySkippedList} /> : null}
            </div>
            {job.skipped.length ?
              <ul className="mt-2 max-h-40 overflow-y-auto rounded-control border border-line bg-surface-1 px-3 py-2 text-xs text-fg-muted">
                {job.skipped.slice(0, SHOWN_SKIPPED).map(s => (
                  <li key={s.path} className="flex justify-between gap-3">
                    <span className="min-w-0 truncate font-mono" title={s.path}>
                      {s.path}
                    </span>
                    <span className="shrink-0 text-fg-subtle">
                      {SKIP_TEXT[s.reason] ?? s.reason} · <span className="tabular">{formatBytes(s.size_bytes)}</span>
                    </span>
                  </li>
                ))}
                {job.skipped_count > Math.min(job.skipped.length, SHOWN_SKIPPED) ?
                  <li className="pt-1 text-fg-subtle">{C.copySkippedMore(job.skipped_count - Math.min(job.skipped.length, SHOWN_SKIPPED))}</li>
                : null}
              </ul>
            : null}
          </div>
        : <p className="text-sm text-fg-muted">{C.copyNoneSkipped}</p>
      : null}
    </div>
  )
}
