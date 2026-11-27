'use client'

import React, { useId, useState } from 'react'
import { useWsMutation } from '@/lib/query'
import { api } from '@/lib/session'
import { isWsError } from '@/lib/ws/errors'
import { formatDateTime, formatRelative } from '@/lib/format'
import { Badge } from '@/components/ui/Badge'
import { Checkbox } from '@/components/ui/Choice'
import { confirm } from '@/components/ui/Confirm'
import { DataTable, type Column } from '@/components/ui/DataTable'
import { Label } from '@/components/ui/Field'
import { IconButton } from '@/components/ui/IconButton'
import { QueryState } from '@/components/ui/State'
import { notify } from '@/components/ui/Toast'
import { ArrowsRotateIcon, DownloadIcon, TrashIcon } from '@/components/ui/icons'
import { PeerError } from '@/features/peers/parts'
import { CommandCopy } from '@/features/vaults/CommandCopy'
import { MIRROR_COPY as C } from '@/features/mirrors/copy'
import { MIRROR_READS, canDownloadHeld, decodeBase64, heldPath, heldWhat, type HeldChange } from '@/features/mirrors/model'
import { useHeld } from '@/features/mirrors/queries'

const STATE_TONE: Record<string, 'warn' | 'info' | 'neutral'> = { open: 'warn', retried: 'info', discarded: 'neutral' }

// Changes made on this server that the core refused, for one vault (mirror.held.list {vault_id}): what was done to
// which file, the core's reason in its own words, and Retry / Discard / save the person's version (mirror.held.get).
export const HeldChanges = ({ vaultId, live }: { vaultId: number; live: boolean }) => {
  const ids = useId()
  const [showAll, setShowAll] = useState(false)
  const held = useHeld(vaultId, showAll)
  const [error, setError] = useState<unknown>(null)
  const [tooLarge, setTooLarge] = useState<HeldChange | null>(null)
  const [downloading, setDownloading] = useState<number | null>(null)

  const retry = useWsMutation('mirror.held.retry', {
    toPayload: (h: HeldChange) => ({ id: h.id }),
    invalidates: [...MIRROR_READS],
    onSuccess: () => notify.success(C.heldRetried, C.heldRetriedHint),
  })
  const discard = useWsMutation('mirror.held.discard', {
    toPayload: (h: HeldChange) => ({ id: h.id }),
    invalidates: [...MIRROR_READS],
    onSuccess: () => notify.success(C.heldDiscarded),
  })

  const askDiscard = async (h: HeldChange) => {
    const ok = await confirm({
      title: C.heldDiscardTitle,
      description: h.kind === 'conflict' ? C.heldDiscardConflictBody : C.heldDiscardBody(heldPath(h)),
      confirmLabel: C.heldDiscard,
      tone: 'danger',
    })
    if (!ok) return
    setError(null)
    discard.mutate(h, { onError: setError })
  }

  const download = async (h: HeldChange) => {
    setError(null)
    setTooLarge(null)
    setDownloading(h.id)
    try {
      const res = await api.send('mirror.held.get', { id: h.id })
      const blob = new Blob([decodeBase64(res.content_b64) as BlobPart])
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = res.name || h.name || 'held-version'
      document.body.appendChild(a)
      a.click()
      a.remove()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
    } catch (e) {
      if (isWsError(e) && e.code === 'too_large') setTooLarge(h)
      else setError(e)
    } finally {
      setDownloading(null)
    }
  }

  const columns: Column<HeldChange>[] = [
    {
      key: 'what',
      header: 'Change',
      sortValue: h => heldPath(h).toLowerCase(),
      cell: h => (
        <span className="flex min-w-0 flex-col">
          <span className="truncate font-medium text-fg" title={heldPath(h)} data-testid="mirror-held-path">
            {heldPath(h)}
          </span>
          <span className="text-xs text-fg-subtle">
            {heldWhat(h)} · {C.heldBy(h.person.id)}
          </span>
        </span>
      ),
    },
    {
      key: 'reason',
      header: 'Why the core refused it',
      cell: h => (
        <span className="text-xs break-words text-fg-muted" data-testid="mirror-held-reason">
          {h.reason || h.reason_code}
        </span>
      ),
      hideBelow: 'md',
    },
    {
      key: 'state',
      header: 'State',
      sortValue: h => h.state,
      cell: h => (
        <Badge tone={STATE_TONE[h.state] ?? 'neutral'} className="h-5 px-2 text-[11px]">
          {C.heldStates[h.state] ?? h.state}
        </Badge>
      ),
      hideBelow: 'sm',
    },
    {
      key: 'when',
      header: 'When',
      sortValue: h => h.created_at,
      cell: h => (
        <span className="whitespace-nowrap tabular text-fg-muted" title={formatDateTime(h.created_at)}>
          {formatRelative(h.created_at)}
        </span>
      ),
      hideBelow: 'lg',
    },
  ]

  return (
    <section id="held-changes" aria-labelledby={`${ids}-title`} className="mt-8" data-testid="mirror-held">
      <h2 id={`${ids}-title`} className="text-[15px] font-semibold text-fg">
        {C.heldTitle}
      </h2>
      <p className="mt-0.5 mb-3 max-w-3xl text-sm text-fg-subtle">{C.heldBody}</p>
      <PeerError error={error} fallback={C.heldFailed} className="mb-3" />
      {tooLarge ?
        <div className="mb-3 rounded-control border border-line bg-surface-1 p-3 text-sm text-fg-muted" role="status">
          {C.heldTooLarge}
          <CommandCopy command={`vh mirror save ${tooLarge.id} ./${tooLarge.name || 'held-version'}`} label="Copy command" />
        </div>
      : null}
      <QueryState query={held}>
        {data => (
          <DataTable
            rows={data.held}
            columns={columns}
            rowKey={h => h.id}
            initialSort={{ key: 'when', dir: 'desc' }}
            empty={C.heldEmpty}
            toolbar={
              <span className="flex items-center gap-2">
                <Checkbox id={`${ids}-all`} checked={showAll} onCheckedChange={setShowAll} data-testid="mirror-held-show-all" />
                <Label htmlFor={`${ids}-all`} className="text-fg-muted">
                  {C.heldShowAll}
                </Label>
              </span>
            }
            rowActions={h =>
              h.state !== 'open' ? null : (
                <span className="inline-flex items-center gap-0.5">
                  {canDownloadHeld(h) ?
                    <IconButton
                      label={`${C.heldDownload}: ${heldPath(h)}`}
                      icon={DownloadIcon}
                      size="icon-sm"
                      disabled={downloading === h.id}
                      onClick={() => void download(h)}
                      data-testid={`mirror-held-download-${h.id}`}
                    />
                  : null}
                  {h.kind === 'held' ?
                    <IconButton
                      label={live ? `${C.heldRetry}: ${heldPath(h)}` : C.heldRetryNeedsLive}
                      icon={ArrowsRotateIcon}
                      size="icon-sm"
                      disabled={!live || (retry.isPending && retry.variables?.id === h.id)}
                      onClick={() => {
                        setError(null)
                        retry.mutate(h, { onError: setError })
                      }}
                      data-testid={`mirror-held-retry-${h.id}`}
                    />
                  : null}
                  <IconButton
                    label={`${C.heldDiscard}: ${heldPath(h)}`}
                    icon={TrashIcon}
                    size="icon-sm"
                    className="hover:text-danger"
                    disabled={discard.isPending && discard.variables?.id === h.id}
                    onClick={() => void askDiscard(h)}
                    data-testid={`mirror-held-discard-${h.id}`}
                  />
                </span>
              )
            }
          />
        )}
      </QueryState>
    </section>
  )
}
