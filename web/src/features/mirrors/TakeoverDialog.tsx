'use client'

import React, { useId, useState } from 'react'
import { useWs, useWsMutation } from '@/lib/query'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Dialog, DialogClose, DialogContent } from '@/components/ui/Dialog'
import { Field, Input } from '@/components/ui/Field'
import { TriangleExclamationIcon } from '@/components/ui/icons'
import { PeerError } from '@/features/peers/parts'
import { MIRROR_COPY as C } from '@/features/mirrors/copy'
import { MIRROR_READS, peerName, type MirroredVault, type TakeoverResult } from '@/features/mirrors/model'

// Take over as the vault's core on a mirror whose core is gone (mirror.takeover {vault_id, confirm}): what it does, the
// warning that the old core may hold changes this server never received, what the preview says becomes of the changes
// and missing files here, then the vault's name typed. The data.destroy step-up runs through the shell's dialog
// ("Take over as a vault’s core"). A refusal (the core still answers: mirror_core_reachable) shows the server's
// sentence. Loaded with next/dynamic, mounted while open.
export default function TakeoverDialog({
  row,
  open,
  onOpenChange,
}: {
  row: MirroredVault
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const ids = useId()
  const peer = peerName(row)
  const [typed, setTyped] = useState('')
  const [result, setResult] = useState<TakeoverResult | null>(null)
  // The same read (and cache entry) as the vault page: the pending changes and missing files it reports.
  const preview = useWs('mirror.detach.preview', { vault_id: row.vault_id }, { enabled: open, retry: false, select: d => d.preview })
  const p = preview.data

  const take = useWsMutation<'mirror.takeover', void>('mirror.takeover', {
    toPayload: () => ({ vault_id: row.vault_id, confirm: typed }),
    invalidates: [...MIRROR_READS, 'storage.vault.list', 'storage.vault.get'],
    onSuccess: data => setResult(data),
  })
  const ready = typed === row.vault_name

  const footer =
    result ?
      <DialogClose asChild>
        <Button variant="secondary">{C.done}</Button>
      </DialogClose>
    : <>
        <DialogClose asChild>
          <Button variant="ghost" disabled={take.isPending}>
            {C.keepGoing}
          </Button>
        </DialogClose>
        <Button variant="danger-solid" loading={take.isPending} disabled={!ready} onClick={() => take.mutate()} data-testid="mirror-takeover-confirm">
          {take.isPending ? C.takingOver : C.takeoverConfirm}
        </Button>
      </>

  return (
    <Dialog open={open} onOpenChange={next => (take.isPending ? undefined : onOpenChange(next))}>
      <DialogContent
        title={C.takeoverTitle(row.vault_name)}
        description={result ? undefined : C.takeoverBody(peer)}
        size="md"
        footer={footer}
        data-testid="mirror-takeover-dialog">
        {result ?
          <div className="space-y-2" data-testid="mirror-takeover-result" aria-live="polite">
            <Badge tone="ok" dot>
              {C.tookOver}
            </Badge>
            <p className="text-sm text-fg">{C.tookOverBody(result.pending_made_local, result.held)}</p>
            {result.contents_missing ? <p className="text-sm text-fg-muted">{C.takeoverMissing(result.contents_missing)}</p> : null}
            {result.warning ?
              <p className="text-sm text-fg-muted" data-testid="mirror-takeover-warning">
                {result.warning}
              </p>
            : null}
          </div>
        : <div className="space-y-4">
            <div className="rounded-control border border-warn-line bg-warn-soft p-3" role="note" data-testid="mirror-takeover-warn">
              <p className="flex items-center gap-2 text-sm font-semibold text-warn">
                <TriangleExclamationIcon className="size-4 shrink-0" aria-hidden />
                {C.takeoverWarnTitle(peer)}
              </p>
              <p className="mt-1.5 text-sm text-fg-muted">{C.takeoverWarnBody(peer)}</p>
            </div>
            {p && (p.pending_changes || p.missing_count) ?
              <ul className="list-disc space-y-1 pl-5 text-sm text-fg-muted" data-testid="mirror-takeover-preview">
                {p.pending_changes ? <li>{C.takeoverPending(p.pending_changes)}</li> : null}
                {p.missing_count ? <li>{C.takeoverMissing(p.missing_count)}</li> : null}
              </ul>
            : null}
            <p className="text-xs text-fg-subtle">{C.takeoverSwitchHint(peer)}</p>
            <Field label={C.takeoverType(row.vault_name)} htmlFor={`${ids}-typed`}>
              <Input id={`${ids}-typed`} value={typed} autoComplete="off" onChange={e => setTyped(e.target.value)} data-testid="mirror-takeover-typed" />
            </Field>
            <PeerError error={take.error} fallback={C.takeoverFailed} />
          </div>
        }
      </DialogContent>
    </Dialog>
  )
}
