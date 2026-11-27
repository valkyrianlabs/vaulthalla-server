'use client'

import React, { useState } from 'react'
import { useWsMutation } from '@/lib/query'
import { isWsError } from '@/lib/ws/errors'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Checkbox } from '@/components/ui/Choice'
import { Dialog, DialogClose, DialogContent } from '@/components/ui/Dialog'
import { TriangleExclamationIcon } from '@/components/ui/icons'
import { PeerError } from '@/features/peers/parts'
import { MIRROR_COPY as C } from '@/features/mirrors/copy'
import { MIRROR_READS, accessText, peerName, reasonText, type MirroredVault, type SwitchResult } from '@/features/mirrors/model'

// The refusal that means the old core would keep no role on the vault on its new core: answered by resending with
// accept_no_access once the person ticks it.
const NO_ROLE = 'mirror_switch_no_role'

// A planned switch of the core role (mirror.switch). It waits for the outcome: switched (with the access the old core
// keeps), abandoned (with the reason; nothing changed) or still running. Loaded with next/dynamic, mounted while open.
export default function SwitchDialog({
  row,
  open,
  onOpenChange,
}: {
  row: MirroredVault
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const peer = peerName(row)
  const from = row.role === 'core' ? C.thisServer : peer
  const to = row.role === 'core' ? peer : C.thisServer
  const [result, setResult] = useState<SwitchResult | null>(null)
  const [noRole, setNoRole] = useState<string | null>(null)
  const [acceptNoAccess, setAcceptNoAccess] = useState(false)

  const run = useWsMutation('mirror.switch', {
    toPayload: (accept: boolean) => ({ vault_id: row.vault_id, ...(accept ? { accept_no_access: true } : {}) }),
    invalidates: [...MIRROR_READS],
    onSuccess: data => setResult(data),
  })
  const start = () => {
    setResult(null)
    run.mutate(Boolean(noRole && acceptNoAccess), {
      onError: e => {
        if (isWsError(e) && e.code === NO_ROLE) setNoRole(e.message)
      },
    })
  }
  const refusedNoRole = isWsError(run.error) && run.error.code === NO_ROLE
  // Sentences may start with "this server"; a server's own name keeps its spelling.
  const cap = (s: string) => (s.startsWith(C.thisServer) ? `T${s.slice(1)}` : s)

  const footer =
    result ?
      <DialogClose asChild>
        <Button variant="secondary">Done</Button>
      </DialogClose>
    : <>
        <DialogClose asChild>
          <Button variant="ghost" disabled={run.isPending}>
            {C.keepGoing}
          </Button>
        </DialogClose>
        <Button variant="primary" loading={run.isPending} disabled={Boolean(noRole) && !acceptNoAccess} onClick={start} data-testid="mirror-switch-confirm">
          {run.isPending ? C.switching : C.switchConfirm}
        </Button>
      </>

  return (
    <Dialog open={open} onOpenChange={next => (run.isPending ? undefined : onOpenChange(next))}>
      <DialogContent title={C.switchTitle(row.vault_name)} description={result ? undefined : cap(C.switchBody(from, to))} size="md" footer={footer} data-testid="mirror-switch-dialog">
        {result ?
          <div className="space-y-2" data-testid="mirror-switch-result" aria-live="polite">
            {result.outcome === 'switched' ?
              <>
                <Badge tone="ok" dot>
                  {C.switched}
                </Badge>
                <p className="text-sm text-fg">{cap(C.switchedBody(to))}</p>
                <p className="text-sm text-fg-muted" data-testid="mirror-switch-access">
                  {cap(accessText(result, from))}
                </p>
              </>
            : result.outcome === 'abandoned' ?
              <>
                <Badge tone="warn" dot>
                  {C.switchAbandoned}
                </Badge>
                <p className="text-sm text-fg-muted">{C.switchAbandonedBody(reasonText(result.reason) ?? result.reason)}</p>
              </>
            : <>
                <Badge tone="info" dot>
                  {C.switchRunning}
                </Badge>
                <p className="text-sm text-fg-muted">{C.switchRunningBody}</p>
              </>
            }
          </div>
        : <div className="space-y-4">
            {noRole ?
              <div className="rounded-control border border-warn-line bg-warn-soft p-3" role="alert" data-testid="mirror-switch-no-role">
                <p className="flex items-center gap-2 text-sm font-semibold text-warn">
                  <TriangleExclamationIcon className="size-4 shrink-0" aria-hidden />
                  {C.switchNoAccessTitle}
                </p>
                <p className="mt-1.5 text-sm text-fg-muted">{noRole}</p>
                <p className="mt-1 text-sm text-fg-muted">{cap(C.switchNoAccess(from, to))}</p>
                <label className="mt-3 flex items-start gap-2.5 text-sm text-fg">
                  <Checkbox className="mt-0.5" checked={acceptNoAccess} onCheckedChange={setAcceptNoAccess} data-testid="mirror-switch-accept-no-access" />
                  <span>{C.switchNoAccessAccept}</span>
                </label>
              </div>
            : null}
            {refusedNoRole ? null : <PeerError error={run.error} fallback={C.switchFailed} />}
          </div>
        }
      </DialogContent>
    </Dialog>
  )
}
