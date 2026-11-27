'use client'

import React, { useId, useState } from 'react'
import { useWsMutation } from '@/lib/query'
import { Button } from '@/components/ui/Button'
import { Dialog, DialogClose, DialogContent } from '@/components/ui/Dialog'
import { notify } from '@/components/ui/Toast'
import { PeerError } from '@/features/peers/parts'
import { MIRROR_COPY as C } from '@/features/mirrors/copy'
import { MIRROR_READS, peerName, type MirroredVault } from '@/features/mirrors/model'
import { ChoiceCards } from '@/features/mirrors/parts'

// End a mirror on its core (mirror.cancel {vault_id, remove_copy}): what happens to the other server's copy is chosen
// here (kept, orphaned, by default, as `vh mirror cancel` does). The data.destroy step-up runs through the shell's
// dialog. Loaded with next/dynamic and mounted only while open.
export default function EndMirrorDialog({
  row,
  open,
  onOpenChange,
}: {
  row: MirroredVault
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const name = useId()
  const peer = peerName(row)
  const [copy, setCopy] = useState<'leave' | 'remove'>('leave')
  const end = useWsMutation('mirror.cancel', {
    toPayload: (removeCopy: boolean) => ({ vault_id: row.vault_id, remove_copy: removeCopy }),
    invalidates: [...MIRROR_READS],
    onSuccess: data => {
      notify.success(C.ended(row.vault_name), C.endedHint(data.remove_copy))
      onOpenChange(false)
    },
  })
  return (
    <Dialog open={open} onOpenChange={next => (end.isPending ? undefined : onOpenChange(next))}>
      <DialogContent
        title={C.endTitle(row.vault_name)}
        description={C.endBody(peer)}
        size="md"
        data-testid="mirror-end-dialog"
        footer={
          <>
            <DialogClose asChild>
              <Button variant="ghost">{C.keepGoing}</Button>
            </DialogClose>
            <Button variant="danger-solid" loading={end.isPending} onClick={() => end.mutate(copy === 'remove')} data-testid="mirror-end-confirm">
              {C.endConfirm}
            </Button>
          </>
        }>
        <ChoiceCards
          name={name}
          legend={C.endLegend(peer)}
          value={copy}
          onChange={setCopy}
          testId="mirror-end-copy"
          options={[
            { value: 'leave', title: C.endLeave, hint: C.endLeaveHint(peer) },
            { value: 'remove', title: C.endRemove, hint: C.endRemoveHint(peer) },
          ]}
        />
        <PeerError error={end.error} fallback={C.cancelFailed} className="mt-4" />
      </DialogContent>
    </Dialog>
  )
}
