'use client'

import React, { useState } from 'react'
import { useWsMutation } from '@/lib/query'
import { Button } from '@/components/ui/Button'
import { Dialog, DialogClose, DialogContent } from '@/components/ui/Dialog'
import { Field, Input } from '@/components/ui/Field'
import { notify } from '@/components/ui/Toast'
import { PEERS_COPY } from '@/features/peers/copy'
import { PEER_READS, peerLabel, type LinkedPeer } from '@/features/peers/model'
import { PeerError } from '@/features/peers/parts'

// core device::normalizeDeviceName (peer names use it too): 1-64 characters, no control characters.
const MAX_NAME = 64

// Loaded with next/dynamic and mounted only while open.
export default function RenamePeerDialog({
  peer,
  open,
  onOpenChange,
}: {
  peer: LinkedPeer
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const [name, setName] = useState(peer.name)
  const trimmed = name.trim()
  const rename = useWsMutation('peer.rename', {
    toPayload: (next: string) => ({ peer: String(peer.id), name: next }),
    invalidates: [...PEER_READS],
    onSuccess: data => {
      notify.success(PEERS_COPY.renamed(peerLabel(data.peer)))
      onOpenChange(false)
    },
  })
  const tooLong = [...trimmed].length > MAX_NAME
  const unchanged = trimmed === peer.name

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        size="sm"
        title={PEERS_COPY.renameTitle(peerLabel(peer))}
        description={PEERS_COPY.renameBody}
        data-testid="peer-rename-dialog"
        footer={
          <>
            <DialogClose asChild>
              <Button variant="ghost">Cancel</Button>
            </DialogClose>
            <Button type="submit" form="peer-rename-form" variant="primary" loading={rename.isPending} disabled={!trimmed || tooLong || unchanged}>
              Rename
            </Button>
          </>
        }>
        <form
          id="peer-rename-form"
          noValidate
          onSubmit={event => {
            event.preventDefault()
            if (trimmed && !tooLong && !unchanged) rename.mutate(trimmed)
          }}
          className="space-y-3">
          <Field label="Name" htmlFor="peer-rename-name" error={tooLong ? `At most ${MAX_NAME} characters` : undefined}>
            <Input
              id="peer-rename-name"
              value={name}
              autoFocus
              maxLength={MAX_NAME * 2}
              onChange={event => setName(event.target.value)}
              aria-invalid={tooLong || undefined}
            />
          </Field>
          <PeerError error={rename.error} fallback={PEERS_COPY.renameFailed} />
        </form>
      </DialogContent>
    </Dialog>
  )
}
