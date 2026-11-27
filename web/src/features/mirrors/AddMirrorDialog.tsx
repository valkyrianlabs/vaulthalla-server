'use client'

import React, { useId, useMemo, useState } from 'react'
import { useWsMutation } from '@/lib/query'
import { Button } from '@/components/ui/Button'
import { Dialog, DialogClose, DialogContent } from '@/components/ui/Dialog'
import { Field, Select } from '@/components/ui/Field'
import { Skeleton } from '@/components/ui/State'
import { notify } from '@/components/ui/Toast'
import { useVaultList } from '@/features/vaults/hooks'
import { peerLabel, type LinkedPeer } from '@/features/peers/model'
import { PeerError } from '@/features/peers/parts'
import { MIRROR_COPY as C } from '@/features/mirrors/copy'
import { MIRROR_READS, offerable, type MirroredVault } from '@/features/mirrors/model'

// Mirror a vault (mirror.add): one of this server's vaults to one linked server. The server checks every
// precondition and refuses with its own sentence; the vault keys step-up runs through the shell's dialog.
// Loaded with next/dynamic and mounted only while open.
export default function AddMirrorDialog({
  open,
  onOpenChange,
  mirrored,
  peers,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  mirrored: MirroredVault[]
  peers: LinkedPeer[]
}) {
  const ids = useId()
  const vaults = useVaultList()
  const choices = useMemo(() => offerable(vaults.data ?? [], mirrored), [vaults.data, mirrored])
  const [vaultId, setVaultId] = useState('')
  const [peerId, setPeerId] = useState(peers.length === 1 ? String(peers[0].id) : '')

  const add = useWsMutation<'mirror.add', void>('mirror.add', {
    toPayload: () => ({ vault_id: Number(vaultId), peer: peerId }),
    invalidates: [...MIRROR_READS],
    onSuccess: data => {
      const peer = peers.find(p => p.id === data.offer.peer_id)
      notify.success(C.offered(data.offer.name, peer ? peerLabel(peer) : C.unnamedServer), C.offeredHint)
      onOpenChange(false)
    },
  })
  const ready = Boolean(vaultId && peerId)

  return (
    <Dialog open={open} onOpenChange={next => (add.isPending ? undefined : onOpenChange(next))}>
      <DialogContent
        title={C.addTitle}
        description={C.addDescription}
        size="md"
        data-testid="mirror-add-dialog"
        footer={
          <>
            <DialogClose asChild>
              <Button variant="ghost">Cancel</Button>
            </DialogClose>
            <Button type="submit" form={`${ids}-form`} variant="primary" loading={add.isPending} disabled={!ready} data-testid="mirror-add-submit">
              {C.addSubmit}
            </Button>
          </>
        }>
        <form
          id={`${ids}-form`}
          noValidate
          className="space-y-4"
          onSubmit={event => {
            event.preventDefault()
            if (ready) add.mutate()
          }}>
          <Field label={C.addVault} htmlFor={`${ids}-vault`} hint={choices.length ? C.addVaultHint : undefined}>
            {vaults.isPending ?
              <Skeleton className="h-9" />
            : choices.length ?
              <Select id={`${ids}-vault`} value={vaultId} onChange={e => setVaultId(e.target.value)} autoFocus data-testid="mirror-add-vault">
                <option value="">{C.addChoose}</option>
                {choices.map(v => (
                  <option key={v.id} value={v.id}>
                    {v.name}
                  </option>
                ))}
              </Select>
            : <p className="text-sm text-fg-subtle">{C.addVaultNone}</p>}
          </Field>
          <Field label={C.addServer} htmlFor={`${ids}-peer`} hint={C.addServerHint}>
            <Select id={`${ids}-peer`} value={peerId} onChange={e => setPeerId(e.target.value)} data-testid="mirror-add-peer">
              <option value="">{C.addChoose}</option>
              {peers.map(p => (
                <option key={p.id} value={p.id}>
                  {peerLabel(p)}
                </option>
              ))}
            </Select>
          </Field>
          <ol className="list-decimal space-y-1.5 pl-5 text-sm text-fg-muted">
            {C.addSteps.map(step => (
              <li key={step}>{step}</li>
            ))}
          </ol>
          <PeerError error={add.error} fallback={C.addFailed} />
        </form>
      </DialogContent>
    </Dialog>
  )
}
