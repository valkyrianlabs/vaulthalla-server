'use client'

import React, { useState } from 'react'
import dynamic from 'next/dynamic'
import { useWsMutation } from '@/lib/query'
import { Button } from '@/components/ui/Button'
import { confirm } from '@/components/ui/Confirm'
import { PageHeader, Panel } from '@/components/ui/Panel'
import { EmptyState, QueryState } from '@/components/ui/State'
import { notify } from '@/components/ui/Toast'
import { GearIcon, PlusIcon, VaultIcon } from '@/components/ui/icons'
import { PEERS_COPY } from '@/features/peers/copy'
import { PeersGate, PeersTabs } from '@/features/peers/Gate'
import { healthText, peerLabel, type LinkedPeer } from '@/features/peers/model'
import { PeerError } from '@/features/peers/parts'
import { formatRelative } from '@/lib/format'
import { MIRROR_COPY as C } from '@/features/mirrors/copy'
import { MIRROR_READS, cancelTarget, peerName, type MirroredVault } from '@/features/mirrors/model'
import { MirrorTable } from '@/features/mirrors/MirrorTable'
import { OffersPanel } from '@/features/mirrors/OffersPanel'
import { useHeldCounts, useMirrorList, useOffers, usePeers } from '@/features/mirrors/queries'

// Dialogs load only when someone opens one.
const AddMirrorDialog = dynamic(() => import('@/features/mirrors/AddMirrorDialog'), { ssr: false })
const LinkSettingsDialog = dynamic(() => import('@/features/mirrors/LinkSettingsDialog'), { ssr: false })

// /linked-servers/mirrors (design/peers/mirror.md): every vault mirrored with a linked server, the offers waiting
// here, starting a mirror and each link's settings. Super admins (PeersGate); the same operations as `vh mirror`, and the daemon decides everything.
export const MirroredVaultsPage = () => (
  <PeersGate denied={C.denied}>
    <MirroredVaults />
  </PeersGate>
)

export const MirrorHeader = ({ actions }: { actions?: React.ReactNode }) => (
  <>
    <PageHeader
      title={PEERS_COPY.title}
      description={C.description}
      actions={actions}
      className="mb-4"
    />
    <PeersTabs />
  </>
)

const MirroredVaults = () => {
  const list = useMirrorList()
  const offers = useOffers()
  const { byId, linked } = usePeers()
  const held = useHeldCounts()
  const [adding, setAdding] = useState(false)
  const [settingsFor, setSettingsFor] = useState<LinkedPeer | null>(null)
  const [error, setError] = useState<unknown>(null)

  const cancelStart = useWsMutation('mirror.cancel', {
    toPayload: (row: MirroredVault) => cancelTarget(row),
    invalidates: [...MIRROR_READS],
    onSuccess: () => notify.success(C.startCancelled),
  })
  const askCancelStart = async (row: MirroredVault) => {
    const name = row.start?.name ?? row.vault_name
    const ok = await confirm({
      title: C.cancelStartTitle(name),
      description: C.cancelStartBody(peerName(row)),
      confirmLabel: C.cancelStartConfirm,
      cancelLabel: C.keepGoing,
      tone: 'danger',
    })
    if (!ok) return
    setError(null)
    cancelStart.mutate(row, { onError: setError })
  }

  return (
    <div className="w-full">
      <MirrorHeader
        actions={
          <Button variant="primary" onClick={() => setAdding(true)} disabled={!linked.length} data-testid="mirror-add-open">
            <PlusIcon aria-hidden />
            {C.addAction}
          </Button>
        }
      />
      <OffersPanel offers={offers.data?.offers ?? []} peers={byId} />
      <PeerError error={error} fallback={C.cancelFailed} className="mb-3" />
      <QueryState query={list}>
        {data => (
          <MirrorTable
            rows={data.vaults}
            peers={byId}
            held={held}
            onCancelStart={row => void askCancelStart(row)}
            empty={
              linked.length ?
                <EmptyState icon={VaultIcon} title={C.emptyTitle} description={C.emptyBody} />
              : <EmptyState icon={VaultIcon} title={C.noLinksTitle} description={C.noLinksBody} />
            }
          />
        )}
      </QueryState>
      {linked.length ?
        <Panel title={C.settingsTitle} description={C.settingsBody} className="mt-6" id="mirror-link-settings">
          <ul className="divide-y divide-line/60" data-testid="mirror-link-settings">
            {linked.map(p => {
              const h = healthText(p, unix => formatRelative(unix))
              return (
                <li key={p.id} className="flex flex-wrap items-center justify-between gap-3 py-2.5 first:pt-0 last:pb-0">
                  <span className="min-w-0">
                    <span className="block truncate text-sm font-medium text-fg">{peerLabel(p)}</span>
                    <span className="block text-xs text-fg-subtle">{h.label}</span>
                  </span>
                  <Button variant="secondary" size="sm" onClick={() => setSettingsFor(p)} data-testid={`mirror-settings-open-${p.id}`}>
                    <GearIcon aria-hidden />
                    {C.settingsOpen}
                  </Button>
                </li>
              )
            })}
          </ul>
        </Panel>
      : null}
      {adding ?
        <AddMirrorDialog open onOpenChange={next => !next && setAdding(false)} mirrored={list.data?.vaults ?? []} peers={linked} />
      : null}
      {settingsFor ? <LinkSettingsDialog peer={settingsFor} open onOpenChange={next => !next && setSettingsFor(null)} /> : null}
    </div>
  )
}
