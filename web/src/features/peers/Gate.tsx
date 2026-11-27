'use client'

import React from 'react'
import { WsError } from '@/lib/ws/errors'
import { Spinner } from '@/components/ui/Spinner'
import { EmptyState, ErrorState } from '@/components/ui/State'
import { LinkTabs, type LinkTab } from '@/components/ui/Tabs'
import { ServerIcon, VaultIcon } from '@/components/ui/icons'
import { PEERS_COPY } from '@/features/peers/copy'
import { usePeersAvailability } from '@/features/peers/signal'
import { MIRROR_COPY } from '@/features/mirrors/copy'

// What every page under /linked-servers shows before its own content: the typed denial for anyone but a super admin,
// a spinner while peer.status answers, and one plain sentence while linked servers are off (nothing about turning
// them on). Only then does the page mount and send anything else.
export const PeersGate = ({ denied = PEERS_COPY.denied, children }: { denied?: string; children: React.ReactNode }) => {
  const { superAdmin, pending, enabled } = usePeersAvailability()
  if (!superAdmin) return <ErrorState error={new WsError('denied', denied)} />
  if (pending)
    return (
      <div className="flex justify-center py-14">
        <Spinner className="size-6" label="Loading" />
      </div>
    )
  if (!enabled) return <PeersUnavailable />
  return <>{children}</>
}

// The switched-off state, also shown when a command answers that linked servers are off (peers_experimental).
export const PeersUnavailable = () => (
  <div data-testid="peers-unavailable">
    <EmptyState icon={ServerIcon} title={PEERS_COPY.unavailableTitle} description={PEERS_COPY.unavailableBody} />
  </div>
)

const TABS: LinkTab[] = [
  { href: '/linked-servers', label: MIRROR_COPY.tabServers, icon: ServerIcon, exact: true },
  { href: '/linked-servers/mirrors', label: MIRROR_COPY.tabMirrors, icon: VaultIcon },
]

export const PeersTabs = ({ className }: { className?: string }) => <LinkTabs tabs={TABS} className={className ?? 'mb-6'} />
