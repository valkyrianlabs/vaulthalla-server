'use client'

import React from 'react'
import { WsError } from '@/lib/ws/errors'
import { useCan } from '@/lib/permissions'
import { ErrorState } from '@/components/ui/State'
import { LinkTabs, type LinkTab } from '@/components/ui/Tabs'
import { ServerIcon, VaultIcon } from '@/components/ui/icons'
import { PEERS_COPY } from '@/features/peers/copy'
import { MIRROR_COPY } from '@/features/mirrors/copy'

// What every page under /linked-servers shows before its own content: the typed denial for anyone but a super admin.
// Only then does the page mount and send anything.
export const PeersGate = ({ denied = PEERS_COPY.denied, children }: { denied?: string; children: React.ReactNode }) => {
  const superAdmin = useCan({ superAdmin: true })
  if (!superAdmin) return <ErrorState error={new WsError('denied', denied)} />
  return <>{children}</>
}

const TABS: LinkTab[] = [
  { href: '/linked-servers', label: MIRROR_COPY.tabServers, icon: ServerIcon, exact: true },
  { href: '/linked-servers/mirrors', label: MIRROR_COPY.tabMirrors, icon: VaultIcon },
]

export const PeersTabs = ({ className }: { className?: string }) => <LinkTabs tabs={TABS} className={className ?? 'mb-6'} />
