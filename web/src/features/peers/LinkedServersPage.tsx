'use client'

import React, { useState } from 'react'
import dynamic from 'next/dynamic'
import { useWs } from '@/lib/query'
import { WsError } from '@/lib/ws/errors'
import { PageHeader } from '@/components/ui/Panel'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'
import { EmptyState, ErrorState, QueryState } from '@/components/ui/State'
import { LinkIcon, PlusIcon, ServerIcon } from '@/components/ui/icons'
import { PEERS_COPY } from '@/features/peers/copy'
import { usePeersAvailability } from '@/features/peers/signal'
import { PeerTable } from '@/features/peers/PeerTable'

// The two pairing dialogs (Radix Dialog, their pollers, the number matching) load only when someone opens one.
const AcceptLinkDialog = dynamic(() => import('@/features/peers/AcceptLinkDialog'), { ssr: false })
const LinkServerDialog = dynamic(() => import('@/features/peers/LinkServerDialog'), { ssr: false })

// /linked-servers (design/peers/link.md, "Three ways to drive it": the web console). Super admins only, and only on a
// server with peers.experimental on (peer.status): anywhere else this URL shows a denial or one plain sentence, and the
// nav has no entry (features/peers/signal.ts). The same operations as `vh peer`; the daemon decides everything.
export const LinkedServersPage = () => {
  const { superAdmin, pending, enabled } = usePeersAvailability()
  if (!superAdmin) return <ErrorState error={new WsError('denied', PEERS_COPY.denied)} />
  if (pending)
    return (
      <div className="flex justify-center py-14">
        <Spinner className="size-6" label="Loading" />
      </div>
    )
  if (!enabled)
    return (
      <div data-testid="peers-unavailable">
        <EmptyState icon={ServerIcon} title={PEERS_COPY.unavailableTitle} description={PEERS_COPY.unavailableBody} />
      </div>
    )
  return <LinkedServers />
}

type Open = 'accept' | 'link' | null

const LinkedServers = () => {
  const [open, setOpen] = useState<Open>(null)
  // Health moves on its own (connections come and go): a light poll, paused in hidden tabs.
  const list = useWs('peer.list', { all: true }, { refetchInterval: 15_000 })
  const onOpenChange = (next: boolean) => !next && setOpen(null)
  return (
    <div className="w-full">
      <PageHeader
        title={
          <span className="inline-flex items-center gap-2.5">
            {PEERS_COPY.title}
            <Badge tone="warn" className="align-middle" title="This feature is still being built and may change.">
              <span data-testid="peers-experimental">{PEERS_COPY.experimental}</span>
            </Badge>
          </span>
        }
        description={
          <>
            {PEERS_COPY.description}{' '}
            <span data-testid="peers-purpose">{PEERS_COPY.purpose}</span>
          </>
        }
        actions={
          <>
            <Button variant="secondary" onClick={() => setOpen('accept')} data-testid="peers-accept-open">
              <PlusIcon aria-hidden />
              {PEERS_COPY.acceptAction}
            </Button>
            <Button variant="primary" onClick={() => setOpen('link')} data-testid="peers-link-open">
              <LinkIcon aria-hidden />
              {PEERS_COPY.linkAction}
            </Button>
          </>
        }
      />
      <QueryState query={list}>
        {data => (
          <PeerTable
            peers={data.peers}
            empty={<EmptyState icon={ServerIcon} title={PEERS_COPY.emptyTitle} description={PEERS_COPY.emptyBody} />}
          />
        )}
      </QueryState>
      {open === 'accept' ? <AcceptLinkDialog open onOpenChange={onOpenChange} /> : null}
      {open === 'link' ? <LinkServerDialog open onOpenChange={onOpenChange} /> : null}
    </div>
  )
}
