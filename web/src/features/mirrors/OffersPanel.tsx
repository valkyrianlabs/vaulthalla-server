'use client'

import React, { useState } from 'react'
import { useWsMutation } from '@/lib/query'
import { formatBytes, formatInt, formatRelative } from '@/lib/format'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { confirm } from '@/components/ui/Confirm'
import { Panel } from '@/components/ui/Panel'
import { notify } from '@/components/ui/Toast'
import type { LinkedPeer } from '@/features/peers/model'
import { PeerError } from '@/features/peers/parts'
import { MIRROR_COPY as C } from '@/features/mirrors/copy'
import { MIRROR_READS, type MirrorOffer } from '@/features/mirrors/model'

// Offers linked servers made this server (mirror.pending): what the vault is, who offers it, and Accept or Decline.
// Shown only while one waits.
export const OffersPanel = ({ offers, peers }: { offers: MirrorOffer[]; peers: Map<number, LinkedPeer> }) => {
  const [error, setError] = useState<{ error: unknown; fallback: string } | null>(null)
  const nameOf = (o: MirrorOffer) => peers.get(o.peer_id)?.name || C.unnamedServer

  const accept = useWsMutation('mirror.accept', {
    toPayload: (o: MirrorOffer) => ({ offer: o.id }),
    invalidates: [...MIRROR_READS],
    onSuccess: data => notify.success(C.accepted(data.offer.name), C.acceptedHint),
  })
  const decline = useWsMutation('mirror.decline', {
    toPayload: (o: MirrorOffer) => ({ offer: o.id }),
    invalidates: [...MIRROR_READS],
    onSuccess: data => notify.success(C.declined(data.offer.name)),
  })

  const askAccept = async (o: MirrorOffer) => {
    const ok = await confirm({ title: C.acceptTitle(o.name), description: C.acceptBody(o.name, nameOf(o)), confirmLabel: C.accept, tone: 'primary' })
    if (!ok) return
    setError(null)
    accept.mutate(o, { onError: e => setError({ error: e, fallback: C.acceptFailed }) })
  }
  const askDecline = async (o: MirrorOffer) => {
    const ok = await confirm({ title: C.declineTitle(o.name), description: C.declineBody(nameOf(o)), confirmLabel: C.decline, tone: 'danger' })
    if (!ok) return
    setError(null)
    decline.mutate(o, { onError: e => setError({ error: e, fallback: C.declineFailed }) })
  }

  if (!offers.length) return null
  const busy = (o: MirrorOffer) => (accept.isPending && accept.variables?.id === o.id) || (decline.isPending && decline.variables?.id === o.id)

  return (
    <Panel title={C.offersTitle} description={C.offersBody} className="mb-6" id="mirror-offers">
      <PeerError error={error?.error} fallback={error?.fallback ?? ''} className="mb-3" />
      <ul className="divide-y divide-line/60" data-testid="mirror-offers">
        {offers.map(o => (
          <li key={o.id} className="flex flex-wrap items-center justify-between gap-3 py-3 first:pt-0 last:pb-0" data-testid="mirror-offer">
            <div className="min-w-0">
              <p className="text-sm text-fg">
                <span className="font-medium" data-testid="mirror-offer-name">
                  {o.name}
                </span>{' '}
                <span className="text-fg-subtle">{C.offerFrom(nameOf(o))}</span>
              </p>
              <p className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-fg-subtle">
                <span className="tabular">{C.offerSize(formatBytes(o.size_bytes), formatInt(o.file_count))}</span>
                {o.owner?.name ? <span>{C.offerOwner(o.owner.name)}</span> : null}
                {o.role ? <span>{C.offerGrant(o.role.role_name)}</span> : null}
                {o.history ? <Badge className="h-5 px-2 text-[11px]">{C.offerHistory}</Badge> : null}
                {o.expires_at ? <span>{C.offerExpires(formatRelative(o.expires_at))}</span> : null}
              </p>
              {o.description ? <p className="mt-1 text-xs break-words text-fg-muted">{o.description}</p> : null}
            </div>
            <div className="flex items-center gap-2">
              <Button variant="ghost" size="sm" disabled={busy(o)} onClick={() => void askDecline(o)} data-testid={`mirror-offer-decline-${o.id}`}>
                {C.decline}
              </Button>
              <Button
                variant="primary"
                size="sm"
                disabled={busy(o)}
                loading={accept.isPending && accept.variables?.id === o.id}
                onClick={() => void askAccept(o)}
                data-testid={`mirror-offer-accept-${o.id}`}>
                {C.accept}
              </Button>
            </div>
          </li>
        ))}
      </ul>
    </Panel>
  )
}
