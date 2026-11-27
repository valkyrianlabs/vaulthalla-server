'use client'

// The reads the Mirrored vaults pages share, one cached copy each. Super admins only (the pages sit behind PeersGate).
import { useMemo } from 'react'
import { useWs } from '@/lib/query'
import type { LinkedPeer } from '@/features/peers/model'
import { heldCounts } from '@/features/mirrors/model'

// A mirror's state moves on its own (the link, the first copy, the core): a light poll, paused in hidden tabs.
export const LIST_POLL_MS = 15_000
// A vault's own page polls faster while something is running (a first copy, a switch, a start).
export const DETAIL_POLL_MS = 5_000

export const useMirrorList = () => useWs('mirror.list', null, { refetchInterval: LIST_POLL_MS })

export const useOffers = () => useWs('mirror.pending', null, { refetchInterval: LIST_POLL_MS })

// The same read (and cache entry) as the Servers tab's table: names and link health by peer id.
export const usePeers = () => {
  const list = useWs('peer.list', { all: true }, { refetchInterval: LIST_POLL_MS })
  const maps = useMemo(() => {
    const byId = new Map<number, LinkedPeer>()
    for (const p of list.data?.peers ?? []) byId.set(p.id, p)
    const linked = (list.data?.peers ?? []).filter(p => !p.revoked)
    return { byId, linked }
  }, [list.data])
  return { ...maps, query: list }
}

// Whether the link to a vault's other server is up; null while unknown (never up by guess).
export const linkUpOf = (byId: Map<number, LinkedPeer>, peerId: number | null | undefined): boolean | null => {
  if (peerId === null || peerId === undefined) return null
  const p = byId.get(peerId)
  if (!p) return null
  if (p.revoked) return false
  return p.health.connected
}

export const useHeld = (vaultId?: number, all = false) =>
  useWs('mirror.held.list', vaultId ? { vault_id: vaultId, ...(all ? { all } : {}) } : all ? { all } : {}, {
    refetchInterval: LIST_POLL_MS,
  })

// Open held changes per vault (one read for the whole list).
export const useHeldCounts = () => {
  const held = useHeld()
  return useMemo(() => heldCounts(held.data?.held ?? []), [held.data])
}
