'use client'

// Whether this server offers linked servers, kept small: the shell's nav reads it on every route. Super admins only
// (nobody else may link servers, and nobody else is asked). peer.status is the one peer.* command that answers while
// peers.experimental is off, so no page load provokes a refusal; a server without it (unknown command) leaves the
// feature out too. Cached 10 minutes: the switch is config.yaml's, read at start.
import { useWs } from '@/lib/query'
import { useCan } from '@/lib/permissions'

export const usePeersAvailability = () => {
  const superAdmin = useCan({ superAdmin: true })
  const status = useWs('peer.status', null, { enabled: superAdmin, staleTime: 10 * 60_000, retry: false })
  return { superAdmin, pending: superAdmin && status.isPending, enabled: superAdmin && status.data?.enabled === true }
}

export const usePeersSignal = () => usePeersAvailability().enabled
