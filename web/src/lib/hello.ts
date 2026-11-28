'use client'

import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/session'
import { wsKey } from '@/lib/query'

const HELLO = { client: { name: 'Vaulthalla Web' } } as const

// Whether this server announces a meta.hello capability, cached 10 min like the upload probe (one request per page:
// every caller shares the query). Unknown (no answer yet, or a refusal) reads as absent.
export const useHelloCapability = (capability: string, enabled = true) =>
  !!useQuery({
    queryKey: wsKey('meta.hello', HELLO),
    queryFn: ({ signal }) => api.send('meta.hello', HELLO, { signal }),
    staleTime: 10 * 60_000,
    enabled,
    retry: false,
  }).data?.capabilities.includes(capability)
