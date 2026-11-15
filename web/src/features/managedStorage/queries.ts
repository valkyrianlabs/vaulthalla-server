'use client'

import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/session'
import { queryClient, useWs, wsKey } from '@/lib/query'
import { MANAGED_STORAGE_CAPABILITY } from '@/features/managedStorage/model'

export { useCloudView } from '@/features/managedStorage/signal'

const HELLO = { client: { name: 'Vaulthalla Web' } } as const

// Whether this server offers managed storage (meta.hello capability), cached 10 min like the upload probe.
export const useManagedStorageCapability = (enabled = true) =>
  !!useQuery({
    queryKey: wsKey('meta.hello', HELLO),
    queryFn: ({ signal }) => api.send('meta.hello', HELLO, { signal }),
    staleTime: 10 * 60_000,
    enabled,
    retry: false,
  }).data?.capabilities.includes(MANAGED_STORAGE_CAPABILITY)

// cloud.storage.status, polled every 30 s (every 3 s while something uploads or becomes local).
export const useManagedStorageStatus = (enabled: boolean) =>
  useWs('cloud.storage.status', null, {
    enabled,
    refetchInterval: query => {
      const vaults = query.state.data?.vaults ?? []
      return vaults.some(v => v.state === 'attaching' || v.state === 'detaching') ? 3_000 : 30_000
    },
  })

export const refreshManagedStorage = () => queryClient.invalidateQueries({ queryKey: ['cloud.storage.status'] })
