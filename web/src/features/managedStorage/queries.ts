'use client'

import { useHelloCapability } from '@/lib/hello'
import { queryClient, useWs } from '@/lib/query'
import { MANAGED_STORAGE_CAPABILITY } from '@/features/managedStorage/model'

export { useCloudView } from '@/features/managedStorage/signal'
export { useHelloCapability }

// Whether this server offers managed storage.
export const useManagedStorageCapability = (enabled = true) => useHelloCapability(MANAGED_STORAGE_CAPABILITY, enabled)

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
