'use client'

// The shell's nav signal for managed storage, kept small: it is in every route's first load. A server without the
// capability has no cloud.storage.status command, so its error leaves the item hidden; the page and the new-vault
// switch also check the meta.hello capability (queries.ts).
import { useSession } from '@/lib/session'
import { useWs } from '@/lib/query'
import { meets } from '@/lib/permissions'

export const useCloudView = () => {
  const user = useSession(state => state.user)
  return meets(user, { superAdmin: true }) || meets(user, { permission: 'admin.cloud.view' })
}

// Shown once managed storage is available, or once the server is linked at all: the page also holds the cloud relay's
// switch, which needs a link but no storage plan.
export const useManagedStorageSignal = () => {
  const canView = useCloudView()
  const data = useWs('cloud.storage.status', null, { enabled: canView, staleTime: 60_000, retry: false }).data
  return canView && !!(data?.available || data?.linked)
}
