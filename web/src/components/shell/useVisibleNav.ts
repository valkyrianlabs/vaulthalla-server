'use client'

import { NAV, type NavSection, type NavSignal } from '@/components/shell/nav'
import { useSession } from '@/lib/session'
import { meets } from '@/lib/permissions'
import { useSyncConflictCount } from '@/features/syncConflicts/summary'
import { useManagedStorageSignal } from '@/features/managedStorage/signal'

export const useVisibleNav = (): NavSection[] => {
  const user = useSession(state => state.user)
  // "Sync Conflicts" only appears while there are open conflicts this account can resolve (core filters the count).
  const conflicts = useSyncConflictCount()
  const cloudStorage = useManagedStorageSignal()
  const signals: Record<NavSignal, boolean> = { syncConflicts: conflicts > 0, cloudStorage }
  return NAV.map(section => ({
    ...section,
    items: section.items.filter(item => meets(user, item.requires) && (!item.shownWhen || signals[item.shownWhen])),
  })).filter(section => section.items.length > 0)
}
