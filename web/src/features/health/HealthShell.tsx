'use client'

import React from 'react'
import { PageHeader } from '@/components/ui/Panel'
import { LinkTabs, type LinkTab } from '@/components/ui/Tabs'
import { ErrorState } from '@/components/ui/State'
import { ChartLineIcon, FolderTreeIcon, GaugeHighIcon, HardDriveIcon, MicrochipIcon } from '@/components/ui/icons'
import { STATS_VIEW, useCan } from '@/lib/permissions'
import { WsError } from '@/lib/ws/errors'
import { useHealthPush } from '@/features/health/findings/push'

const TABS: LinkTab[] = [
  { href: '/health', label: 'Overview', icon: GaugeHighIcon, exact: true },
  { href: '/health/runtime', label: 'Runtime', icon: MicrochipIcon },
  { href: '/health/filesystem', label: 'Filesystem', icon: FolderTreeIcon },
  { href: '/health/storage', label: 'Storage', icon: HardDriveIcon },
  { href: '/health/activity', label: 'Activity', icon: ChartLineIcon },
]

// Every health command needs admin.stats.view on the server; without it the page shows the denied state instead of a
// page of refusals. Every health view follows health.changed while mounted (findings/push.ts).
export const HealthShell = ({ children }: { children: React.ReactNode }) => {
  const canView = useCan(STATS_VIEW)
  useHealthPush(canView)
  if (!canView) return <ErrorState error={new WsError('denied', 'Health needs the "view stats" admin permission.')} />
  return (
    <div className="w-full">
      <PageHeader
        title="Health"
        description="Live runtime, filesystem, storage and activity telemetry. Severity comes from the daemon."
        className="mb-4"
      />
      <LinkTabs tabs={TABS} className="mb-6" />
      {children}
    </div>
  )
}
