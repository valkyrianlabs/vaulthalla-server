'use client'

import React, { createContext, useContext, useState } from 'react'
import dynamic from 'next/dynamic'
import { useCan } from '@/lib/permissions'
import { PageHeader } from '@/components/ui/Panel'
import { Button } from '@/components/ui/Button'
import { LinkTabs, type LinkTab } from '@/components/ui/Tabs'
import { PlusIcon, UserIcon, UsersIcon } from '@/components/ui/icons'

// Pairing (Radix Dialog, the poller and the number-matching UI) loads only when someone opens it.
const PairDeviceDialog = dynamic(() => import('@/features/devices/PairDeviceDialog'), { ssr: false })

const TABS: LinkTab[] = [
  { href: '/devices', label: 'Your devices', icon: UserIcon, exact: true },
  { href: '/devices/all', label: 'All devices', icon: UsersIcon },
]

const PairContext = createContext<() => void>(() => undefined)

// Opens the "Pair a device" dialog from anywhere under /devices (header button, empty state).
export const useOpenPairing = () => useContext(PairContext)

// /devices: any signed-in user's own devices; super admins also get /devices/all (every user's devices and the
// remote-connections switch). The daemon enforces both (D3: no device-specific permission bits).
export const DevicesShell = ({ children }: { children: React.ReactNode }) => {
  const superAdmin = useCan({ superAdmin: true })
  const [pairing, setPairing] = useState(false)
  return (
    <PairContext.Provider value={() => setPairing(true)}>
      <div className="w-full">
        <PageHeader
          title="Devices"
          description="Vaulthalla Desktop on your Macs. A paired device acts as the account that paired it, with that account’s permissions."
          className={superAdmin ? 'mb-4' : undefined}
          actions={
            <Button variant="primary" onClick={() => setPairing(true)} data-testid="pair-open">
              <PlusIcon aria-hidden />
              Pair a device
            </Button>
          }
        />
        {superAdmin ? <LinkTabs tabs={TABS} className="mb-6" /> : null}
        {children}
      </div>
      {pairing ? <PairDeviceDialog open onOpenChange={setPairing} /> : null}
    </PairContext.Provider>
  )
}
