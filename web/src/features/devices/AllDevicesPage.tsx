'use client'

import React from 'react'
import { useWs } from '@/lib/query'
import { useCan } from '@/lib/permissions'
import { WsError } from '@/lib/ws/errors'
import { ErrorState, QueryState } from '@/components/ui/State'
import { DeviceTable } from '@/features/devices/DeviceTable'
import { RemoteConnectionsCard } from '@/features/devices/RemoteConnectionsCard'

// Super admins: every user's devices (device.list {all}) and the listener's remote-connections switch. The UI gate
// mirrors core (ops::devices requireSuperAdmin); the daemon refuses anyone else anyway.
export const AllDevicesPage = () => {
  const superAdmin = useCan({ superAdmin: true })
  if (!superAdmin) return <ErrorState error={new WsError('denied', 'Only super admins can see every device.')} />
  return (
    <div className="space-y-5">
      <RemoteConnectionsCard />
      <section aria-labelledby="all-devices-title" className="space-y-3">
        <h2 id="all-devices-title" className="text-[15px] font-semibold text-fg">
          Every user’s devices
        </h2>
        <AllDevices />
      </section>
    </div>
  )
}

const AllDevices = () => {
  const list = useWs('device.list', { all: true })
  return (
    <QueryState query={list}>
      {data => <DeviceTable devices={data.devices} showOwner empty="No device is paired with this server." />}
    </QueryState>
  )
}
