'use client'

import React from 'react'
import { useWs } from '@/lib/query'
import { Button } from '@/components/ui/Button'
import { EmptyState, QueryState } from '@/components/ui/State'
import { LinkIcon, PlusIcon } from '@/components/ui/icons'
import { DeviceTable } from '@/features/devices/DeviceTable'
import { useOpenPairing } from '@/features/devices/DevicesShell'

// The signed-in user's own devices, revoked ones included (behind "Show revoked").
export const MyDevicesPage = () => {
  const list = useWs('device.list', {})
  const openPairing = useOpenPairing()
  return (
    <QueryState query={list}>
      {data =>
        data.devices.length ? (
          <DeviceTable devices={data.devices} empty="All your devices were revoked. Pair a device to use Desktop again." />
        ) : (
          <div className="panel" data-testid="devices-empty">
            <EmptyState
              icon={LinkIcon}
              title="No paired devices yet"
              description={
                <>
                  Pair Vaulthalla Desktop with your account: click Pair a device, add this server in Desktop and choose Pair,
                  then click the code your Mac shows. No passwords, API keys or certificates.
                </>
              }
              action={
                <Button variant="primary" onClick={openPairing}>
                  <PlusIcon aria-hidden />
                  Pair a device
                </Button>
              }
            />
          </div>
        )
      }
    </QueryState>
  )
}
