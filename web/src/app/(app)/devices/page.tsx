import type { Metadata } from 'next'
import { MyDevicesPage } from '@/features/devices/MyDevicesPage'

export const metadata: Metadata = { title: 'Devices' }

export default function Page() {
  return <MyDevicesPage />
}
