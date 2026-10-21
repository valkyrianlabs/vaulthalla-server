import type { Metadata } from 'next'
import { AllDevicesPage } from '@/features/devices/AllDevicesPage'

export const metadata: Metadata = { title: 'All devices' }

export default function Page() {
  return <AllDevicesPage />
}
