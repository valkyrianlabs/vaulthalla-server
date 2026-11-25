import type { Metadata } from 'next'
import { LinkedServersPage } from '@/features/peers/LinkedServersPage'

export const metadata: Metadata = { title: 'Linked servers' }

export default function Page() {
  return <LinkedServersPage />
}
