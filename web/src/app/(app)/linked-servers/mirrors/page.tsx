import type { Metadata } from 'next'
import { MirroredVaultsPage } from '@/features/mirrors/MirroredVaultsPage'

export const metadata: Metadata = { title: 'Mirrored vaults' }

export default function Page() {
  return <MirroredVaultsPage />
}
