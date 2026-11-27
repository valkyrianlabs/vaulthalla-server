import type { Metadata } from 'next'
import { MirrorDetailPage } from '@/features/mirrors/MirrorDetailPage'

export const metadata: Metadata = { title: 'Mirrored vault' }

export default function Page() {
  return <MirrorDetailPage />
}
