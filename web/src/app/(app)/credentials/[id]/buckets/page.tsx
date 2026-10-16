import type { Metadata } from 'next'
import { notFound } from 'next/navigation'
import { BucketsPage } from '@/features/credentials/upstream/BucketsPage'

export const metadata: Metadata = { title: 'Upstream buckets' }

export default async function Page({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  const numeric = Number(id)
  if (!Number.isInteger(numeric) || numeric <= 0) notFound()
  return <BucketsPage apiKeyId={numeric} />
}
