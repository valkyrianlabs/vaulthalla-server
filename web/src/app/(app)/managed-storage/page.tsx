import React, { Suspense } from 'react'
import type { Metadata } from 'next'
import { ManagedStoragePage } from '@/features/managedStorage/ManagedStoragePage'

export const metadata: Metadata = { title: 'Managed storage' }

export default function Page() {
  return (
    <Suspense>
      <ManagedStoragePage />
    </Suspense>
  )
}
