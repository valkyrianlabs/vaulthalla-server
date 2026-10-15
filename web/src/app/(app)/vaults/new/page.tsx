import { Suspense } from 'react'
import type { Metadata } from 'next'
import { NewVaultPage } from '@/features/vaults/NewVaultPage'

export const metadata: Metadata = { title: 'New vault' }

export default function Page() {
  // The form reads deep-link parameters (bucket adoption from the credential's bucket inventory).
  return (
    <Suspense>
      <NewVaultPage />
    </Suspense>
  )
}
