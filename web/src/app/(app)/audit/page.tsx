import type { Metadata } from 'next'
import { AuditPage } from '@/features/audit/AuditPage'

export const metadata: Metadata = { title: 'Audit trail' }

export default function Page() {
  return <AuditPage />
}
