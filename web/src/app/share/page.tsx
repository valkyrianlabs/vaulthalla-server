import type { Metadata } from 'next'
import { SharePage } from '@/features/share/SharePage'

export const metadata: Metadata = { title: 'Shared files', robots: { index: false, follow: false } }

// The token and folder live in the URL fragment (`/share#<token>/<path>`, #327): SharePage reads them in the browser.
export default function Page() {
  return <SharePage />
}
