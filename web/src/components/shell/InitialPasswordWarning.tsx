'use client'

import { useState } from 'react'
import Link from 'next/link'
import { useWs } from '@/lib/query'
import { TriangleExclamationIcon, XmarkIcon } from '@/components/ui/icons'

// Shown while the generated initial super-admin password is still stored in plain text on the server
// (auth.security.status). Advice only: it never blocks navigation, and either remedy clears it.
export const InitialPasswordWarning = () => {
  const status = useWs('auth.security.status', null, { staleTime: Infinity, retry: false })
  const [hidden, setHidden] = useState(false)
  const file = status.data?.initial_password_file
  if (!file || hidden) return null
  return (
    <div role="status" data-testid="initial-password-warning" className="mb-5 flex items-start gap-3 rounded-card border border-warn-line bg-warn-soft px-4 py-3 text-sm">
      <TriangleExclamationIcon className="mt-0.5 size-4 shrink-0 text-warn" aria-hidden />
      <div className="min-w-0 flex-1 text-fg-muted">
        <p className="font-medium text-fg">The initial super-admin password is still stored in plain text on the server.</p>
        <p className="mt-1">
          It’s in <code className="rounded bg-black/30 px-1 font-mono text-xs break-all text-fg">{file}</code>. Either{' '}
          <Link href="/account" className="text-accent-text underline-offset-2 hover:underline">
            change your password
          </Link>{' '}
          (or run <code className="rounded bg-black/30 px-1 font-mono text-xs text-fg">vh setup set-super-admin-password</code>), or keep it and delete that
          file.
        </p>
      </div>
      <button type="button" onClick={() => setHidden(true)} aria-label="Hide this warning until the next page load" className="rounded p-1 text-fg-subtle hover:bg-surface-3 hover:text-fg">
        <XmarkIcon className="size-3.5" aria-hidden />
      </button>
    </div>
  )
}
