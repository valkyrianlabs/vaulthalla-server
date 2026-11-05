'use client'

import React, { useEffect } from 'react'
import { usePathname } from 'next/navigation'
import { api, endSession, refreshSession, useSession } from '@/lib/session'
import { createActivityReporter, trackActivity } from '@/lib/activity'
import { useConnectionStatus } from '@/components/shell/ConnectionIndicator'
import { Spinner } from '@/components/ui/Spinner'

// Re-establishes the session from the HttpOnly refresh cookie (the access token is never persisted), keeps it fresh,
// and sends the visitor to login only when the server actually refuses the session.
export const SessionGate = ({ children }: { children: React.ReactNode }) => {
  const status = useSession(state => state.status)
  const connection = useConnectionStatus()
  const pathname = usePathname()

  useEffect(() => {
    api.connect()
  }, [])

  // (Re)try whenever the socket is open and the session is still unknown — covers a daemon that was down at load.
  useEffect(() => {
    if (connection === 'open' && useSession.getState().status === 'unknown') void refreshSession()
  }, [connection])

  // The middleware only checks that a refresh cookie exists, so this is where a revoked or bogus one ends up.
  useEffect(() => {
    if (status === 'unauthenticated') endSession(`${window.location.pathname}${window.location.search}`)
  }, [status, pathname])

  // Idle sign-out (#319): report real input so the server's idle clock only counts a person using the console.
  useEffect(() => {
    if (status !== 'authenticated') return
    const reporter = createActivityReporter({ send: () => api.send('auth.activity', null) })
    return trackActivity(window, reporter)
  }, [status])

  // A socket the server closed (an idle sign-out among other reasons) gets its session re-checked as soon as it
  // reconnects, so an ended session reaches the sign-in page at once instead of on the next poll.
  useEffect(() => {
    if (connection === 'open' && useSession.getState().status === 'authenticated') void refreshSession()
  }, [connection])

  // Access tokens live ~60 minutes; refresh well before that, and right after the tab wakes up.
  useEffect(() => {
    if (status !== 'authenticated') return
    const interval = setInterval(() => void refreshSession(), 10 * 60_000)
    const onVisible = () => {
      if (document.visibilityState === 'visible') void refreshSession()
    }
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      clearInterval(interval)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [status])

  if (status !== 'authenticated') {
    const unreachable = connection === 'reconnecting' || connection === 'closed'
    return (
      <div className="grid min-h-dvh place-items-center px-6 text-center">
        <div className="flex flex-col items-center gap-3">
          <Spinner className="size-7" label={unreachable ? 'Reconnecting' : 'Signing in'} />
          {unreachable ? (
            <>
              <p className="text-sm font-medium text-fg">Can’t reach the Vaulthalla server</p>
              <p className="max-w-xs text-xs text-fg-subtle">It may be restarting. This page reconnects on its own.</p>
            </>
          ) : null}
        </div>
      </div>
    )
  }
  return <>{children}</>
}
