'use client'

import { create } from 'zustand'
import { WsClient, type Command } from '@/lib/ws/client'
import { WsError, isWsError } from '@/lib/ws/errors'
import { checkServerContract } from '@/lib/ws/contract'
import type { IUser } from '@/models/user'

export type SessionStatus = 'unknown' | 'authenticated' | 'unauthenticated'

interface SessionState {
  status: SessionStatus
  user: IUser | null
  // Access token. Memory only: the HttpOnly refresh cookie re-issues it on every page load (auth.refresh).
  token: string | null
}

export const useSession = create<SessionState>(() => ({ status: 'unknown', user: null, token: null }))

// Session-lifecycle commands work without (or with an expired) access token. Mirrors core's
// isSessionLifecycleCommand (protocols/ws/Router.cpp).
const LIFECYCLE: ReadonlySet<Command> = new Set<Command>([
  'auth.login',
  'auth.logout',
  'auth.refresh',
  'auth.isAuthenticated',
  'meta.contract.get',
])

let refreshing: Promise<boolean> | null = null

export const api = new WsClient({
  path: '/ws',
  lifecycle: LIFECYCLE,
  token: () => useSession.getState().token ?? '',
  onToken: token => useSession.setState({ token }),
  onUnauthorized: () => refreshSession(),
  onOpen: () => void checkServerContract(api),
})

// Single-flight refresh. Resolves false (and marks the session unauthenticated) when the server definitively refuses.
export const refreshSession = (): Promise<boolean> => {
  if (refreshing) return refreshing
  refreshing = (async () => {
    try {
      const { user } = await api.send('auth.refresh', null)
      useSession.setState({ status: 'authenticated', user: (user as unknown as IUser) ?? useSession.getState().user })
      return true
    } catch (error) {
      // A dropped connection or timeout says nothing about the session; only a refusal ends it.
      if (isWsError(error, 'disconnected', 'timeout', 'aborted')) return useSession.getState().status === 'authenticated'
      useSession.setState({ status: 'unauthenticated', user: null, token: null })
      return false
    } finally {
      refreshing = null
    }
  })()
  return refreshing
}

export const login = async (name: string, password: string) => {
  const { user } = await api.send('auth.login', { name, password })
  if (!useSession.getState().token) throw new WsError('error', 'The server did not issue a session token')
  useSession.setState({ status: 'authenticated', user: user as unknown as IUser })
}

const resetHandlers = new Set<() => void>()

// Feature stores register here so a logout or a lost session never leaks the previous user's state.
export const onSessionReset = (handler: () => void) => {
  resetHandlers.add(handler)
  return () => {
    resetHandlers.delete(handler)
  }
}

const resetEverything = () => {
  for (const handler of resetHandlers) handler()
  useSession.setState({ status: 'unauthenticated', user: null, token: null })
  try {
    // Legacy persisted stores from earlier releases; nothing in this client persists server data.
    for (const key of Object.keys(localStorage)) if (key.startsWith('vaulthalla-') && key !== 'vaulthalla-ui') localStorage.removeItem(key)
  } catch {
    // Storage can be unavailable (private mode); there is nothing to clear then.
  }
}

export const logout = async () => {
  try {
    await api.send('auth.logout', null, { timeoutMs: 4000 })
  } catch {
    // The hard navigation below drops the socket either way; the server expires the session on close.
  }
  resetEverything()
  api.close()
  // A full navigation guarantees no in-memory state, pollers or sockets survive into the next session.
  window.location.assign('/login')
}

export const endSession = (next?: string) => {
  resetEverything()
  const target = next ? `/login?next=${encodeURIComponent(next)}` : '/login'
  window.location.assign(target)
}
