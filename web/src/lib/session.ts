'use client'

import { create } from 'zustand'
import { WsClient, type Command } from '@/lib/ws/client'
import { WsError, isWsError } from '@/lib/ws/errors'
import { checkServerContract } from '@/lib/ws/contract'
import type { IUser } from '@/models/user'
import { readPending, type MfaPending, type MfaPendingCode } from '@/models/mfa'

export type SessionStatus = 'unknown' | 'authenticated' | 'unauthenticated'

interface SessionState {
  status: SessionStatus
  user: IUser | null
  // Access token. Memory only: the HttpOnly refresh cookie re-issues it on every page load (auth.refresh).
  token: string | null
}

export const useSession = create<SessionState>(() => ({ status: 'unknown', user: null, token: null }))

// Session-lifecycle commands work without (or with an expired) access token. Mirrors core's
// isSessionLifecycleCommand (protocols/ws/Router.cpp, discoverable passkey sign-in included), plus the pending-MFA allowlist (core
// auth/mfa/Pending.hpp kPendingCommands + kPendingEnrollmentCommands; tools/contracts/test_mfa_pending_contract.py
// keeps them equal): a pending sign-in has no token, and an unauthorized answer there means it ended, never that a
// refresh would help.
const LIFECYCLE: ReadonlySet<Command> = new Set<Command>([
  'auth.login',
  'auth.logout',
  'auth.refresh',
  'auth.isAuthenticated',
  // discoverable passkey sign-in (#358): an anonymous connection, no token yet
  'auth.passkey.options',
  'auth.passkey.login',
  // pending-MFA
  'auth.mfa.verify',
  'auth.mfa.cancel',
  // pending enrollment
  'auth.mfa.webauthn.register.options',
  'auth.mfa.webauthn.register.finish',
  'auth.mfa.totp.enroll.start',
  'auth.mfa.totp.enroll.confirm',
  'auth.mfa.recovery.acknowledge',
])

let refreshing: Promise<boolean> | null = null

export const api = new WsClient({
  path: '/ws',
  lifecycle: LIFECYCLE,
  token: () => useSession.getState().token ?? '',
  onToken: token => useSession.setState({ token }),
  onUnauthorized: () => refreshSession(),
  // The contract hash needs a session (no build fingerprinting before login): checked once signed in, and again on
  // every reconnect of a signed-in page.
  onOpen: () => {
    if (useSession.getState().status === 'authenticated') void checkServerContract(api)
  },
})

// Single-flight refresh. Resolves false (and marks the session unauthenticated) when the server definitively refuses.
export const refreshSession = (): Promise<boolean> => {
  if (refreshing) return refreshing
  refreshing = (async () => {
    try {
      const { user } = await api.send('auth.refresh', null)
      useSession.setState({ status: 'authenticated', user: (user as unknown as IUser) ?? useSession.getState().user })
      void checkServerContract(api)
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

export type LoginResult = { status: 'signed_in' } | { status: 'pending'; code: MfaPendingCode; pending: MfaPending }

// A refusal that left this socket pending-MFA (#357): auth.login's mfa_required / mfa_enrollment_required, or
// auth.mfa.verify's fresh challenge.
export const pendingOf = (error: unknown): { code: MfaPendingCode; pending: MfaPending } | null => {
  if (!isWsError(error) || (error.code !== 'mfa_required' && error.code !== 'mfa_enrollment_required')) return null
  const pending = readPending(error.data)
  return pending ? { code: error.code, pending } : null
}

// Signs in on a fresh connection: its handshake sets the refresh cookie this session will use (#354), so another tab
// that loaded the sign-in page later can't leave this browser holding a cookie that isn't this session's. A
// connection that comes up already signed in (another tab signed in meanwhile) answers already_signed_in: the browser
// is signed in, so take that session. When a second factor is due (#357) the connection is left pending: the caller
// finishes on this same socket (auth.mfa.verify or the enrollment commands) and then calls completeSignIn.
export const login = async (name: string, password: string): Promise<LoginResult> => {
  await api.reconnect()
  try {
    const { user } = await api.send('auth.login', { name, password })
    completeSignIn(user as unknown as IUser)
    return { status: 'signed_in' }
  } catch (error) {
    if (isWsError(error) && error.code === 'already_signed_in' && (await refreshSession())) return { status: 'signed_in' }
    const pending = pendingOf(error)
    if (pending) return { status: 'pending', ...pending }
    throw error
  }
}

// The answer that signed this socket in (auth.login, auth.mfa.verify, the enrollment's auth.mfa.recovery.acknowledge)
// carried the access token in its envelope.
export const completeSignIn = (user: IUser) => {
  if (!useSession.getState().token) throw new WsError('error', 'The server did not issue a session token')
  useSession.setState({ status: 'authenticated', user })
  void checkServerContract(api)
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
