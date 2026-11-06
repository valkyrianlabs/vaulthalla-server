'use client'

import { api, completeSignIn, refreshSession } from '@/lib/session'
import { WsError, isWsError } from '@/lib/ws/errors'
import { assertionToJson, ceremonyMessage, requestOptionsFromJson, type CredentialLike, type RequestOptionsJson } from '@/lib/webauthn'
import type { IUser } from '@/models/user'

// Discoverable passkey sign-in (#358; design sections 4.1 and 8.6): a passkey alone, no username or password first.
// Loaded on demand by LoginForm (the "Sign in with passkey" button, and the autofill request where the browser has
// conditional mediation), so none of it is in /login's first load.
//
// auth.passkey.options and auth.passkey.login run on the same connection: the challenge is bound to it. Both are in
// LIFECYCLE (lib/session.ts): an anonymous connection has no token to refresh.

export type PasskeyOutcome = 'signed_in' | 'aborted'

// The server has no passkey relying party (auth.webauthn.rp_id): the button has nothing to offer.
export class PasskeysUnavailable extends Error {}

interface Options {
  publicKey: RequestOptionsJson
  expires_at: number
}

const fetchOptions = async (): Promise<Options> => {
  try {
    return (await api.send('auth.passkey.options', null)) as unknown as Options
  } catch (error) {
    if (isWsError(error, 'invalid')) throw new PasskeysUnavailable(error.message)
    throw error
  }
}

const aborted = (error: unknown) => !!error && typeof error === 'object' && 'name' in error && (error as { name: unknown }).name === 'AbortError'

// Hands the assertion to the daemon. An already_signed_in connection means another tab signed this browser in.
const finish = async (credential: CredentialLike): Promise<PasskeyOutcome> => {
  try {
    const { user } = await api.send('auth.passkey.login', { credential: assertionToJson(credential) })
    completeSignIn(user as unknown as IUser)
    return 'signed_in'
  } catch (error) {
    if (isWsError(error) && error.code === 'already_signed_in' && (await refreshSession())) return 'signed_in'
    throw error
  }
}

const getCredential = async (options: RequestOptionsJson, mediation: 'conditional' | undefined, signal: AbortSignal) => {
  const got = await navigator.credentials.get({
    publicKey: requestOptionsFromJson(options) as PublicKeyCredentialRequestOptions,
    signal,
    ...(mediation ? { mediation } : {}),
  })
  if (!got) throw new WsError('error', 'No passkey was used.')
  return got as unknown as CredentialLike
}

// The button: a fresh connection (like a password sign-in, so it owns the browser's current refresh cookie, #354),
// a challenge, the browser's passkey prompt, the sign-in.
export const signInWithPasskey = async (signal: AbortSignal): Promise<PasskeyOutcome> => {
  await api.reconnect()
  const { publicKey } = await fetchOptions()
  let credential: CredentialLike
  try {
    credential = await getCredential(publicKey, undefined, signal)
  } catch (ceremony) {
    if (signal.aborted || aborted(ceremony)) return 'aborted'
    throw new Error(ceremonyMessage(ceremony))
  }
  return finish(credential)
}

export const conditionalMediationAvailable = async (): Promise<boolean> => {
  try {
    const pkc = window.PublicKeyCredential as unknown as { isConditionalMediationAvailable?: () => Promise<boolean> }
    return typeof pkc?.isConditionalMediationAvailable === 'function' && (await pkc.isConditionalMediationAvailable())
  } catch {
    return false
  }
}

const sleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>(resolve => {
    if (signal.aborted) return resolve()
    const timer = setTimeout(resolve, ms)
    signal.addEventListener('abort', () => {
      clearTimeout(timer)
      resolve()
    }, { once: true })
  })

// The autofill request (mediation "conditional"): the browser lists this server's passkeys under the username field.
// It stays open until the person picks one or `signal` aborts it (the password form was sent, the button was used).
// A challenge lives 120 s, so the request is renewed shortly before it lapses. A refused passkey is reported through
// onError and the request starts over with a fresh challenge.
export const passkeyAutofill = async (signal: AbortSignal, onError: (message: unknown) => void): Promise<PasskeyOutcome> => {
  while (!signal.aborted) {
    const { publicKey } = await fetchOptions()
    if (signal.aborted) break
    const renew = new AbortController()
    const stop = () => renew.abort()
    signal.addEventListener('abort', stop, { once: true })
    const timer = setTimeout(stop, Math.max(5_000, publicKey.timeout - 10_000))
    let credential: CredentialLike | null = null
    try {
      credential = await getCredential(publicKey, 'conditional', renew.signal)
    } catch (ceremony) {
      // Renewed or stopped: nothing to report. Anything else is the browser refusing; try again shortly.
      if (!renew.signal.aborted && !aborted(ceremony)) {
        onError(new Error(ceremonyMessage(ceremony)))
        await sleep(2_000, signal)
      }
    } finally {
      clearTimeout(timer)
      signal.removeEventListener('abort', stop)
    }
    if (!credential || signal.aborted) continue
    try {
      return await finish(credential)
    } catch (error) {
      onError(error)
      await sleep(1_000, signal)
    }
  }
  return 'aborted'
}
