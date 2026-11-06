// MFA (#357). A password sign-in that still owes a factor is "pending": auth.login refuses with data.code
// mfa_required (a factor is enrolled) or mfa_enrollment_required (the MFA policy requires one and there is none) and
// data.pending below. The socket is not signed in (no user, no access token, no session row) and may only finish
// (auth.mfa.verify, or the enrollment commands then auth.mfa.recovery.acknowledge), cancel or sign out. It ends after
// 5 minutes (10 enrolling), 5 failed factors, or when the socket closes. Core: auth/mfa/Pending.hpp, handler/Mfa.cpp.

import type { WsModels } from '../util/generated/wsContract.ts'

export type MfaMethod = 'webauthn' | 'totp' | 'recovery_code'
export type MfaPendingCode = 'mfa_required' | 'mfa_enrollment_required'

export interface MfaPending {
  kind: 'mfa' | 'enrollment'
  expires_at: number // Unix seconds, the server's clock
  methods: MfaMethod[]
  attempts_remaining: number
  // kind mfa with a usable passkey: PublicKeyCredentialRequestOptionsJSON (challenge good for publicKey.timeout ms).
  webauthn?: { publicKey: PublicKeyRequestOptionsJson }
}

export interface PublicKeyRequestOptionsJson {
  challenge: string
  rpId: string
  timeout: number
  userVerification: 'required'
  allowCredentials: { type: 'public-key'; id: string; transports?: string[] }[]
}

export type MfaFactor = WsModels['MfaFactor']

const METHODS: readonly MfaMethod[] = ['webauthn', 'totp', 'recovery_code']

// data.pending of a refusal, when it is one (a narrow guard: the refusal data is not in the generated contract).
export const readPending = (data: unknown): MfaPending | null => {
  if (!data || typeof data !== 'object') return null
  const p = (data as Record<string, unknown>).pending
  if (!p || typeof p !== 'object') return null
  const r = p as Record<string, unknown>
  if (r.kind !== 'mfa' && r.kind !== 'enrollment') return null
  if (typeof r.expires_at !== 'number' || !Array.isArray(r.methods)) return null
  const methods = r.methods.filter((m): m is MfaMethod => METHODS.includes(m as MfaMethod))
  const attempts = typeof r.attempts_remaining === 'number' ? r.attempts_remaining : 0
  const out: MfaPending = { kind: r.kind, expires_at: r.expires_at, methods, attempts_remaining: attempts }
  const w = r.webauthn as { publicKey?: PublicKeyRequestOptionsJson } | undefined
  if (w && typeof w === 'object' && w.publicKey && typeof w.publicKey.challenge === 'string') out.webauthn = { publicKey: w.publicKey }
  return out
}

// Names of the sign-in methods, as the console says them. "Passkey / Security key" is the wording for every
// WebAuthn authenticator (1Password, the device's passkey manager, a security key): no product is required.
export const PASSKEY_LABEL = 'Passkey / Security key'
export const PASSKEY_HINT = 'Works with 1Password, your device’s passkey manager, and security keys'
