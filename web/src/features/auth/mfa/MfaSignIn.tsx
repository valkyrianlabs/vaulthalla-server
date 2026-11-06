'use client'

import React, { useState } from 'react'
import { api, completeSignIn, pendingOf } from '@/lib/session'
import { isWsError } from '@/lib/ws/errors'
import { assertionToJson, ceremonyMessage, requestOptionsFromJson, webauthnSupported, type CredentialLike } from '@/lib/webauthn'
import { Button } from '@/components/ui/Button'
import { Field, Input } from '@/components/ui/Field'
import { InlineError } from '@/components/ui/State'
import { KeyIcon, ShieldCheckIcon } from '@/components/ui/icons'
import { PASSKEY_HINT, PASSKEY_LABEL, type MfaPending } from '@/models/mfa'
import type { IUser } from '@/models/user'
import { PasskeySetup, RecoveryCodes, TotpSetup, type Enrolled, type RecoveryBatch } from './setup'

// The second sign-in step and the guided first run (#357, design sections 7.2, 8.1 and 8.2). The connection that sent
// the password is pending: it is not signed in until a factor succeeds here, and everything happens on it (a reload or
// a reconnect starts over with the password, by design).

export interface Recovery {
  codes_remaining: number
  cooldown_until: number
  sessions_revoked: number
}

interface Props {
  name: string
  pending: MfaPending
  // Signed in; `recovery` when it was with a recovery code (the account page then guides re-enrollment).
  onFinished: (recovery?: Recovery) => void
  // The pending sign-in is over (expired, too many attempts, cancelled): back to the password, with why.
  onRestart: (message?: string) => void
}

const RESTART_EXPIRED = 'The sign-in timed out. Enter your password again.'

// An answer that means the pending sign-in is gone: the router refuses (unauthorized), it expired, or the 5th failure.
const restartReason = (error: unknown): string | null => {
  if (isWsError(error, 'unauthorized') || (isWsError(error) && error.code === 'mfa_expired')) return RESTART_EXPIRED
  if (isWsError(error) && error.code === 'mfa_invalid' && error.data?.attempts_remaining === 0)
    return 'Too many attempts. Enter your password again.'
  return null
}

export const MfaSignIn = (props: Props) =>
  props.pending.kind === 'enrollment' ? <Enrollment {...props} /> : <SecondFactor {...props} />

const Frame = ({ title, subtitle, children }: { title: string; subtitle: React.ReactNode; children: React.ReactNode }) => (
  <div className="glass space-y-5 rounded-panel p-6" data-testid="mfa-step">
    <div>
      <h2 className="flex items-center gap-2 text-base font-semibold text-fg">
        <ShieldCheckIcon className="size-4 text-accent-text" aria-hidden />
        {title}
      </h2>
      <p className="mt-1 text-sm text-fg-subtle">{subtitle}</p>
    </div>
    {children}
  </div>
)

const SecondFactor = ({ name, pending: initial, onFinished, onRestart }: Props) => {
  const [pending, setPending] = useState(initial)
  const [optionsAt, setOptionsAt] = useState(() => Date.now())
  const [mode, setMode] = useState<'choose' | 'recovery'>('choose')
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState<null | 'webauthn' | 'code'>(null)
  const [error, setError] = useState<unknown>(null)
  const methods = pending.methods
  const passkey = methods.includes('webauthn') && !!pending.webauthn && webauthnSupported()

  const fail = (err: unknown) => {
    const restart = restartReason(err)
    if (restart) return onRestart(restart)
    // mfa_invalid carries the next challenge (the last one is spent) and the attempts left.
    const next = isWsError(err) && err.data ? (err.data.pending as MfaPending | undefined) : undefined
    if (next) {
      setPending(next)
      setOptionsAt(Date.now())
    }
    setError(err)
  }

  const finish = (answer: { user: unknown; recovery?: Recovery }) => {
    completeSignIn(answer.user as IUser)
    onFinished(answer.recovery)
  }

  const usePasskey = async () => {
    setBusy('webauthn')
    setError(null)
    try {
      let options = pending.webauthn?.publicKey
      // The challenge is good for publicKey.timeout: ask for a fresh one (not an attempt) when it is about to lapse.
      if (!options || Date.now() - optionsAt > options.timeout - 10_000) {
        try {
          await api.send('auth.mfa.verify', { method: 'webauthn' })
        } catch (err) {
          const fresh = pendingOf(err)
          if (!fresh) throw err
          setPending(fresh.pending)
          setOptionsAt(Date.now())
          options = fresh.pending.webauthn?.publicKey
        }
      }
      if (!options) throw new Error('No passkey can be used for this account here.')
      let credential: CredentialLike
      try {
        const got = await navigator.credentials.get({ publicKey: requestOptionsFromJson(options) as PublicKeyCredentialRequestOptions })
        if (!got) throw new Error('No passkey was used.')
        credential = got as unknown as CredentialLike
      } catch (ceremony) {
        throw new Error(ceremonyMessage(ceremony))
      }
      finish(await api.send('auth.mfa.verify', { method: 'webauthn', credential: assertionToJson(credential) }))
    } catch (err) {
      fail(err)
      setBusy(null)
    }
  }

  const submitCode = async (event: React.FormEvent) => {
    event.preventDefault()
    const method = mode === 'recovery' ? 'recovery_code' : 'totp'
    if (!code.trim()) return
    setBusy('code')
    setError(null)
    try {
      finish(await api.send('auth.mfa.verify', { method, code: code.trim() }))
    } catch (err) {
      fail(err)
      setCode('')
      setBusy(null)
    }
  }

  const cancel = async () => {
    try {
      await api.send('auth.mfa.cancel', null, { timeoutMs: 4000 })
    } catch {
      // Ending it is what we want either way.
    }
    onRestart()
  }

  const totp = methods.includes('totp')
  const recovery = methods.includes('recovery_code')
  const showCode = mode === 'recovery' ? recovery : totp
  const attempts = pending.attempts_remaining

  return (
    <Frame title="Confirm it’s you" subtitle={<>Signing in as <span className="font-medium text-fg">{name}</span>. Your password was right; now your second factor.</>}>
      {passkey && mode === 'choose' ? (
        <div className="space-y-2">
          <Button variant="primary" size="lg" className="w-full" onClick={usePasskey} loading={busy === 'webauthn'} data-testid="mfa-use-passkey">
            <KeyIcon aria-hidden />
            Use {PASSKEY_LABEL.toLowerCase()}
          </Button>
          <p className="text-center text-xs text-fg-subtle">{PASSKEY_HINT}.</p>
        </div>
      ) : null}
      {showCode ? (
        <form onSubmit={submitCode} className="space-y-3" noValidate>
          {mode === 'recovery' ? (
            <Field label="Recovery code" htmlFor="mfa-code" hint="One of the ten codes you saved, like ABCDE-FGHJK. It works once.">
              <Input id="mfa-code" autoComplete="off" autoCapitalize="characters" value={code} onChange={e => setCode(e.target.value)} data-testid="mfa-code" />
            </Field>
          ) : (
            <Field label="Code from your authenticator app" htmlFor="mfa-code">
              <Input
                id="mfa-code"
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={7}
                autoFocus={!passkey}
                value={code}
                onChange={e => setCode(e.target.value)}
                data-testid="mfa-code"
              />
            </Field>
          )}
          <Button type="submit" variant={passkey && mode === 'choose' ? 'secondary' : 'primary'} className="w-full" loading={busy === 'code'} data-testid="mfa-submit-code">
            {mode === 'recovery' ? 'Sign in with recovery code' : 'Verify code'}
          </Button>
        </form>
      ) : null}
      <InlineError error={error} />
      {error && attempts > 0 && attempts < 5 ? <p className="text-xs text-fg-subtle">{attempts === 1 ? '1 attempt left' : `${attempts} attempts left`}.</p> : null}
      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line pt-4 text-sm">
        {recovery ? (
          <Button
            variant="link"
            size="sm"
            onClick={() => {
              setMode(mode === 'recovery' ? 'choose' : 'recovery')
              setCode('')
              setError(null)
            }}
            data-testid="mfa-toggle-recovery">
            {mode === 'recovery' ? 'Use your passkey or app instead' : 'Use a recovery code'}
          </Button>
        ) : (
          <span />
        )}
        <Button variant="ghost" size="sm" onClick={cancel}>
          Cancel
        </Button>
      </div>
    </Frame>
  )
}

type Step = { at: 'choose' } | { at: 'passkey' } | { at: 'totp' } | { at: 'codes'; batch: RecoveryBatch } | { at: 'done' } | { at: 'another' }

// First run for an account the MFA policy requires a factor of (design 7.2): Create passkey (recommended) or an
// authenticator app, then the recovery codes; acknowledging them is what signs in.
const Enrollment = ({ name, pending, onFinished, onRestart }: Props) => {
  const [step, setStep] = useState<Step>({ at: 'choose' })
  const [error, setError] = useState<unknown>(null)
  const passkeys = pending.methods.includes('webauthn') && webauthnSupported()

  const enrolled = (result: Enrolled) => {
    if (!result.recovery_codes) return setError(new Error('The server did not return recovery codes. Start again.'))
    setStep({ at: 'codes', batch: result.recovery_codes })
  }

  const acknowledge = async (batchId: string) => {
    try {
      const answer = await api.send('auth.mfa.recovery.acknowledge', { batch_id: batchId })
      if (!answer.user) throw new Error('The server did not finish the sign-in.')
      completeSignIn(answer.user as unknown as IUser)
      setStep({ at: 'done' })
    } catch (err) {
      const restart = restartReason(err)
      if (restart) return onRestart(restart)
      throw err
    }
  }

  const guarded = (fn: (r: Enrolled) => void) => (r: Enrolled) => {
    setError(null)
    fn(r)
  }

  const cancel = async () => {
    try {
      await api.send('auth.mfa.cancel', null, { timeoutMs: 4000 })
    } catch {
      // Ending it is what we want either way.
    }
    onRestart()
  }

  if (step.at === 'done' || step.at === 'another')
    return (
      <Frame title="You’re signed in" subtitle="Your account is protected by a second factor.">
        {step.at === 'another' ? (
          <PasskeySetup cta="Add this passkey" defaultLabel="Second passkey" onEnrolled={() => onFinished()} />
        ) : (
          <>
            <p className="text-sm text-fg-muted">
              Add a second passkey too, on another device or in 1Password, so losing one never locks you out. You can do it later in Account → Security.
            </p>
            <div className="flex flex-col gap-2">
              <Button variant="primary" className="w-full" onClick={() => onFinished()} data-testid="mfa-enrollment-continue">
                Continue to Vaulthalla
              </Button>
              {passkeys ? (
                <Button className="w-full" onClick={() => setStep({ at: 'another' })}>
                  Add another passkey
                </Button>
              ) : null}
            </div>
          </>
        )}
      </Frame>
    )

  return (
    <Frame
      title={step.at === 'codes' ? 'Save your recovery codes' : 'Set up a second factor'}
      subtitle={
        step.at === 'codes' ? (
          'Last step: these codes are shown once.'
        ) : (
          <>
            Your password was right, <span className="font-medium text-fg">{name}</span>. This account needs a second factor before it can sign in.
          </>
        )
      }>
      {step.at === 'choose' ? (
        <div className="space-y-3">
          {passkeys ? (
            <div className="space-y-1.5">
              <Button variant="primary" size="lg" className="w-full" onClick={() => setStep({ at: 'passkey' })} data-testid="mfa-choose-passkey">
                <KeyIcon aria-hidden />
                Create passkey (recommended)
              </Button>
              <p className="text-center text-xs text-fg-subtle">
                {PASSKEY_LABEL}. {PASSKEY_HINT}.
              </p>
            </div>
          ) : (
            <p className="text-sm text-fg-subtle">
              {pending.methods.includes('webauthn')
                ? 'This browser can’t use passkeys. Use an authenticator app.'
                : 'Passkeys aren’t set up on this server yet. Use an authenticator app.'}
            </p>
          )}
          <Button size="lg" className="w-full" variant={passkeys ? 'secondary' : 'primary'} onClick={() => setStep({ at: 'totp' })} data-testid="mfa-choose-totp">
            Use an authenticator app
          </Button>
        </div>
      ) : null}
      {step.at === 'passkey' ? <PasskeySetup onEnrolled={guarded(enrolled)} /> : null}
      {step.at === 'totp' ? <TotpSetup onEnrolled={guarded(enrolled)} /> : null}
      {step.at === 'codes' ? <RecoveryCodes batch={step.batch} onAcknowledged={acknowledge} cta="I saved them: finish signing in" /> : null}
      <InlineError error={error} />
      {step.at !== 'codes' ? (
        <div className="flex justify-between gap-2 border-t border-line pt-4">
          {step.at !== 'choose' ? (
            <Button variant="ghost" size="sm" onClick={() => setStep({ at: 'choose' })}>
              Back
            </Button>
          ) : (
            <span />
          )}
          <Button variant="ghost" size="sm" onClick={cancel}>
            Cancel
          </Button>
        </div>
      ) : null}
    </Frame>
  )
}
