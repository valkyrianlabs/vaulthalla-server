'use client'

import React, { useEffect, useRef, useState } from 'react'
import NextImage from 'next/image'
import dynamic from 'next/dynamic'
import { useRouter, useSearchParams } from 'next/navigation'
import { api, login, refreshSession } from '@/lib/session'
import { errorMessage, isWsError } from '@/lib/ws/errors'
import { Button } from '@/components/ui/Button'
import { Field, Input } from '@/components/ui/Field'
import { InlineError } from '@/components/ui/State'
import { vaulthallaQuotes } from '@/util/quotes'
import Logo from '@/public/vaulthalla-logo.png'
import type { MfaPending } from '@/models/mfa'

// The second step (#357) loads only when a sign-in needs it: /login's first load stays the password form.
const MfaSignIn = dynamic(() => import('./mfa/MfaSignIn').then(m => m.MfaSignIn), {
  ssr: false,
  loading: () => <div className="glass rounded-panel p-6 text-sm text-fg-subtle">Loading…</div>,
})

// Discoverable passkey sign-in (#358) is loaded on first use (the button) or once the browser says it can offer
// passkeys in the username field's autofill (conditional mediation): never in /login's first load.
const loadPasskeys = () => import('./passkeySignIn')

const passkeysSupported = () =>
  typeof window !== 'undefined' && typeof window.PublicKeyCredential === 'function' && !!navigator.credentials

// Only same-origin paths; never bounce back to /login or off-site.
const safeNext = (value: string | null) => (value && value.startsWith('/') && !value.startsWith('//') && !value.startsWith('/login') ? value : '/files')

export const LoginForm = () => {
  const router = useRouter()
  const next = safeNext(useSearchParams().get('next'))
  const [quote, setQuote] = useState<string | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [name, setName] = useState('')
  const [password, setPassword] = useState('')
  const [isSubmitting, setSubmitting] = useState(false)
  // A correct password with a factor due: this socket is pending until the second step finishes (or ends).
  const [pending, setPending] = useState<{ name: string; pending: MfaPending } | null>(null)
  // 'unavailable': the browser has no WebAuthn, or the server has no passkey relying party.
  const [passkeys, setPasskeys] = useState<'unknown' | 'available' | 'unavailable'>('unknown')
  const [passkeyBusy, setPasskeyBusy] = useState(false)
  // The open autofill request: aborted (and awaited) before anything else uses the connection or the authenticator.
  const autofill = useRef<{ controller: AbortController; done: Promise<unknown> } | null>(null)

  const stopAutofill = async () => {
    const current = autofill.current
    autofill.current = null
    if (!current) return
    current.controller.abort()
    await current.done
  }

  const startAutofill = async (isCancelled: () => boolean) => {
    const passkey = await loadPasskeys()
    if (isCancelled() || autofill.current || !(await passkey.conditionalMediationAvailable()) || isCancelled()) return
    const controller = new AbortController()
    const done = passkey
      .passkeyAutofill(controller.signal, setError)
      .then(outcome => {
        if (outcome === 'signed_in') router.replace(next)
      })
      .catch(err => {
        if (err instanceof passkey.PasskeysUnavailable) setPasskeys('unavailable')
      })
    autofill.current = { controller, done }
  }

  useEffect(() => {
    setQuote(vaulthallaQuotes[Math.floor(Math.random() * vaulthallaQuotes.length)])
    setPasskeys(passkeysSupported() ? 'available' : 'unavailable')
    // Already signed in (valid refresh cookie)? Skip the form. Otherwise offer passkeys in the username autofill.
    api.connect()
    let cancelled = false
    void refreshSession().then(ok => {
      if (cancelled) return
      if (ok) return router.replace(next)
      if (passkeysSupported()) void startAutofill(() => cancelled)
    })
    return () => {
      cancelled = true
      void stopAutofill()
    }
    // startAutofill and stopAutofill read refs and stable setters only.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [next, router])

  const onPasskey = async () => {
    setError(null)
    setPasskeyBusy(true)
    try {
      const passkey = await loadPasskeys()
      await stopAutofill()
      try {
        const outcome = await passkey.signInWithPasskey(new AbortController().signal)
        if (outcome === 'signed_in') return router.replace(next)
      } catch (err) {
        if (err instanceof passkey.PasskeysUnavailable) setPasskeys('unavailable')
        throw err
      }
    } catch (err) {
      setError(err)
    }
    setPasskeyBusy(false)
    void startAutofill(() => false)
  }

  const onSubmit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!name.trim() || !password) return setError(new Error('Enter your username and password'))
    setError(null)
    setSubmitting(true)
    await stopAutofill()
    try {
      const result = await login(name.trim(), password)
      if (result.status === 'pending') {
        setPassword('')
        setPending({ name: name.trim(), pending: result.pending })
        setSubmitting(false)
        return
      }
      router.replace(next)
    } catch (err) {
      setError(isWsError(err, 'unauthorized', 'error', 'denied', 'invalid') ? new Error(errorMessage(err, 'Invalid username or password')) : err)
      setSubmitting(false)
    }
  }

  return (
    <div className="w-full max-w-sm">
      <div className="mb-8 flex flex-col items-center text-center">
        <NextImage
          src={Logo}
          alt="Vaulthalla"
          priority
          width={132}
          height={132}
          className="mb-5 drop-shadow-[0_0_28px_rgb(34_211_238/0.22)]"
        />
        <h1 className="text-xl font-semibold tracking-tight text-fg">Sign in to Vaulthalla</h1>
        <p className="mt-2 min-h-5 max-w-xs text-sm text-fg-subtle italic">{quote}</p>
      </div>

      {pending ? (
        <MfaSignIn
          name={pending.name}
          pending={pending.pending}
          // After a recovery-code sign-in, Account → Security guides setting up a new factor and new codes.
          onFinished={recovery => router.replace(recovery ? '/account?recovery=1#security' : next)}
          onRestart={message => {
            setPending(null)
            setError(message ? new Error(message) : null)
          }}
        />
      ) : (
      <form onSubmit={onSubmit} className="glass space-y-4 rounded-panel p-6" noValidate>
        <Field label="Username" htmlFor="login-name">
          <Input id="login-name" autoComplete="username webauthn" autoFocus required value={name} onChange={e => setName(e.target.value)} />
        </Field>
        <Field label="Password" htmlFor="login-password">
          <Input id="login-password" type="password" autoComplete="current-password" required value={password} onChange={e => setPassword(e.target.value)} />
        </Field>
        <InlineError error={error} />
        <Button type="submit" variant="primary" size="lg" className="w-full" loading={isSubmitting} disabled={passkeyBusy}>
          Sign in
        </Button>
        {passkeys !== 'unavailable' && (
          <>
            <div className="flex items-center gap-3 text-xs text-fg-faint" aria-hidden>
              <span className="h-px flex-1 bg-line" />
              or
              <span className="h-px flex-1 bg-line" />
            </div>
            <Button type="button" size="lg" className="w-full" data-testid="passkey-sign-in" loading={passkeyBusy} disabled={isSubmitting} onClick={() => void onPasskey()}>
              Sign in with passkey
            </Button>
          </>
        )}
      </form>
      )}
      <p className="mt-6 text-center text-xs text-fg-faint">What you cannot verify, you do not control.</p>
    </div>
  )
}
