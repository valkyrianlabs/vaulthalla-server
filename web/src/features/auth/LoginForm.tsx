'use client'

import React, { useEffect, useState } from 'react'
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

  useEffect(() => {
    setQuote(vaulthallaQuotes[Math.floor(Math.random() * vaulthallaQuotes.length)])
    // Already signed in (valid refresh cookie)? Skip the form.
    api.connect()
    let cancelled = false
    void refreshSession().then(ok => {
      if (ok && !cancelled) router.replace(next)
    })
    return () => {
      cancelled = true
    }
  }, [next, router])

  const onSubmit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!name.trim() || !password) return setError(new Error('Enter your username and password'))
    setError(null)
    setSubmitting(true)
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
          <Input id="login-name" autoComplete="username" autoFocus required value={name} onChange={e => setName(e.target.value)} />
        </Field>
        <Field label="Password" htmlFor="login-password">
          <Input id="login-password" type="password" autoComplete="current-password" required value={password} onChange={e => setPassword(e.target.value)} />
        </Field>
        <InlineError error={error} />
        <Button type="submit" variant="primary" size="lg" className="w-full" loading={isSubmitting}>
          Sign in
        </Button>
      </form>
      )}
      <p className="mt-6 text-center text-xs text-fg-faint">What you cannot verify, you do not control.</p>
    </div>
  )
}
