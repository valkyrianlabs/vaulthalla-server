'use client'

import React, { useCallback, useEffect, useState } from 'react'
import { api } from '@/lib/session'
import { useStepUp } from '@/lib/stepUp'
import { isWsError } from '@/lib/ws/errors'
import {
  assertionToJson,
  ceremonyMessage,
  requestOptionsFromJson,
  webauthnSupported,
  type CredentialLike,
  type RequestOptionsJson,
} from '@/lib/webauthn'
import { Button } from '@/components/ui/Button'
import { Dialog, DialogContent } from '@/components/ui/Dialog'
import { Field, Input } from '@/components/ui/Field'
import { InlineError } from '@/components/ui/State'
import { KeyIcon } from '@/components/ui/icons'
import { PASSKEY_HINT, PASSKEY_LABEL } from '@/models/mfa'
import { readStepUp, STEP_UP_ACTION, stepUpWindowText, type StepUpMethod } from '@/models/stepUp'

interface Ceremony {
  id: string
  methods: StepUpMethod[]
  publicKey: RequestOptionsJson | null
  at: number
}

// The Step-up dialog (#359): a command answered step_up_required; the person confirms with a passkey, the password and
// an authenticator code, or (an account without MFA, lower-risk changes only) the password; the command is then resent.
// Everything that matters is decided by the server: this only collects the answer.
export const StepUpDialog = () => {
  const prompt = useStepUp(s => s.prompt)
  const [ceremony, setCeremony] = useState<Ceremony | null>(null)
  const [unavailable, setUnavailable] = useState<string | null>(null)
  const [busy, setBusy] = useState<null | 'begin' | 'webauthn' | 'password'>('begin')
  const [error, setError] = useState<unknown>(null)
  const [attempts, setAttempts] = useState<number | null>(null)
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')

  // Parsed once per prompt (the refusal's data is checked here, not trusted).
  const [request] = useState(() => (prompt ? readStepUp(prompt.error.code, prompt.error.data) : null))

  const begin = useCallback(async (): Promise<Ceremony | null> => {
    if (!request) return null
    setBusy('begin')
    try {
      const answer = await api.send('auth.stepup.begin', { family: request.family, target: request.target })
      const next: Ceremony = {
        id: answer.stepup_id,
        methods: answer.methods.filter((m): m is StepUpMethod => m === 'webauthn' || m === 'password_totp' || m === 'password'),
        publicKey: (answer.webauthn?.publicKey as RequestOptionsJson | undefined) ?? null,
        at: Date.now(),
      }
      setCeremony(next)
      return next
    } catch (err) {
      if (isWsError(err) && err.code === 'step_up_unavailable') setUnavailable(err.message)
      else setError(err)
      return null
    } finally {
      setBusy(null)
    }
  }, [request])

  useEffect(() => {
    if (prompt && !request) {
      prompt.resolve(false)
      return
    }
    if (request && request.methods.length === 0) {
      setUnavailable('This change can’t be confirmed from here. Add a passkey or an authenticator app in Account › Security, or do it in the web console.')
      setBusy(null)
      return
    }
    void begin()
  }, [prompt, request, begin])

  if (!prompt || !request) return null

  // The ceremony is good for 120 s; a fresh one is not an attempt.
  const live = async (): Promise<Ceremony | null> => (ceremony && Date.now() - ceremony.at < 100_000 ? ceremony : begin())

  const finish = async (body: Record<string, unknown>) => {
    const c = await live()
    if (!c) return
    try {
      await api.send('auth.stepup.finish', { stepup_id: c.id, ...body } as never)
      prompt.resolve(true)
    } catch (err) {
      setCeremony(null)
      if (isWsError(err) && err.code === 'step_up_failed') {
        const left = typeof err.data?.attempts_remaining === 'number' ? err.data.attempts_remaining : null
        setAttempts(left)
        if (left === 0) {
          setError(err)
          setUnavailable('Too many failed attempts: this session was signed out.')
          return
        }
      }
      setError(err)
      void begin()
    }
  }

  const usePasskey = async () => {
    setBusy('webauthn')
    setError(null)
    try {
      const c = await live()
      if (!c?.publicKey) throw new Error('No passkey can be used for this account here.')
      let credential: CredentialLike
      try {
        const got = await navigator.credentials.get({ publicKey: requestOptionsFromJson(c.publicKey) as PublicKeyCredentialRequestOptions })
        if (!got) throw new Error('No passkey was used.')
        credential = got as unknown as CredentialLike
      } catch (ceremonyError) {
        throw new Error(ceremonyMessage(ceremonyError))
      }
      await finish({ method: 'webauthn', credential: assertionToJson(credential) })
    } catch (err) {
      setError(err)
    } finally {
      setBusy(null)
    }
  }

  const methods = ceremony?.methods ?? []
  const passkey = methods.includes('webauthn') && !!ceremony?.publicKey && webauthnSupported()
  const withCode = methods.includes('password_totp')
  const passwordOnly = !withCode && methods.includes('password')

  const submitPassword = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!password || (withCode && !code.trim())) return
    setBusy('password')
    setError(null)
    try {
      await finish(withCode ? { method: 'password_totp', password, code: code.trim() } : { method: 'password', password })
    } finally {
      setPassword('')
      setCode('')
      setBusy(null)
    }
  }

  return (
    <Dialog open onOpenChange={open => !open && prompt.resolve(false)}>
      <DialogContent
        size="sm"
        title="Confirm it’s you"
        description={`${STEP_UP_ACTION[request.family]}. ${stepUpWindowText(request)}`}
        data-testid="stepup-dialog">
        {unavailable ? (
          <div className="space-y-3">
            <p className="text-sm text-fg-muted" data-testid="stepup-unavailable">
              {unavailable}
            </p>
            <Button variant="secondary" className="w-full" onClick={() => prompt.resolve(false)}>
              Close
            </Button>
          </div>
        ) : (
          <div className="space-y-4">
            {passkey ? (
              <div className="space-y-2">
                <Button variant="primary" size="lg" className="w-full" onClick={usePasskey} loading={busy === 'webauthn'} disabled={busy === 'begin'} data-testid="stepup-use-passkey">
                  <KeyIcon aria-hidden />
                  Use {PASSKEY_LABEL.toLowerCase()}
                </Button>
                <p className="text-center text-xs text-fg-subtle">{PASSKEY_HINT}.</p>
              </div>
            ) : null}
            {withCode || passwordOnly ? (
              <form onSubmit={submitPassword} className="space-y-3" noValidate>
                <Field label="Password" htmlFor="stepup-password">
                  <Input
                    id="stepup-password"
                    type="password"
                    autoComplete="current-password"
                    autoFocus={!passkey}
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    data-testid="stepup-password"
                  />
                </Field>
                {withCode ? (
                  <Field label="Code from your authenticator app" htmlFor="stepup-code">
                    <Input
                      id="stepup-code"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      maxLength={7}
                      value={code}
                      onChange={e => setCode(e.target.value)}
                      data-testid="stepup-code"
                    />
                  </Field>
                ) : null}
                <Button type="submit" variant={passkey ? 'secondary' : 'primary'} className="w-full" loading={busy === 'password'} disabled={busy === 'begin'} data-testid="stepup-submit">
                  Confirm
                </Button>
              </form>
            ) : null}
            <InlineError error={error} />
            {error && attempts !== null && attempts > 0 ? (
              <p className="text-xs text-fg-subtle">{attempts === 1 ? '1 attempt left' : `${attempts} attempts left`}.</p>
            ) : null}
            <div className="flex justify-end border-t border-line pt-3">
              <Button variant="ghost" size="sm" onClick={() => prompt.resolve(false)} data-testid="stepup-cancel">
                Cancel
              </Button>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
