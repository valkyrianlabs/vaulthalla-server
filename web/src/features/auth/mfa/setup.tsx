'use client'

import React, { useEffect, useRef, useState } from 'react'
import { api } from '@/lib/session'
import { ceremonyMessage, creationOptionsFromJson, registrationToJson, webauthnSupported, type CredentialLike } from '@/lib/webauthn'
import { Button } from '@/components/ui/Button'
import { Field, Input } from '@/components/ui/Field'
import { Checkbox } from '@/components/ui/Choice'
import { InlineError } from '@/components/ui/State'
import { QrCode } from '@/components/ui/QrCode'
import { CopyIcon, DownloadIcon, KeyIcon } from '@/components/ui/icons'
import { PASSKEY_HINT, PASSKEY_LABEL } from '@/models/mfa'
import type { WebSocketCommandMap } from '@/util/webSocketCommands'

// Setting up a factor (#357), shared by the first-run enrollment at sign-in (a pending socket) and Account → Security
// (a signed-in one): the same commands, on the console's one socket. Neither knows which it is; the server does.

export type Enrolled = WebSocketCommandMap['auth.mfa.totp.enroll.confirm']['response']
export type RecoveryBatch = { batch_id: string; codes: string[] }

// "Passkey / Security key": registration with userVerification required (the browser asks for Touch ID, Windows
// Hello, a PIN, or the passkey manager's unlock).
export const PasskeySetup = ({
  onEnrolled,
  defaultLabel = 'Passkey',
  cta = 'Create passkey',
}: {
  onEnrolled: (result: Enrolled) => void
  defaultLabel?: string
  cta?: string
}) => {
  const [label, setLabel] = useState(defaultLabel)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const supported = webauthnSupported()

  const create = async () => {
    setBusy(true)
    setError(null)
    try {
      const { registration_id, publicKey } = await api.send('auth.mfa.webauthn.register.options', { label })
      let credential: CredentialLike
      try {
        const created = await navigator.credentials.create({ publicKey: creationOptionsFromJson(publicKey) as PublicKeyCredentialCreationOptions })
        if (!created) throw new Error('No passkey was created.')
        credential = created as unknown as CredentialLike
      } catch (ceremony) {
        throw new Error(ceremonyMessage(ceremony))
      }
      const result = await api.send('auth.mfa.webauthn.register.finish', {
        registration_id,
        label,
        credential: registrationToJson(credential),
      })
      onEnrolled(result)
    } catch (err) {
      setError(err)
      setBusy(false)
    }
  }

  return (
    <div className="space-y-4">
      <Field label="Name" htmlFor="mfa-passkey-label" hint="So you can tell your passkeys apart, e.g. “1Password” or “YubiKey”.">
        <Input id="mfa-passkey-label" value={label} maxLength={64} onChange={e => setLabel(e.target.value)} />
      </Field>
      {supported ? null : <InlineError error={new Error('This browser can’t use passkeys. Use an authenticator app instead.')} />}
      <InlineError error={error} />
      <Button variant="primary" className="w-full" onClick={create} loading={busy} disabled={!supported || !label.trim()} data-testid="mfa-passkey-create">
        <KeyIcon aria-hidden />
        {cta}
      </Button>
      <p className="text-center text-xs text-fg-subtle">
        {PASSKEY_LABEL}. {PASSKEY_HINT}.
      </p>
    </div>
  )
}

const groupSecret = (secret: string) => secret.replace(/(.{4})/g, '$1 ').trim()

// An authenticator app (RFC 6238): the QR code is drawn here, never by a service, and the secret is shown once.
export const TotpSetup = ({ onEnrolled }: { onEnrolled: (result: Enrolled) => void }) => {
  const [started, setStarted] = useState<WebSocketCommandMap['auth.mfa.totp.enroll.start']['response'] | null>(null)
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const once = useRef(false)

  useEffect(() => {
    if (once.current) return
    once.current = true
    api.send('auth.mfa.totp.enroll.start', { label: 'Authenticator app' }).then(setStarted, setError)
  }, [])

  const confirm = async (event: React.FormEvent) => {
    event.preventDefault()
    if (!started) return
    setBusy(true)
    setError(null)
    try {
      onEnrolled(await api.send('auth.mfa.totp.enroll.confirm', { enrollment_id: started.enrollment_id, code: code.replace(/\s/g, '') }))
    } catch (err) {
      setError(err)
      setBusy(false)
    }
  }

  if (!started) return error ? <InlineError error={error} /> : <p className="text-sm text-fg-subtle">Preparing…</p>
  return (
    <form onSubmit={confirm} className="space-y-4" noValidate>
      <div className="flex flex-col items-center gap-3 sm:flex-row sm:items-start">
        <QrCode value={started.otpauth_uri} label="QR code for your authenticator app" className="w-44 shrink-0" />
        <div className="min-w-0 space-y-2 text-sm text-fg-muted">
          <p>Scan the code with your authenticator app (1Password, Google Authenticator, Aegis…), or enter this key:</p>
          <code className="block rounded-md bg-surface-2 px-2 py-1.5 font-mono text-[13px] break-all text-fg" data-testid="mfa-totp-secret" data-secret={started.secret_base32}>
            {groupSecret(started.secret_base32)}
          </code>
          <a href={started.otpauth_uri} className="text-accent-text hover:underline">
            Open in an authenticator app on this device
          </a>
        </div>
      </div>
      <Field label="Code from the app" htmlFor="mfa-totp-code">
        <Input
          id="mfa-totp-code"
          inputMode="numeric"
          autoComplete="one-time-code"
          maxLength={7}
          value={code}
          onChange={e => setCode(e.target.value)}
          data-testid="mfa-totp-code"
        />
      </Field>
      <InlineError error={error} />
      <Button type="submit" variant="primary" className="w-full" loading={busy} disabled={code.replace(/\s/g, '').length !== 6} data-testid="mfa-totp-confirm">
        Turn on
      </Button>
    </form>
  )
}

// Ten codes, shown once, inactive until acknowledged. They stand in for a lost factor at sign-in only.
export const RecoveryCodes = ({
  batch,
  onAcknowledged,
  cta = 'I saved my recovery codes',
}: {
  batch: RecoveryBatch
  onAcknowledged: (batchId: string) => Promise<void>
  cta?: string
}) => {
  const [saved, setSaved] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const text = `Vaulthalla recovery codes (each works once)\n\n${batch.codes.join('\n')}\n`

  const download = () => {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }))
    const a = document.createElement('a')
    a.href = url
    a.download = 'vaulthalla-recovery-codes.txt'
    a.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }

  const acknowledge = async () => {
    setBusy(true)
    setError(null)
    try {
      await onAcknowledged(batch.batch_id)
    } catch (err) {
      setError(err)
      setBusy(false)
    }
  }

  return (
    <div className="space-y-4">
      <p className="text-sm text-fg-muted">
        If you lose your passkey or authenticator, one of these codes and your password get you back in. Each works once. Keep them
        somewhere other than your passkey manager, so one loss doesn’t take both.
      </p>
      <ol className="grid grid-cols-2 gap-x-4 gap-y-1.5 rounded-card border border-line bg-surface-1 p-4 font-mono text-sm text-fg" data-testid="mfa-recovery-codes">
        {batch.codes.map(c => (
          <li key={c} data-testid="mfa-recovery-code">
            {c}
          </li>
        ))}
      </ol>
      <div className="flex flex-wrap gap-2">
        <Button size="sm" onClick={() => void navigator.clipboard?.writeText(text)}>
          <CopyIcon aria-hidden />
          Copy
        </Button>
        <Button size="sm" onClick={download}>
          <DownloadIcon aria-hidden />
          Download
        </Button>
      </div>
      <label className="flex items-start gap-2.5 text-sm text-fg-muted">
        <Checkbox checked={saved} onCheckedChange={setSaved} data-testid="mfa-recovery-saved" />
        <span>I saved these codes somewhere safe.</span>
      </label>
      <InlineError error={error} />
      <Button variant="primary" className="w-full" disabled={!saved} loading={busy} onClick={acknowledge} data-testid="mfa-recovery-ack">
        {cta}
      </Button>
    </div>
  )
}
