'use client'

import React, { useEffect, useState } from 'react'
import dynamic from 'next/dynamic'
import { api } from '@/lib/session'
import { invalidate, useWs } from '@/lib/query'
import { formatDateTime, formatRelative } from '@/lib/format'
import { isWsError } from '@/lib/ws/errors'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Input } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import { InlineError, QueryState } from '@/components/ui/State'
import { notify } from '@/components/ui/Toast'
import { Notice } from '@/features/access/shared'
import { PASSKEY_HINT, PASSKEY_LABEL, type MfaFactor } from '@/models/mfa'
import type { Enrolled, RecoveryBatch } from '@/features/auth/mfa/setup'

// Account → Security → Sign-in factors (#357): the account's passkeys and authenticator apps, its recovery codes,
// and whether the MFA policy requires them. Removing a factor needs step-up (#359) and is not offered yet.

// The setup dialog (Radix, the QR encoder, WebAuthn) loads when it opens: none of it is in /account's first load.
const MfaSetupDialog = dynamic(() => import('./MfaSetupDialog').then(m => m.MfaSetupDialog), { ssr: false })

export type Open = null | { at: 'passkey' } | { at: 'totp' } | { at: 'codes'; batch: RecoveryBatch }

const REASONS: Record<string, string> = {
  policy_admins: 'Required: your role can change accounts, roles, settings or keys.',
  policy_all: 'Required for every account on this server.',
  user_required: 'Required for your account by an administrator.',
}

const kindLabel = (f: MfaFactor) =>
  f.kind === 'webauthn' ? (f.backup_eligible ? 'Synced passkey' : 'Passkey / security key') : 'Authenticator app'

export const MfaPanel = () => {
  const query = useWs('auth.mfa.status', null)
  // ?recovery=1: the sign-in page sends a recovery-code sign-in here.
  const [recoveryLanding, setRecoveryLanding] = useState(false)
  useEffect(() => setRecoveryLanding(new URLSearchParams(window.location.search).get('recovery') === '1'), [])
  const [open, setOpen] = useState<Open>(null)
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState<unknown>(null)

  const refresh = () => invalidate('auth.mfa.status', 'auth.sessions.list')

  const enrolled = (result: Enrolled) => {
    notify.success(result.factor.kind === 'webauthn' ? 'Passkey added' : 'Authenticator app turned on')
    refresh()
    setOpen(result.recovery_codes ? { at: 'codes', batch: result.recovery_codes } : null)
  }

  const acknowledge = async (batchId: string) => {
    await api.send('auth.mfa.recovery.acknowledge', { batch_id: batchId })
    notify.success('Recovery codes saved')
    setOpen(null)
    refresh()
  }

  const generate = async () => {
    setGenerating(true)
    setError(null)
    try {
      const batch = await api.send('auth.mfa.recovery.generate', null)
      setOpen({ at: 'codes', batch })
    } catch (err) {
      setError(
        isWsError(err) && err.code === 'step_up_required'
          ? new Error('To replace working recovery codes, sign out and sign in again with your passkey or app, then make them within 5 minutes.')
          : err,
      )
    } finally {
      setGenerating(false)
    }
  }

  return (
    <Panel id="security-factors" title="Sign-in factors" description="Passkeys and authenticator apps that confirm it’s you after your password.">
      <QueryState query={query}>
        {status => (
          <div className="space-y-4" data-testid="mfa-panel">
            {status.recovery_restricted || recoveryLanding ? (
              <Notice tone="warn" title="You signed in with a recovery code">
                Every other browser was signed out. Add a new passkey or authenticator app and make new recovery codes now.
                {status.cooldown_until ? ` Sensitive actions wait until ${formatDateTime(status.cooldown_until)}.` : ''}
              </Notice>
            ) : null}
            <div className="flex flex-wrap items-center gap-2 text-sm">
              {status.policy.required ? <Badge tone="accent">Required</Badge> : <Badge>Optional</Badge>}
              <span className="text-fg-subtle">{REASONS[status.policy.reason] ?? 'Recommended: it keeps your account safe if your password leaks.'}</span>
            </div>
            {status.factors.length ? (
              <ul className="divide-y divide-line" data-testid="mfa-factors">
                {status.factors.map(f => (
                  <FactorRow key={`${f.kind}-${f.id}`} factor={f} onRenamed={refresh} />
                ))}
              </ul>
            ) : (
              <p className="text-sm text-fg-subtle">No second factor yet.</p>
            )}
            <div className="flex flex-wrap gap-2">
              <Button
                variant="primary"
                size="sm"
                onClick={() => setOpen({ at: 'passkey' })}
                disabled={!status.policy.webauthn_available}
                title={status.policy.webauthn_available ? PASSKEY_HINT : 'Passkeys are not configured on this server (Settings → auth.webauthn).'}
                data-testid="mfa-add-passkey">
                Add {PASSKEY_LABEL.toLowerCase()}
              </Button>
              <Button size="sm" onClick={() => setOpen({ at: 'totp' })} data-testid="mfa-add-totp">
                Add authenticator app
              </Button>
            </div>
            <div className="rounded-card border border-line bg-surface-1 px-4 py-3 text-sm">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <div className="font-medium text-fg">Recovery codes</div>
                  <div className="text-fg-subtle" data-testid="mfa-recovery-remaining">
                    {status.recovery.active ? `${status.recovery.remaining} of 10 left` : 'None yet'}
                  </div>
                </div>
                <Button size="sm" onClick={generate} loading={generating} disabled={!status.factors.length} data-testid="mfa-recovery-generate">
                  {status.recovery.active ? 'Make new codes' : 'Make codes'}
                </Button>
              </div>
              <InlineError error={error} className="mt-2" />
            </div>
          </div>
        )}
      </QueryState>
      {open ? <MfaSetupDialog open={open} onClose={() => setOpen(null)} onEnrolled={enrolled} onAcknowledged={acknowledge} /> : null}
    </Panel>
  )
}

const FactorRow = ({ factor, onRenamed }: { factor: MfaFactor; onRenamed: () => void }) => {
  const [editing, setEditing] = useState(false)
  const [label, setLabel] = useState(factor.label)
  const [busy, setBusy] = useState(false)

  const save = async (event: React.FormEvent) => {
    event.preventDefault()
    setBusy(true)
    try {
      await api.send('auth.mfa.factor.rename', { kind: factor.kind, id: factor.id, label: label.trim() })
      setEditing(false)
      onRenamed()
    } catch (err) {
      notify.error(err, 'The name was not changed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <li className="flex flex-wrap items-center justify-between gap-3 py-3 first:pt-0 last:pb-0" data-testid="mfa-factor">
      <div className="min-w-0">
        {editing ? (
          <form onSubmit={save} className="flex items-center gap-2">
            <Input aria-label="Name" value={label} maxLength={64} onChange={e => setLabel(e.target.value)} className="h-8" />
            <Button type="submit" size="sm" loading={busy} disabled={!label.trim()}>
              Save
            </Button>
            <Button size="sm" variant="ghost" onClick={() => setEditing(false)}>
              Cancel
            </Button>
          </form>
        ) : (
          <div className="flex items-center gap-2">
            <span className="truncate font-medium text-fg">{factor.label}</span>
            {factor.suspended ? <Badge tone="danger">Suspended</Badge> : null}
          </div>
        )}
        <div className="mt-0.5 text-xs text-fg-subtle">
          {kindLabel(factor)} · added <span title={formatDateTime(factor.created_at)}>{formatRelative(factor.created_at)}</span>
          {factor.last_used_at ? (
            <>
              {' · used '}
              <span title={formatDateTime(factor.last_used_at)}>{formatRelative(factor.last_used_at)}</span>
            </>
          ) : null}
        </div>
      </div>
      {editing ? null : (
        <Button size="sm" variant="ghost" onClick={() => setEditing(true)}>
          Rename
        </Button>
      )}
    </li>
  )
}
