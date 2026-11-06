'use client'

import React, { useState } from 'react'
import { useWs, useWsMutation } from '@/lib/query'
import { formatDateTime } from '@/lib/format'
import { isWsError } from '@/lib/ws/errors'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Dialog, DialogContent } from '@/components/ui/Dialog'
import { Field, Input } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import { InlineError, Skeleton } from '@/components/ui/State'
import { notify } from '@/components/ui/Toast'
import type { UserRecord } from '@/features/access/types'

// Users → a user → Sign-in factors (#360): another account's MFA. The server decides who may (whoever may reset the
// account's password; a super admin's only a super admin), so a refusal just says so. Reset is for an account that
// lost every factor: factors disabled, codes voided, sessions signed out, enrollment at the next sign-in, a recovery
// cooldown. Both actions ask for a step-up (the client's step-up dialog handles the refusal and resends).

const REASONS: Record<string, string> = {
  policy_admins: 'Required: administrators must use a second factor.',
  policy_all: 'Required for every account on this server.',
  user_required: 'Required for this account.',
  none: 'Not required.',
}

export const MfaAdminPanel = ({ user }: { user: UserRecord }) => {
  const status = useWs('auth.mfa.admin.status', { user_id: user.id }, { retry: false })
  const [resetOpen, setResetOpen] = useState(false)
  const require = useWsMutation('auth.mfa.admin.require', {
    invalidates: ['auth.mfa.admin.status'],
    onSuccess: data => notify.success(data.required_flag ? `MFA is now required for ${user.name}` : `MFA follows the policy for ${user.name}`),
  })

  if (status.isPending) return <Panel title="Sign-in factors"><Skeleton className="h-16" /></Panel>
  if (status.error) {
    // Not ours to manage (or an older daemon): say so quietly.
    if (isWsError(status.error, 'denied', 'not_found', 'invalid', 'error')) return null
    return (
      <Panel title="Sign-in factors">
        <InlineError error={status.error} />
      </Panel>
    )
  }
  const s = status.data
  return (
    <Panel title="Sign-in factors" id="mfa-admin" description="Passkeys and authenticator apps this account signs in with.">
      <div className="space-y-3 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          {s.required ? <Badge tone="accent">Required</Badge> : <Badge>Optional</Badge>}
          <span className="text-fg-subtle">{REASONS[s.reason] ?? ''}</span>
        </div>
        <div data-testid="mfa-admin-factors">
          {s.factors.length
            ? `${s.factors.length} factor${s.factors.length === 1 ? '' : 's'}: ${s.factors.map(f => f.label).join(', ')}`
            : 'No sign-in factors.'}
          {' · '}
          {s.recovery.active ? `${s.recovery.remaining} recovery codes left` : 'no recovery codes'}
        </div>
        {s.cooldown_until ? (
          <div className="text-fg-subtle">Recovery cooldown until {formatDateTime(s.cooldown_until)}: sensitive actions wait.</div>
        ) : null}
        {s.reset_at ? <div className="text-fg-subtle">Last reset {formatDateTime(s.reset_at)}.</div> : null}
        <div className="flex flex-wrap gap-2 pt-1">
          <Button
            size="sm"
            onClick={() => require.mutate({ user_id: user.id, required: !s.required_flag })}
            loading={require.isPending}
            data-testid="mfa-admin-require">
            {s.required_flag ? 'Stop requiring MFA' : 'Require MFA'}
          </Button>
          <Button size="sm" variant="danger" onClick={() => setResetOpen(true)} data-testid="mfa-admin-reset">
            Reset MFA…
          </Button>
        </div>
        <InlineError error={require.error} />
      </div>
      {resetOpen ? <ResetMfaDialog user={user} open onOpenChange={setResetOpen} /> : null}
    </Panel>
  )
}

const ResetMfaDialog = ({ user, open, onOpenChange }: { user: UserRecord; open: boolean; onOpenChange: (open: boolean) => void }) => {
  const [reason, setReason] = useState('')
  const reset = useWsMutation('auth.mfa.admin.reset', {
    invalidates: ['auth.mfa.admin.status'],
    onSuccess: data => {
      notify.success(
        `MFA reset for ${user.name}`,
        `${data.factors_disabled} factor(s) disabled, ${data.sessions_revoked} session(s) signed out. They set up a new factor at their next sign-in.`,
      )
      onOpenChange(false)
    },
  })
  const trimmed = reason.trim()
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        size="sm"
        title={`Reset ${user.name}’s MFA`}
        description="For an account that lost every passkey and authenticator app. Its factors stop working, its recovery codes are voided, every session is signed out and paired devices pause their automatic key backup (they stay paired). They set up a new factor at their next sign-in, and sensitive actions wait for the recovery cooldown. They and the security recipients are emailed."
        footer={
          <>
            <Button variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button variant="danger" type="submit" form="reset-mfa-form" loading={reset.isPending} disabled={!trimmed} data-testid="mfa-admin-reset-confirm">
              Reset MFA
            </Button>
          </>
        }>
        <form
          id="reset-mfa-form"
          noValidate
          onSubmit={e => {
            e.preventDefault()
            if (trimmed) reset.mutate({ user_id: user.id, reason: trimmed })
          }}
          className="space-y-4">
          <Field label="Reason" htmlFor="reset-mfa-reason" required hint="Kept in the audit trail, e.g. “lost phone, verified by video call”.">
            <Input id="reset-mfa-reason" value={reason} maxLength={200} autoFocus onChange={e => setReason(e.target.value)} data-testid="mfa-admin-reset-reason" />
          </Field>
          <InlineError error={reset.error} />
        </form>
      </DialogContent>
    </Dialog>
  )
}
