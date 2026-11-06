'use client'

import React from 'react'
import { useWs, useWsMutation } from '@/lib/query'
import { formatDateTime, formatRelative } from '@/lib/format'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Panel } from '@/components/ui/Panel'
import { QueryState } from '@/components/ui/State'
import { confirm } from '@/components/ui/Confirm'
import { notify } from '@/components/ui/Toast'
import type { AuthSession } from '@/models/authSession'

// Account → Security → Sessions (#354): the browsers signed in to this account (every tab of one browser shares a
// session), how each signed in, and a way to sign them out. Revoking ends the session at once on the server.

const METHOD_LABELS: Record<string, string> = {
  pwd: 'Password',
  hwk: 'Security key or device passkey',
  swk: 'Synced passkey',
  otp: 'Authenticator code',
  rec: 'Recovery code',
}

const methods = (session: AuthSession) => session.amr.map(m => METHOD_LABELS[m] ?? m).join(' + ') || 'Unknown'

// "Mozilla/5.0 (Macintosh; …) … Chrome/131…" → "Chrome on macOS". A hint only: the user agent is what the browser said.
export const describeAgent = (agent: string) => {
  const browser = /Edg\//.test(agent)
    ? 'Edge'
    : /Firefox\//.test(agent)
      ? 'Firefox'
      : /Chrome\//.test(agent)
        ? 'Chrome'
        : /Safari\//.test(agent)
          ? 'Safari'
          : null
  const os = /Windows/.test(agent)
    ? 'Windows'
    : /iPhone|iPad/.test(agent)
      ? 'iOS'
      : /Mac OS X|Macintosh/.test(agent)
        ? 'macOS'
        : /Android/.test(agent)
          ? 'Android'
          : /Linux/.test(agent)
            ? 'Linux'
            : null
  if (browser && os) return `${browser} on ${os}`
  return browser ?? os ?? (agent || 'Unknown browser')
}

export const SessionsPanel = () => {
  const query = useWs('auth.sessions.list', null)
  const revoke = useWsMutation('auth.sessions.revoke', {
    toPayload: (payload: { id: string } | { all_others: true }) => payload,
    invalidates: ['auth.sessions.list'],
  })

  const askRevoke = async (session: AuthSession) => {
    const ok = await confirm({
      title: `Sign out ${describeAgent(session.user_agent)}?`,
      description: 'That browser is signed out now and has to sign in again.',
      confirmLabel: 'Sign out',
      tone: 'danger',
    })
    if (!ok) return
    revoke.mutate(
      { id: session.id },
      {
        onSuccess: () => notify.success('Session signed out'),
        onError: error => notify.error(error, 'The session was not signed out'),
      },
    )
  }

  const askRevokeOthers = async () => {
    const ok = await confirm({
      title: 'Sign out every other session?',
      description: 'Every other browser signed in to your account is signed out now. This one stays signed in.',
      confirmLabel: 'Sign out others',
      tone: 'danger',
    })
    if (!ok) return
    revoke.mutate(
      { all_others: true },
      {
        onSuccess: data => notify.success(data.revoked === 1 ? '1 session signed out' : `${data.revoked} sessions signed out`),
        onError: error => notify.error(error, 'The sessions were not signed out'),
      },
    )
  }

  const others = query.data?.sessions.filter(s => !s.current).length ?? 0

  return (
    <Panel
      id="sessions"
      title="Sessions"
      description="Browsers signed in to your account. Sign out any you don’t recognise."
      actions={
        others > 0 ? (
          <Button size="sm" variant="danger" onClick={askRevokeOthers} loading={revoke.isPending} data-testid="sessions-revoke-others">
            Sign out other sessions
          </Button>
        ) : null
      }>
      <QueryState query={query}>
        {data => (
          <ul className="divide-y divide-line" data-testid="sessions-list">
            {data.sessions.map(session => (
              <li key={session.id} className="flex flex-wrap items-center justify-between gap-3 py-3 first:pt-0 last:pb-0" data-testid="session-row">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="truncate font-medium text-fg" title={session.user_agent}>
                      {describeAgent(session.user_agent)}
                    </span>
                    {session.current ? (
                      <Badge tone="accent" className="h-5 px-2 text-[11px]">
                        This session
                      </Badge>
                    ) : null}
                  </div>
                  <div className="mt-0.5 text-xs text-fg-subtle">
                    <span className="font-mono">{session.ip_address || '—'}</span>
                    {' · '}
                    <span title={formatDateTime(session.auth_time)}>Signed in {formatRelative(session.auth_time)}</span>
                    {' with '}
                    {methods(session)}
                    {' · '}
                    <span title={formatDateTime(session.last_activity_at)}>Active {formatRelative(session.last_activity_at)}</span>
                  </div>
                </div>
                {session.current ? null : (
                  <Button size="sm" variant="secondary" onClick={() => askRevoke(session)} data-testid="session-revoke">
                    Sign out
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </QueryState>
    </Panel>
  )
}
