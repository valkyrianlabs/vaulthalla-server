'use client'

import React, { useId, useState } from 'react'
import Link from 'next/link'
import { api } from '@/lib/session'
import { invalidate, queryClient, wsKey } from '@/lib/query'
import { DASH, formatDateTime } from '@/lib/format'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Field, Input } from '@/components/ui/Field'
import { DefinitionList, Panel } from '@/components/ui/Panel'
import { InlineError, QueryState } from '@/components/ui/State'
import { confirm } from '@/components/ui/Confirm'
import { notify } from '@/components/ui/Toast'
import { ArrowsRotateIcon, BucketIcon, CircleCheckIcon, CircleExclamationIcon } from '@/components/ui/icons'
import type { ProviderCredential } from '@/features/credentials/types'
import { supportsAdmin, type AdminStatus, type Capability } from '@/models/upstream'
import { useAdminStatus, useUpstreamPerms } from '@/features/credentials/upstream/hooks'

const CAPABILITY_LABELS: Record<string, string> = {
  'buckets.list': 'List buckets',
  'buckets.create': 'Create buckets',
  lifecycle: 'Lifecycle rules',
  'events.notifications': 'Event notifications',
  'events.queues': 'Event queues',
}

const refresh = () => invalidate('upstream.admin.status', 'storage.apiKey.get', 'storage.apiKey.list')

// Provider administration (#237) on one AWS / Cloudflare R2 credential: enable it, see what the provider lets it do,
// and (R2) store the Cloudflare account API token the event infrastructure needs. Lazy-loaded by the credential page.
const AdminPanel = ({ credential }: { credential: ProviderCredential }) => {
  const perms = useUpstreamPerms()
  const canRead = perms.view || perms.configure
  const supported = supportsAdmin(credential.provider)
  const status = useAdminStatus(credential.api_key_id, supported && canRead)

  if (!supported)
    return (
      <Panel title="Provider administration">
        <p className="text-fg-subtle text-sm">
          Not supported for this provider. Vaulthalla can create, adopt and watch buckets for AWS S3 and Cloudflare R2
          credentials; this one keeps working as plain vault storage.
        </p>
      </Panel>
    )

  if (!canRead)
    return (
      <Panel title="Provider administration">
        <p className="text-fg-subtle text-sm">
          {credential.admin_enabled ? 'Enabled on this credential.' : 'Not enabled on this credential.'} Your role
          doesn’t include an upstream administration permission.
        </p>
      </Panel>
    )

  return (
    <QueryState
      query={status}
      pending={
        <Panel title="Provider administration">
          <p className="text-fg-subtle text-sm">Loading…</p>
        </Panel>
      }>
      {data => <AdminBody credential={credential} status={data} />}
    </QueryState>
  )
}

const AdminBody = ({ credential, status }: { credential: ProviderCredential; status: AdminStatus }) => {
  const ids = useId()
  const perms = useUpstreamPerms()
  const isR2 = credential.provider === 'Cloudflare R2'
  const [token, setToken] = useState('')
  const [busy, setBusy] = useState<null | 'enable' | 'disable' | 'probe' | 'token' | 'clear'>(null)
  const [error, setError] = useState<unknown>(null)

  const run = async (kind: NonNullable<typeof busy>, fn: () => Promise<void>) => {
    setBusy(kind)
    setError(null)
    try {
      await fn()
    } catch (e) {
      setError(e)
    } finally {
      setBusy(null)
    }
  }

  const enable = () =>
    run('enable', async () => {
      await api.send('upstream.admin.enable', {
        api_key_id: credential.api_key_id,
        ...(isR2 && token ? { provider_token: token } : {}),
      })
      setToken('')
      await refresh()
      notify.success('Provider administration enabled', credential.name)
    })

  const disable = () =>
    run('disable', async () => {
      const ok = await confirm({
        title: 'Disable provider administration?',
        description:
          'Vaulthalla stops creating, adopting and configuring buckets with this credential. Vaults keep their buckets and data. The daemon refuses while an event subscription still runs on this credential.',
        confirmLabel: 'Disable',
        tone: 'danger',
      })
      if (!ok) return
      await api.send('upstream.admin.disable', { api_key_id: credential.api_key_id })
      await refresh()
      notify.success('Provider administration disabled', credential.name)
    })

  const probe = () =>
    run('probe', async () => {
      const res = await api.send('upstream.admin.status', { api_key_id: credential.api_key_id, probe: true })
      queryClient.setQueryData(wsKey('upstream.admin.status', { api_key_id: credential.api_key_id }), res)
      await invalidate('storage.apiKey.get')
    })

  const saveToken = () =>
    run('token', async () => {
      await api.send('upstream.admin.enable', { api_key_id: credential.api_key_id, provider_token: token })
      setToken('')
      await refresh()
      notify.success('Cloudflare API token stored', 'It is sealed on the server and never shown again.')
    })

  const clearToken = () =>
    run('clear', async () => {
      const ok = await confirm({
        title: 'Remove the Cloudflare API token?',
        description: 'Event-driven sync for this account stops working until a token is stored again.',
        confirmLabel: 'Remove token',
        tone: 'danger',
      })
      if (!ok) return
      await api.send('upstream.admin.enable', { api_key_id: credential.api_key_id, clear_provider_token: true })
      await refresh()
    })

  const caps = status.capabilities?.items ?? []

  return (
    <Panel
      title="Provider administration"
      description="Let Vaulthalla list, create, adopt and configure buckets in this account, and run event-driven sync. Who may do what is decided by admin.upstream permissions."
      actions={
        status.enabled ?
          <Badge tone="ok" dot>
            Enabled
          </Badge>
        : <Badge tone="neutral">Disabled</Badge>
      }>
      <div className="space-y-4">
        {!status.supported ?
          <p className="text-fg-subtle text-sm">{status.unsupported_reason || 'Not supported for this provider.'}</p>
        : null}

        <DefinitionList
          items={[
            [
              'Account',
              <span key="a" className="font-mono text-xs">
                {status.account_ref ?? credential.provider_account_id ?? DASH}
              </span>,
            ],
            [
              'Principal',
              <span key="p" className="font-mono text-xs break-all">
                {status.capabilities?.identity?.principal || DASH}
              </span>,
            ],
            [
              'Last checked',
              <span key="c" className="tabular">
                {formatDateTime(status.capabilities?.checked_at ?? credential.admin_validated_at)}
              </span>,
            ],
            ...(isR2 ?
              ([
                [
                  'Cloudflare API token',
                  status.has_provider_token ?
                    <Badge key="t" tone="ok">
                      Stored
                    </Badge>
                  : <span key="t" className="text-fg-subtle">
                      None
                    </span>,
                ],
              ] as [React.ReactNode, React.ReactNode][])
            : []),
          ]}
        />

        {caps.length ?
          <ul className="divide-line rounded-card border-line divide-y border" aria-label="Capabilities">
            {caps.map(cap => (
              <CapabilityRow key={cap.name} cap={cap} />
            ))}
          </ul>
        : status.enabled ?
          <p className="text-fg-subtle text-sm">No capability check recorded yet. Re-check to probe the provider.</p>
        : null}

        {isR2 && perms.configure ?
          <div className="rounded-card border-line bg-surface-1 border p-4">
            <Field
              label="Cloudflare API token"
              htmlFor={`${ids}-token`}
              hint="Needed only for event-driven sync (R2 event notifications and Cloudflare Queues). Create an account API token with Account › Queues: Edit and Account › Workers R2 Storage: Edit. The R2 access key above can’t do this: it only speaks the S3 API.">
              <Input
                id={`${ids}-token`}
                type="password"
                autoComplete="new-password"
                spellCheck={false}
                className="font-mono"
                placeholder={status.has_provider_token ? 'Stored (enter a new one to replace it)' : 'Paste the token'}
                value={token}
                onChange={e => setToken(e.target.value)}
              />
            </Field>
            {status.enabled ?
              <div className="mt-3 flex flex-wrap justify-end gap-2">
                {status.has_provider_token ?
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={clearToken}
                    loading={busy === 'clear'}
                    disabled={busy !== null}>
                    Remove token
                  </Button>
                : null}
                <Button size="sm" onClick={saveToken} loading={busy === 'token'} disabled={!token || busy !== null}>
                  Save token
                </Button>
              </div>
            : null}
          </div>
        : null}

        <InlineError error={error} />

        <div className="flex flex-wrap items-center justify-end gap-2">
          {status.enabled && (perms.view || perms.protect) ?
            <Button asChild variant="subtle">
              <Link href={`/credentials/${credential.api_key_id}/buckets`}>
                <BucketIcon aria-hidden />
                Buckets
              </Link>
            </Button>
          : null}
          {perms.configure && status.enabled ?
            <Button variant="ghost" onClick={probe} loading={busy === 'probe'} disabled={busy !== null}>
              <ArrowsRotateIcon aria-hidden />
              Re-check
            </Button>
          : null}
          {perms.configure && status.enabled ?
            <Button variant="danger" onClick={disable} loading={busy === 'disable'} disabled={busy !== null}>
              Disable
            </Button>
          : null}
          {perms.configure && !status.enabled && status.supported ?
            <Button variant="primary" onClick={enable} loading={busy === 'enable'} disabled={busy !== null}>
              {busy === 'enable' ? 'Checking with the provider…' : 'Enable provider administration'}
            </Button>
          : null}
        </div>
        {!perms.configure ?
          <p className="text-fg-subtle text-xs">
            Changing this needs admin.upstream.configure and edit rights on the credential.
          </p>
        : null}
      </div>
    </Panel>
  )
}

const CapabilityRow = ({ cap }: { cap: Capability }) => (
  <li className="flex items-start gap-3 px-4 py-2.5">
    <span className={cap.ok ? 'text-ok mt-0.5 [&_svg]:size-4' : 'text-warn mt-0.5 [&_svg]:size-4'}>
      {cap.ok ?
        <CircleCheckIcon aria-label="Available" />
      : <CircleExclamationIcon aria-label="Missing" />}
    </span>
    <span className="min-w-0 flex-1">
      <span className="text-fg block text-sm">
        {CAPABILITY_LABELS[cap.name] ?? cap.name}
        {!cap.probed ?
          <span className="text-fg-faint ml-2 text-xs">(not probed)</span>
        : null}
      </span>
      {cap.detail ?
        <span className="text-fg-subtle block text-xs break-words">{cap.detail}</span>
      : null}
    </span>
  </li>
)

export default AdminPanel
