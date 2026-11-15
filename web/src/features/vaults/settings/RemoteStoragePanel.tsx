'use client'

import React, { useEffect, useId, useRef, useState } from 'react'
import { api } from '@/lib/session'
import { invalidate, useWs } from '@/lib/query'
import { useCan } from '@/lib/permissions'
import { isWsError } from '@/lib/ws/errors'
import { DASH, formatBytes, formatDateTime, formatDuration, formatInt } from '@/lib/format'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Checkbox } from '@/components/ui/Choice'
import { confirm } from '@/components/ui/Confirm'
import { Field, Input, Label, Select } from '@/components/ui/Field'
import { DefinitionList, Panel } from '@/components/ui/Panel'
import { Meter } from '@/components/ui/Stat'
import { InlineError } from '@/components/ui/State'
import { Spinner } from '@/components/ui/Spinner'
import { notify } from '@/components/ui/Toast'
import { useCredentials, VAULT_EDIT } from '@/features/vaults/hooks'
import { storageTierOptions } from '@/features/vaults/fields'
import type { VaultDetail } from '@/features/vaults/model'
import {
  accessNotice,
  activeOperation,
  canAbort,
  isRunning,
  lastError,
  phaseLabel,
  progressRatio,
  type VaultRemoteStatus,
} from '@/models/vaultRemote'

// Remote storage of one vault (design/storage/attach-remote.md): attach a bucket to a local vault, follow it, abort
// it, and detach the bucket from an S3 vault again. Everything runs in the daemon's background service; this panel
// starts it (with the keys step-up the client handles), polls vault.remote.status every 3 s while something runs, and
// renders what the status says. Unknown values stay "—".
const refreshAll = () => invalidate('vault.remote.status', 'storage.vault.get', 'storage.vault.list', 'stats.system.storage')

const RemoteStoragePanel = ({ vault }: { vault: VaultDetail }) => {
  const status = useWs(
    'vault.remote.status',
    { vault_id: vault.id },
    {
      select: data => ((data.vaults ?? [])[0] ?? null) as VaultRemoteStatus | null,
      refetchInterval: query => (isRunning(((query.state.data?.vaults ?? [])[0] ?? null) as VaultRemoteStatus | null) ? 3_000 : false),
      retry: false,
    },
  )

  // When an operation ends (the vault switched, or it stopped), the vault itself changed: refresh it everywhere.
  const running = isRunning(status.data)
  const wasRunning = useRef(running)
  useEffect(() => {
    if (wasRunning.current && !running) void invalidate('storage.vault.get', 'storage.vault.list', 'stats.system.storage')
    wasRunning.current = running
  }, [running])

  if (status.error && isWsError(status.error, 'denied')) return null
  return (
    <Panel
      id="remote-storage"
      title="Remote storage"
      description={
        vault.type === 'local' ?
          'Upload this vault to an S3 or R2 bucket and switch it over in place, encrypted, without taking it offline.'
        : 'Where this vault keeps its encrypted objects. Detaching makes it a local vault again with a full copy on this server.'
      }
      actions={status.data ? <OperationBadge status={status.data} /> : null}>
      {status.isPending ?
        <div className="flex justify-center py-6">
          <Spinner className="size-5" label="Loading" />
        </div>
      : status.error ?
        <p className="text-sm text-fg-subtle">Remote storage status is unavailable from this server.</p>
      : <Body vault={vault} status={status.data ?? null} />}
    </Panel>
  )
}

const OperationBadge = ({ status }: { status: VaultRemoteStatus }) => {
  const op = activeOperation(status)
  if (!op) return null
  const state = op === 'detach' ? status.detach?.state : status.attach?.state
  const failed = state === 'failed'
  return (
    <Badge tone={failed ? 'danger' : 'info'} dot pulse={!failed}>
      {op === 'detach' ? 'Detaching' : 'Attaching'} · {failed ? 'stopped' : phaseLabel(state).toLowerCase()}
    </Badge>
  )
}

const Body = ({ vault, status }: { vault: VaultDetail; status: VaultRemoteStatus | null }) => {
  const op = activeOperation(status)
  const notice = accessNotice(status?.access)
  const access = notice ?
      <div role="status" data-testid="remote-access-notice" className="rounded-control border border-warn-line bg-warn-soft px-3 py-2 text-sm text-warn">
        {notice}
      </div>
    : null
  if (op && status)
    return (
      <div className="space-y-4">
        {access}
        <Progress vault={vault} status={status} op={op} />
      </div>
    )
  return (
    <div className="space-y-4">
      {access}
      <LastOutcome status={status} />
      {vault.type === 'local' ? <AttachForm vault={vault} /> : <DetachSection vault={vault} />}
    </div>
  )
}

// What the last finished operation did, in one line.
const LastOutcome = ({ status }: { status: VaultRemoteStatus | null }) => {
  const detach = status?.detach
  const attach = status?.attach
  if (detach?.state === 'done')
    return (
      <p className="text-sm text-fg-subtle">
        Detached {formatDateTime(detach.done_at)}. Bucket <span className="font-mono text-xs">{detach.bucket}</span> was left as
        it was.
      </p>
    )
  if (detach?.state === 'aborted')
    return <p className="text-sm text-fg-subtle">A detach was aborted {formatDateTime(detach.aborted_at)}; the vault kept its bucket.</p>
  if (attach?.state === 'done') return <p className="text-sm text-fg-subtle">Attached {formatDateTime(attach.done_at)}.</p>
  if (attach?.state === 'aborted')
    return (
      <p className="text-sm text-fg-subtle">
        An attach was aborted {formatDateTime(attach.aborted_at)}; what it uploaded was deleted from the bucket.
      </p>
    )
  return null
}

const Progress = ({ vault, status, op }: { vault: VaultDetail; status: VaultRemoteStatus; op: 'attach' | 'detach' }) => {
  const canEdit = useCan(VAULT_EDIT)
  const [busy, setBusy] = useState<null | 'abort' | 'resume'>(null)
  const [error, setError] = useState<unknown>(null)
  const p = status.progress
  const ratio = progressRatio(p)
  const state = op === 'detach' ? status.detach!.state : status.attach!.state
  const failed = state === 'failed'
  const abortAsked = (op === 'detach' ? status.detach?.abort_requested_at : status.attach?.abort_requested_at) !== null
  const bucket = op === 'detach' ? status.detach?.bucket : status.attach?.bucket
  const error_ = lastError(status)

  const run = async (kind: NonNullable<typeof busy>, fn: () => Promise<unknown>, done: string) => {
    setBusy(kind)
    setError(null)
    try {
      await fn()
      await refreshAll()
      notify.success(done, vault.name)
    } catch (e) {
      setError(e)
    } finally {
      setBusy(null)
    }
  }

  const abort = async () => {
    const ok = await confirm({
      title: op === 'detach' ? 'Abort the detach?' : 'Abort the attach?',
      description:
        op === 'detach' ?
          'The vault stays an S3 vault and keeps syncing with its bucket. Files fetched so far stay on this server.'
        : 'Everything the attach uploaded is deleted from the bucket; nothing else in it is touched. The vault stays local.',
      confirmLabel: 'Abort',
      tone: 'danger',
      typeToConfirm: vault.name,
    })
    if (ok)
      void run('abort', () => api.send('vault.remote.abort', { vault_id: vault.id, confirm: vault.name }), 'Abort requested')
  }

  const resume = () =>
    run(
      'resume',
      () =>
        op === 'detach' ?
          api.send('vault.remote.detach', { vault_id: vault.id, confirm: vault.name })
        : api.send('vault.remote.attach', {
            vault_id: vault.id,
            api_key_id: status.attach!.api_key_id ?? 0,
            bucket: status.attach!.bucket,
            storage_tier: status.attach!.storage_tier,
            accept_unpriced: status.attach!.accept_unpriced,
          }),
      op === 'detach' ? 'Detach resumed' : 'Attach resumed',
    )

  const files = p ? `${formatInt(p.files_done)} of ${formatInt(p.files_total)}` : DASH
  const bytes = p ? `${formatBytes(p.bytes_done)} of ${formatBytes(p.bytes_total)}` : DASH
  const estimate = op === 'detach' ? status.detach?.estimate : null
  return (
    <div className="space-y-4" data-testid="remote-progress">
      <div className="space-y-2">
        <div className="flex flex-wrap items-baseline justify-between gap-2 text-sm">
          <span className="text-fg">{failed ? 'Stopped before the switch' : phaseLabel(p?.phase ?? state)}</span>
          <span className="tabular text-fg-subtle">{ratio === null ? DASH : `${Math.round(ratio * 100)} %`}</span>
        </div>
        <Meter ratio={ratio} tone={failed ? 'danger' : 'accent'} label={op === 'detach' ? 'Detach progress' : 'Attach progress'} />
      </div>
      <DefinitionList
        items={[
          ['Bucket', <span key="b" className="font-mono text-xs">{bucket || DASH}</span>],
          [op === 'detach' ? 'Files held here' : 'Files uploaded', <span key="f" className="tabular">{files}</span>],
          ['Bytes', <span key="by" className="tabular">{bytes}</span>],
          [
            'Rate',
            <span key="r" className="tabular">
              {p?.bytes_per_second ? `${formatBytes(p.bytes_per_second)}/s` : DASH}
              {p?.eta_seconds ? ` · about ${formatDuration(p.eta_seconds)} left` : ''}
            </span>,
          ],
          ...(op === 'detach' && status.detach ?
            [
              [
                'Fetched from the bucket',
                <span key="h" className="tabular">
                  {formatInt(status.detach.items.files_fetched)} file(s); {formatInt(status.detach.items.envelopes_copied)}{' '}
                  recovery envelope(s) copied to this server
                </span>,
              ] as [React.ReactNode, React.ReactNode],
            ]
          : []),
          ...(estimate && (estimate.history_in_bucket_only || estimate.trash_without_local_copy) ?
            [
              [
                'Stays only in the bucket',
                <span key="s" className="tabular">
                  {formatInt(estimate.history_in_bucket_only)} earlier version(s),{' '}
                  {formatInt(estimate.trash_without_local_copy)} trashed file(s) without a local copy
                </span>,
              ] as [React.ReactNode, React.ReactNode],
            ]
          : []),
        ]}
      />
      {error_ ?
        <div role="alert" className="rounded-control border border-danger-line bg-danger-soft px-3 py-2 text-sm text-danger">
          {error_}
        </div>
      : null}
      <p className="text-xs text-fg-subtle">
        {failed ?
          op === 'detach' ?
            'The vault is still an S3 vault and syncs as before. Resume to pick up where it stopped, or abort it.'
          : 'The vault is still local and untouched. Resume with the same bucket, or abort to delete what was uploaded.'
        : abortAsked ?
          'Abort requested: the server is ending it.'
        : op === 'detach' ?
          'The vault stays in use and keeps syncing until every file is held and verified here; then it switches in one step.'
        : 'The vault stays local and in use until every upload is verified; then it switches in one step.'}
      </p>
      <InlineError error={error} />
      {canEdit ?
        <div className="flex flex-wrap justify-end gap-2">
          {canAbort(status) ?
            <Button variant="danger" loading={busy === 'abort'} disabled={busy !== null} onClick={() => void abort()}>
              Abort…
            </Button>
          : null}
          {failed && !abortAsked ?
            <Button variant="primary" loading={busy === 'resume'} disabled={busy !== null} onClick={() => void resume()}>
              Resume
            </Button>
          : null}
        </div>
      : null}
    </div>
  )
}

const AttachForm = ({ vault }: { vault: VaultDetail }) => {
  const ids = useId()
  const canEdit = useCan(VAULT_EDIT)
  const credentials = useCredentials(canEdit)
  const [apiKeyId, setApiKeyId] = useState('')
  const [bucket, setBucket] = useState('')
  const [tier, setTier] = useState('')
  const [acceptUnpriced, setAcceptUnpriced] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const credential = credentials.data?.find(c => String(c.api_key_id) === apiKeyId)
  const tiers = storageTierOptions(credential?.provider)

  if (!canEdit) return <p className="text-sm text-fg-subtle">This vault keeps its data on this server only.</p>

  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    setError(null)
    if (!apiKeyId || !bucket.trim()) {
      setError(new Error('Choose a credential and enter the bucket name.'))
      return
    }
    const ok = await confirm({
      title: `Attach “${bucket.trim()}” to ${vault.name}?`,
      description:
        'Every file is uploaded to the bucket as an encrypted object under an opaque name, verified, and then the vault switches to the bucket in one step. The bucket must be empty. Until then the vault stays local and in use; you can abort at any time before the switch.',
      confirmLabel: 'Attach',
      tone: 'primary',
    })
    if (!ok) return
    setBusy(true)
    try {
      await api.send('vault.remote.attach', {
        vault_id: vault.id,
        api_key_id: Number(apiKeyId),
        bucket: bucket.trim(),
        storage_tier: tier || null,
        accept_unpriced: acceptUnpriced,
      })
      await refreshAll()
      notify.success('Attach started', vault.name)
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} noValidate className="space-y-4" data-testid="remote-attach-form">
      <p className="text-sm text-fg-subtle">
        Needs an empty bucket no other vault uses, recovery material that doesn’t depend on this server (a recovery recipient,
        or an export of the vault’s key) and no content in a legacy format. The cost is estimated first.
      </p>
      <fieldset disabled={busy} className="grid gap-4 sm:grid-cols-2">
        <Field label="Provider credential" htmlFor={`${ids}-key`} required>
          <Select id={`${ids}-key`} value={apiKeyId} onChange={e => setApiKeyId(e.target.value)}>
            <option value="">Choose a credential</option>
            {(credentials.data ?? []).map(c => (
              <option key={c.api_key_id} value={c.api_key_id}>
                {c.name}
                {c.provider ? ` · ${c.provider}` : ''}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Bucket" htmlFor={`${ids}-bucket`} required hint="An empty bucket.">
          <Input id={`${ids}-bucket`} className="font-mono" spellCheck={false} value={bucket} onChange={e => setBucket(e.target.value)} />
        </Field>
        <Field label="Storage tier" htmlFor={`${ids}-tier`}>
          {tiers ?
            <Select id={`${ids}-tier`} value={tier} onChange={e => setTier(e.target.value)}>
              {tiers.map(t => (
                <option key={t.value || 'default'} value={t.value}>
                  {t.label}
                </option>
              ))}
            </Select>
          : <Input id={`${ids}-tier`} placeholder="Provider default" value={tier} onChange={e => setTier(e.target.value)} />}
        </Field>
        <div className="flex items-center gap-2 self-end pb-2">
          <Checkbox id={`${ids}-unpriced`} checked={acceptUnpriced} onCheckedChange={setAcceptUnpriced} />
          <Label htmlFor={`${ids}-unpriced`}>Start even if the cost can’t be priced</Label>
        </div>
      </fieldset>
      <InlineError error={error} />
      <div className="flex justify-end">
        <Button type="submit" variant="primary" loading={busy}>
          Attach bucket…
        </Button>
      </div>
    </form>
  )
}

const DetachSection = ({ vault }: { vault: VaultDetail }) => {
  const canEdit = useCan(VAULT_EDIT)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  if (!canEdit) return null

  const detach = async () => {
    const ok = await confirm({
      title: `Detach the bucket from ${vault.name}?`,
      description:
        'Every file without a copy on this server is fetched from the bucket and every copy is verified; then the vault becomes a local vault in one step. The bucket and every object in it are left as they are. Earlier versions only the bucket holds stay in the bucket.',
      confirmLabel: 'Detach',
      tone: 'danger',
      typeToConfirm: vault.name,
    })
    if (!ok) return
    setBusy(true)
    setError(null)
    try {
      await api.send('vault.remote.detach', { vault_id: vault.id, confirm: vault.name })
      await refreshAll()
      notify.success('Detach started', vault.name)
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-3">
      <InlineError error={error} />
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="min-w-0 text-sm text-fg-subtle">
          Keep a full copy on this server and stop using <span className="font-mono text-xs">{vault.bucket || 'the bucket'}</span>.
        </p>
        <Button variant="ghost" loading={busy} onClick={() => void detach()} data-testid="remote-detach">
          Detach bucket…
        </Button>
      </div>
    </div>
  )
}

export default RemoteStoragePanel
