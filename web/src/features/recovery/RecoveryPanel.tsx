'use client'

import React, { useEffect, useId, useMemo, useState } from 'react'
import dynamic from 'next/dynamic'
import { Panel, DefinitionList } from '@/components/ui/Panel'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Switch } from '@/components/ui/Choice'
import { confirm } from '@/components/ui/Confirm'
import { Field, Input, Label, Select } from '@/components/ui/Field'
import { InlineError } from '@/components/ui/State'
import { Meter } from '@/components/ui/Stat'
import { Spinner } from '@/components/ui/Spinner'
import { notify } from '@/components/ui/Toast'
import { ArrowsRotateIcon, TriangleExclamationIcon } from '@/components/ui/icons'
import { api } from '@/lib/session'
import { queryClient, useWs, wsKey } from '@/lib/query'
import { DASH, formatBytes, formatInt, formatRelative } from '@/lib/format'
import { isWsError } from '@/lib/ws/errors'
import { cn } from '@/util/cn'
import { useUpstreamPerms } from '@/features/credentials/upstream/hooks'
import type { VaultDetail } from '@/features/vaults/model'
import { RECOVERY_CODES, type RecoveryMode, type RecoveryStatus } from '@/models/recovery'
import {
  bytesToGib,
  BulletList,
  gibToBytes,
  moneyText,
  needsCode,
  Notice,
  RETENTION_CHOICES,
  SubHeading,
  timeText,
} from '@/features/recovery/shared'
import { refreshRecovery, sendRecoveryUpdate } from '@/features/recovery/update'

const DisclosureDialog = dynamic(() => import('@/features/recovery/DisclosureDialog'), { ssr: false })

const MODE_LABEL: Record<RecoveryMode, string> = {
  off: 'Off',
  local_snapshots: 'Local snapshots',
  provider_versioning: 'Provider versioning',
}

// The retention the bucket has now, as one of the choices (or its own "<n>d" when it is something else).
const currentRetention = (s: RecoveryStatus) =>
  s.provider.retention_mode === 'indefinite' ? 'indefinite'
  : s.provider.retention_mode === 'days' && s.provider.retention_days ? `${s.provider.retention_days}d`
  : ''

// Vault settings → Recovery (lazy). Everything shown is vault.recovery.status; every change goes through
// vault.recovery.update, which the daemon authorizes (vault sync settings; provider versioning also needs
// admin.upstream.configure).
const RecoveryPanel = ({ vault }: { vault: VaultDetail }) => {
  const status = useWs('vault.recovery.status', { vault_id: vault.id }, { retry: false, select: d => d.status })
  const [checking, setChecking] = useState(false)
  const isS3 = vault.type === 's3'

  const recheck = async () => {
    setChecking(true)
    try {
      const data = await api.send('vault.recovery.status', { vault_id: vault.id, refresh_provider: true })
      queryClient.setQueryData(wsKey('vault.recovery.status', { vault_id: vault.id }), data)
    } catch (e) {
      notify.error(e)
    } finally {
      setChecking(false)
    }
  }

  return (
    <Panel
      id="recovery"
      title="Recovery"
      description="Snapshots and earlier versions of files, kept on this server or by the bucket’s provider."
      actions={
        isS3 && status.data ?
          <Button size="sm" variant="ghost" loading={checking} onClick={() => void recheck()}>
            {checking ? null : <ArrowsRotateIcon aria-hidden />}
            Re-check bucket
          </Button>
        : null
      }>
      {status.isPending ?
        <div className="flex justify-center py-6">
          <Spinner className="size-5" label="Loading" />
        </div>
      : status.error || !status.data ?
        <p className="text-fg-subtle text-sm" data-testid="recovery-unavailable">
          {isWsError(status.error, 'denied') ?
            'Your role can’t view recovery settings for this vault.'
          : `Recovery settings are unavailable from this server${status.error instanceof Error ? `: ${status.error.message}` : '.'}`
          }
        </p>
      : <RecoveryBody vault={vault} status={status.data} />}
    </Panel>
  )
}

const RecoveryBody = ({ vault, status }: { vault: VaultDetail; status: RecoveryStatus }) => {
  const isS3 = vault.type === 's3'
  return (
    <div className="space-y-6" data-testid="recovery-panel">
      {status.warnings.length ?
        <Notice tone="warn" icon={TriangleExclamationIcon} role="note">
          <BulletList items={status.warnings} />
        </Notice>
      : null}
      <ModeSection vault={vault} status={status} />
      {isS3 ?
        <ProviderSection status={status} />
      : null}
      <SnapshotSection vault={vault} status={status} />
      <LocalVersioningSection vault={vault} status={status} />
      {isS3 ?
        <BacklogSection status={status} />
      : null}
      <section>
        <SubHeading>Retained key versions</SubHeading>
        <p className="text-sm">
          {status.retained_key_versions.length ?
            <span className="tabular">{status.retained_key_versions.map(v => `v${v}`).join(', ')}</span>
          : <span className="text-fg-subtle">None beyond the current key.</span>}
        </p>
        <p className="text-fg-subtle mt-1 text-xs">
          Earlier encryption key versions are kept while snapshots or versions sealed with them exist, and are included
          in key exports.
        </p>
      </section>
      {isS3 ?
        <AlertSection vault={vault} status={status} />
      : null}
    </div>
  )
}

const ModeSection = ({ vault, status }: { vault: VaultDetail; status: RecoveryStatus }) => {
  const name = useId()
  const perms = useUpstreamPerms()
  const isS3 = vault.type === 's3'
  const [choice, setChoice] = useState<RecoveryMode>(status.mode)
  const [retention, setRetention] = useState(currentRetention(status))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const [disclose, setDisclose] = useState<string | null>(null)

  // A refetch (after a save, a re-check or another admin's change) resets an untouched choice.
  const serverRetention = currentRetention(status)
  useEffect(() => {
    setChoice(status.mode)
    setRetention(serverRetention)
  }, [status.mode, serverRetention])

  const provider = status.provider
  const providerDisabledReason =
    !provider.supported ? provider.unsupported_reason || 'This provider doesn’t support versioning.'
    : !perms.configure ? 'Needs the admin.upstream.configure permission.'
    : null

  const retentionOptions = useMemo(() => {
    const opts: { value: string; label: string }[] = RETENTION_CHOICES.map(c => ({ value: c.value, label: c.label }))
    if (serverRetention && !opts.some(o => o.value === serverRetention))
      opts.push({ value: serverRetention, label: `${serverRetention.replace(/d$/, '')} days (current)` })
    return opts
  }, [serverRetention])

  const providerActive = status.mode === 'provider_versioning'
  const dirty = choice !== status.mode || (choice === 'provider_versioning' && retention !== serverRetention)
  const needsRetention = choice === 'provider_versioning' && !retention

  const apply = async () => {
    setError(null)
    if (choice === 'provider_versioning' && !providerActive) {
      setDisclose(retention)
      return
    }
    if (status.mode === 'provider_versioning' && choice !== 'provider_versioning' && provider.status === 'enabled') {
      const ok = await confirm({
        title: `Switch to ${MODE_LABEL[choice]}?`,
        description:
          'This changes Vaulthalla’s preference only. The bucket stays versioned and keeps the versions it has; use “Suspend versioning” to stop new versions.',
        confirmLabel: 'Switch',
        tone: 'primary',
      })
      if (!ok) return
    }
    setBusy(true)
    try {
      await sendRecoveryUpdate(
        vault.id,
        choice === 'provider_versioning' ? { provider_retention: retention } : { mode: choice },
      )
      notify.success(choice === 'provider_versioning' ? 'Retention updated' : 'Recovery mode saved')
    } catch (e) {
      // A retention change can also need a fresh cost disclosure.
      if (needsCode(e, RECOVERY_CODES.versioningDisclosure)) setDisclose(retention)
      else setError(e)
    } finally {
      setBusy(false)
    }
  }

  const option = (value: RecoveryMode, title: string, hint: string, disabledReason?: string | null) => (
    <label
      className={cn(
        'rounded-control flex items-start gap-3 border px-3 py-2.5 transition-colors',
        disabledReason ? 'cursor-not-allowed opacity-60' : 'cursor-pointer',
        choice === value ? 'border-accent-line bg-accent-soft' : 'border-line hover:border-line-strong',
      )}>
      <input
        type="radio"
        name={name}
        className="mt-1"
        checked={choice === value}
        disabled={Boolean(disabledReason)}
        onChange={() => setChoice(value)}
        data-testid={`recovery-mode-${value}`}
      />
      <span className="min-w-0">
        <span className="text-fg block text-sm font-medium">
          {title}
          {status.mode === value ?
            <Badge tone="accent" className="ml-2 align-middle">
              Current
            </Badge>
          : null}
        </span>
        <span className="text-fg-subtle block text-xs">{hint}</span>
        {disabledReason ?
          <span className="text-warn mt-0.5 block text-xs">{disabledReason}</span>
        : null}
      </span>
    </label>
  )

  return (
    <section>
      <SubHeading>Mode</SubHeading>
      <fieldset className="space-y-2" disabled={busy}>
        <legend className="sr-only">Recovery mode</legend>
        {option('off', 'Off', 'No new snapshots. Existing snapshots and versions stay recoverable.')}
        {option(
          'local_snapshots',
          'Local snapshots',
          'People can create named snapshots of files and folders. They are stored encrypted on this server and count against the vault quota.',
        )}
        {isS3 ?
          option(
            'provider_versioning',
            'Provider versioning',
            'The bucket keeps every version of every object. The provider bills for the versions it keeps.',
            providerDisabledReason,
          )
        : null}
      </fieldset>

      {choice === 'provider_versioning' && !providerDisabledReason ?
        <div className="mt-3 max-w-xs">
          <Field
            label="Keep replaced versions for"
            htmlFor={`${name}-retention`}
            required
            hint="Older versions are permanently deleted by the provider. Choose one; there is no default.">
            <Select
              id={`${name}-retention`}
              value={retention}
              onChange={e => setRetention(e.target.value)}
              data-testid="recovery-retention">
              <option value="" disabled>
                Choose retention…
              </option>
              {retentionOptions.map(o => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </Select>
          </Field>
        </div>
      : null}

      <InlineError error={error} className="mt-3" />
      <div className="mt-3 flex justify-end">
        <Button
          variant="primary"
          disabled={!dirty || needsRetention}
          loading={busy}
          onClick={() => void apply()}
          data-testid="recovery-mode-apply">
          {choice === 'provider_versioning' && !providerActive ? 'Review costs and enable…' : 'Save'}
        </Button>
      </div>

      {disclose ?
        <DisclosureDialog vaultId={vault.id} retention={disclose} onClose={() => setDisclose(null)} />
      : null}
    </section>
  )
}

const tri = (value: boolean | null) =>
  value === null ? 'Unknown'
  : value ? 'On'
  : 'Off'

const ProviderSection = ({ status }: { status: RecoveryStatus }) => {
  const p = status.provider
  const perms = useUpstreamPerms()
  const [busy, setBusy] = useState(false)
  const propagating = p.status === 'enabled' && !p.settled
  const outside = p.status === 'enabled' && status.mode !== 'provider_versioning'

  const suspend = async () => {
    const ok = await confirm({
      title: 'Suspend versioning on this bucket?',
      description:
        'New writes stop creating versions. Nothing is deleted: the versions the bucket already holds stay recoverable until retention removes them. On AWS, versioning can only be suspended, never turned off.',
      confirmLabel: 'Suspend versioning',
      tone: 'danger',
    })
    if (!ok) return
    setBusy(true)
    try {
      await api.send('vault.recovery.suspend', { vault_id: status.vault_id, confirm: true })
      await refreshRecovery()
      notify.success('Versioning suspended')
    } catch (e) {
      notify.error(e)
    } finally {
      setBusy(false)
    }
  }

  return (
    <section>
      <SubHeading>Provider versioning</SubHeading>
      {!p.supported ?
        <p className="text-fg-subtle mb-3 text-sm">
          {p.unsupported_reason || 'This provider doesn’t support versioning.'}
        </p>
      : null}
      <DefinitionList
        items={[
          ['Provider', p.provider ?? DASH],
          [
            'Bucket',
            <span key="b" className="font-mono text-xs">
              {p.bucket ?? DASH}
            </span>,
          ],
          ['Region', p.region ?? DASH],
          ['Storage class', p.storage_class ?? DASH],
          ['Bucket management', p.bucket_state],
          [
            'Versioning',
            <span key="v" className="flex flex-wrap items-center gap-2">
              <Badge
                tone={
                  p.status === 'enabled' ? 'accent'
                  : p.status === 'suspended' ?
                    'warn'
                  : 'neutral'
                }>
                {p.status}
              </Badge>
              {propagating ?
                <span className="text-fg-subtle text-xs">
                  Propagating until {timeText(p.settles_at)} ({formatRelative(p.settles_at)})
                </span>
              : null}
            </span>,
          ],
          [
            'Enabled by Vaulthalla',
            p.enabled_by_vaulthalla ? `Yes${p.enabled_at ? `, ${timeText(p.enabled_at)}` : ''}` : 'No',
          ],
          ['Object lock', tri(p.object_lock)],
          ['MFA delete', tri(p.mfa_delete)],
          [
            'Retention',
            p.retention_mode === 'indefinite' ? 'Indefinite'
            : p.retention_mode === 'days' && p.retention_days ? `${p.retention_days} days`
            : 'Not set',
          ],
          [
            'Effective expiry of replaced versions',
            p.effective_noncurrent_days !== null ? `${p.effective_noncurrent_days} days` : 'None (kept until deleted)',
          ],
          ...(p.foreign_noncurrent_rules.length ?
            ([
              [
                'Lifecycle rules from other applications',
                <BulletList key="f" items={p.foreign_noncurrent_rules} className="text-xs" />,
              ],
            ] as [React.ReactNode, React.ReactNode][])
          : []),
          ['Last checked', timeText(p.checked_at)],
        ]}
      />
      {outside ?
        <Notice
          tone="warn"
          icon={TriangleExclamationIcon}
          className="mt-3"
          role="note"
          testId="recovery-outside-preference">
          The bucket is versioned outside Vaulthalla’s preference: the provider keeps (and bills for) versions even
          though this vault’s mode is {MODE_LABEL[status.mode].toLowerCase()}. Suspend versioning to stop new versions.
        </Notice>
      : null}
      {p.warnings.length ?
        <Notice tone="warn" className="mt-3" role="note">
          <BulletList items={p.warnings} />
        </Notice>
      : null}
      {p.status === 'enabled' && perms.configure ?
        <div className="mt-3 flex justify-end">
          <Button variant="danger" size="sm" loading={busy} onClick={() => void suspend()}>
            Suspend versioning
          </Button>
        </div>
      : null}
    </section>
  )
}

const SnapshotSection = ({ vault, status }: { vault: VaultDetail; status: RecoveryStatus }) => {
  const id = useId()
  const initial = bytesToGib(status.snapshot_quota_bytes)
  const [quota, setQuota] = useState(initial)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  useEffect(() => setQuota(initial), [initial])
  const limit = status.snapshot_quota_bytes
  const save = async () => {
    setBusy(true)
    setError(null)
    try {
      await sendRecoveryUpdate(vault.id, { snapshot_quota_bytes: gibToBytes(quota) })
      notify.success('Snapshot quota saved')
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }
  return (
    <section>
      <SubHeading>Snapshots</SubHeading>
      <p className="tabular text-sm">
        {formatInt(status.snapshots.count)} snapshot{status.snapshots.count === 1 ? '' : 's'} ·{' '}
        {formatBytes(status.snapshots.stored_bytes)} stored
        {limit ? ` of ${formatBytes(limit)}` : ' (no snapshot quota)'}
      </p>
      {limit ?
        <Meter
          className="mt-2"
          label="Snapshot quota used"
          ratio={status.snapshots.stored_bytes / limit}
          tone={status.snapshots.stored_bytes / limit > 0.9 ? 'warn' : 'accent'}
        />
      : null}
      <div className="mt-3 flex flex-wrap items-end gap-2">
        <Field
          label="Snapshot quota (GiB)"
          htmlFor={`${id}-q`}
          hint="Empty: no snapshot quota (the vault quota still applies).">
          <Input
            id={`${id}-q`}
            inputMode="decimal"
            className="w-40"
            value={quota}
            onChange={e => setQuota(e.target.value)}
          />
        </Field>
        <Button size="sm" disabled={quota === initial} loading={busy} onClick={() => void save()} className="mb-6">
          Save
        </Button>
      </div>
      <InlineError error={error} />
    </section>
  )
}

const numOrNull = (value: string) => {
  const n = Number(value.trim())
  return value.trim() && Number.isInteger(n) && n > 0 ? n : null
}

const LocalVersioningSection = ({ vault, status }: { vault: VaultDetail; status: RecoveryStatus }) => {
  const id = useId()
  const lv = status.local_versioning
  const init = useMemo(
    () => ({
      enabled: lv.enabled,
      keep_last: lv.keep_last ? String(lv.keep_last) : '',
      max_age_days: lv.max_age_days ? String(lv.max_age_days) : '',
      quota: bytesToGib(lv.quota_bytes),
    }),
    [lv.enabled, lv.keep_last, lv.max_age_days, lv.quota_bytes],
  )
  const [form, setForm] = useState(init)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  useEffect(() => setForm(init), [init])

  const dirty =
    form.enabled !== init.enabled
    || form.keep_last !== init.keep_last
    || form.max_age_days !== init.max_age_days
    || form.quota !== init.quota

  // A patch: only what changed. Empty clears a limit (null = no limit).
  const save = async () => {
    const patch: NonNullable<Parameters<typeof sendRecoveryUpdate>[1]['local_versioning']> = {}
    if (form.enabled !== init.enabled) patch.enabled = form.enabled
    if (form.keep_last !== init.keep_last) patch.keep_last = numOrNull(form.keep_last)
    if (form.max_age_days !== init.max_age_days) patch.max_age_days = numOrNull(form.max_age_days)
    if (form.quota !== init.quota) patch.quota_bytes = gibToBytes(form.quota) || null
    setBusy(true)
    setError(null)
    try {
      await sendRecoveryUpdate(vault.id, { local_versioning: patch })
      notify.success('Local versioning saved')
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }

  const invalid = (v: string) => Boolean(v.trim()) && numOrNull(v) === null

  return (
    <section>
      <SubHeading>Local versioning</SubHeading>
      <div className="rounded-control border-line bg-surface-1 flex items-start justify-between gap-4 border px-3 py-2.5">
        <div className="min-w-0">
          <Label htmlFor={`${id}-on`} className="text-fg">
            Keep earlier versions of files on this server
          </Label>
          <p className="text-fg-subtle mt-0.5 text-xs">
            Each time a file’s contents change (overwrite, truncate, delete, sync download, restore), the previous
            encrypted contents are kept. Renames don’t create versions.
          </p>
        </div>
        <Switch
          id={`${id}-on`}
          checked={form.enabled}
          onCheckedChange={v => setForm(f => ({ ...f, enabled: v }))}
          data-testid="recovery-local-versioning"
        />
      </div>
      <div className="mt-3 grid gap-3 sm:grid-cols-3">
        <Field
          label="Keep the newest"
          htmlFor={`${id}-k`}
          hint="Versions per file. Empty: no limit."
          error={invalid(form.keep_last) ? 'A whole number' : undefined}>
          <Input
            id={`${id}-k`}
            inputMode="numeric"
            value={form.keep_last}
            onChange={e => setForm(f => ({ ...f, keep_last: e.target.value }))}
          />
        </Field>
        <Field
          label="Maximum age (days)"
          htmlFor={`${id}-a`}
          hint="Empty: no limit."
          error={invalid(form.max_age_days) ? 'A whole number' : undefined}>
          <Input
            id={`${id}-a`}
            inputMode="numeric"
            value={form.max_age_days}
            onChange={e => setForm(f => ({ ...f, max_age_days: e.target.value }))}
          />
        </Field>
        <Field label="Quota (GiB)" htmlFor={`${id}-q`} hint="Oldest removed first. Empty: no limit.">
          <Input
            id={`${id}-q`}
            inputMode="decimal"
            value={form.quota}
            onChange={e => setForm(f => ({ ...f, quota: e.target.value }))}
          />
        </Field>
      </div>
      <p className="text-fg-subtle tabular mt-2 text-xs">
        {formatInt(status.versions.count)} version{status.versions.count === 1 ? '' : 's'} kept ·{' '}
        {formatBytes(status.versions.stored_bytes)} stored
        {lv.quota_bytes ? ` of ${formatBytes(lv.quota_bytes)}` : ''}
      </p>
      {lv.quota_bytes ?
        <Meter className="mt-2" label="Version quota used" ratio={status.versions.stored_bytes / lv.quota_bytes} />
      : null}
      <InlineError error={error} className="mt-3" />
      <div className="mt-3 flex justify-end gap-2">
        <Button variant="ghost" size="sm" disabled={!dirty || busy} onClick={() => setForm(init)}>
          Discard
        </Button>
        <Button
          size="sm"
          variant="primary"
          disabled={!dirty || invalid(form.keep_last) || invalid(form.max_age_days)}
          loading={busy}
          onClick={() => void save()}>
          Save local versioning
        </Button>
      </div>
    </section>
  )
}

const BacklogSection = ({ status }: { status: RecoveryStatus }) => {
  const b = status.backlog
  return (
    <section>
      <SubHeading>Upload backlog</SubHeading>
      <p className="text-fg-subtle mb-2 text-xs">
        Versions kept locally while the provider was unreachable, waiting to be replayed to the bucket in order.
      </p>
      <DefinitionList
        items={[
          [
            'Pending',
            `${formatInt(b.pending_versions)} version${b.pending_versions === 1 ? '' : 's'} (${formatBytes(b.pending_bytes)})`,
          ],
          [
            'Oldest pending',
            b.oldest_pending_at ? `${timeText(b.oldest_pending_at)} (${formatRelative(b.oldest_pending_at)})` : DASH,
          ],
          [
            'Failing',
            <span key="f" className={b.failing ? 'text-danger' : undefined}>
              {formatInt(b.failing)}
            </span>,
          ],
          ['Last error', b.last_error ?? DASH],
        ]}
      />
    </section>
  )
}

const AlertSection = ({ vault, status }: { vault: VaultDetail; status: RecoveryStatus }) => {
  const id = useId()
  const initial = status.cost_alert_monthly?.amount ?? ''
  const [value, setValue] = useState(initial)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  useEffect(() => setValue(initial), [initial])
  const valid = !value.trim() || /^\d{1,12}(\.\d{1,8})?$/.test(value.trim())
  const save = async () => {
    setBusy(true)
    setError(null)
    try {
      await sendRecoveryUpdate(vault.id, { cost_alert_monthly: value.trim() })
      notify.success(value.trim() ? 'Cost alert saved' : 'Cost alert cleared')
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }
  return (
    <section>
      <SubHeading>Versioning cost alert</SubHeading>
      <p className="text-fg-subtle mb-2 text-xs">
        Notifies operators when the estimated monthly versioning cost goes over this amount. Alerts never block writes
        or turn versioning off. Current: {moneyText(status.cost_alert_monthly, 'not set')}.
      </p>
      <div className="flex flex-wrap items-end gap-2">
        <Field
          label={`Monthly threshold (${status.cost_alert_monthly?.currency ?? 'catalog currency'})`}
          htmlFor={`${id}-alert`}
          hint="Empty clears it."
          error={valid ? undefined : 'A non-negative amount, e.g. 25.00'}>
          <Input
            id={`${id}-alert`}
            inputMode="decimal"
            className="w-40"
            value={value}
            onChange={e => setValue(e.target.value)}
          />
        </Field>
        <Button
          size="sm"
          disabled={value === initial || !valid}
          loading={busy}
          onClick={() => void save()}
          className="mb-6">
          Save
        </Button>
      </div>
      <InlineError error={error} />
    </section>
  )
}

export default RecoveryPanel
