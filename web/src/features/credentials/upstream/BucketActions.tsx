'use client'

import React, { useEffect, useId, useState } from 'react'
import Link from 'next/link'
import { api } from '@/lib/session'
import { invalidate, useWs } from '@/lib/query'
import { isWsError } from '@/lib/ws/errors'
import { DASH, formatBytes, formatDateTime, formatInt } from '@/lib/format'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Checkbox } from '@/components/ui/Choice'
import { confirm } from '@/components/ui/Confirm'
import { Dialog, DialogContent, SheetContent } from '@/components/ui/Dialog'
import { Field, Input, Textarea } from '@/components/ui/Field'
import { DefinitionList } from '@/components/ui/Panel'
import { InlineError, QueryState } from '@/components/ui/State'
import { notify } from '@/components/ui/Toast'
import {
  bucketStateLabel,
  bucketStateTone,
  isBound,
  useUpstreamPerms,
  withConfirmation,
} from '@/features/credentials/upstream/hooks'
import { AdmissionReportView } from '@/features/credentials/upstream/AdmissionReportView'
import {
  UPSTREAM_CODES,
  type BucketRow,
  type CleanupPlan,
  type CleanupResult,
  type Inspection,
  type LifecyclePatch,
  type LifecycleRule,
  type NotificationRule,
} from '@/models/upstream'

export type BucketActionKind = 'inspect' | 'lifecycle' | 'adopt' | 'protect' | 'unprotect' | 'detach' | 'cleanup'

interface ActionProps {
  apiKeyId: number
  provider: string
  row: BucketRow
  onClose: () => void
}

const refreshInventory = () => invalidate('upstream.bucket.list', 'upstream.bucket.inspect', 'upstream.audit.list')

// One lazy chunk for every bucket action on the inventory page. Each action is a dialog (or the inspect sheet) that
// closes itself; the daemon decides every refusal, which the dialogs show as-is.
const BucketActions = ({ kind, ...props }: ActionProps & { kind: BucketActionKind }) => {
  const [current, setCurrent] = useState(kind)
  useEffect(() => setCurrent(kind), [kind])
  switch (current) {
    case 'inspect':
      return <InspectSheet {...props} onLifecycle={() => setCurrent('lifecycle')} />
    case 'lifecycle':
      return <LifecycleDialog {...props} />
    case 'adopt':
      return <AdoptDialog {...props} />
    case 'protect':
      return <ProtectDialog {...props} />
    case 'unprotect':
      return <UnprotectAction {...props} />
    case 'detach':
      return <DetachAction {...props} />
    case 'cleanup':
      return <CleanupDialog {...props} />
  }
}

export default BucketActions

const BucketTitle = ({ row }: { row: BucketRow }) => (
  <span className="flex min-w-0 items-center gap-2">
    <span className="truncate font-mono">{row.name}</span>
    <Badge tone={bucketStateTone[row.state] ?? 'unknown'}>{bucketStateLabel[row.state] ?? row.state}</Badge>
  </span>
)

// ---- protect / unprotect / detach --------------------------------------------------------------------------------

const ProtectDialog = ({ apiKeyId, row, onClose }: ActionProps) => {
  const ids = useId()
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const bound = isBound(row.vault_id)
  const submit = async () => {
    setBusy(true)
    setError(null)
    try {
      await api.send('upstream.bucket.protect', { api_key_id: apiKeyId, bucket: row.name, reason: reason.trim() })
      await refreshInventory()
      notify.success('Bucket protected', row.name)
      onClose()
    } catch (e) {
      setError(e)
    } finally {
      setBusy(false)
    }
  }
  return (
    <Dialog open onOpenChange={open => !open && onClose()}>
      <DialogContent
        title={
          <span>
            Protect <span className="font-mono">{row.name}</span>?
          </span>
        }
        description="A protected bucket is excluded from everything Vaulthalla does: no probes, inventory, adoption, lifecycle or event changes, sync reads or writes, cleanup, scheduled jobs or retries. Only its name stays visible here."
        footer={
          <>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" onClick={submit} loading={busy} disabled={!reason.trim()}>
              Protect bucket
            </Button>
          </>
        }>
        <div className="space-y-4">
          {bound ?
            <p
              role="alert"
              className="rounded-control border-warn-line bg-warn-soft text-warn border px-3 py-2 text-sm">
              Vault “{row.vault_name || row.vault_id}” uses this bucket. Its sync stops at the next request and stays
              stalled until the bucket is unprotected.
            </p>
          : null}
          <Field label="Reason" htmlFor={`${ids}-reason`} required hint="Recorded with the lock and in the audit log.">
            <Textarea
              id={`${ids}-reason`}
              rows={3}
              value={reason}
              onChange={e => setReason(e.target.value)}
              autoFocus
            />
          </Field>
          <InlineError error={error} />
        </div>
      </DialogContent>
    </Dialog>
  )
}

const useOnce = (fn: () => void) => {
  useEffect(() => {
    fn()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])
}

const UnprotectAction = ({ apiKeyId, row, onClose }: ActionProps) => {
  useOnce(() => {
    void (async () => {
      try {
        const ok = await confirm({
          title: `Unprotect ${row.name}?`,
          description: (
            <>
              {row.protection_reason ?
                <span className="mb-2 block">
                  Protected{row.protected_by ? ` by ${row.protected_by}` : ''}
                  {row.protected_at ? ` on ${formatDateTime(row.protected_at)}` : ''}: “{row.protection_reason}”
                </span>
              : null}
              Unprotecting re-enables every Vaulthalla operation on this bucket, including sync jobs and retries of any
              vault bound to it. Type the bucket name to confirm; the change is audited.
            </>
          ),
          confirmLabel: 'Unprotect',
          tone: 'danger',
          typeToConfirm: row.name,
        })
        if (!ok) return
        // The typed confirmation above is the person's explicit acceptance (UPSTREAM_CODES.unprotect).
        await api.send('upstream.bucket.unprotect', { api_key_id: apiKeyId, bucket: row.name, confirm: true })
        await refreshInventory()
        notify.success('Bucket unprotected', row.name)
      } catch (e) {
        notify.error(e, 'Could not unprotect the bucket')
      } finally {
        onClose()
      }
    })()
  })
  return null
}

const DetachAction = ({ apiKeyId, row, onClose }: ActionProps) => {
  useOnce(() => {
    void (async () => {
      try {
        const ok = await confirm({
          title: `Detach ${row.name}?`,
          description:
            'Vaulthalla stops managing this bucket: its event rules and its lifecycle rule are removed and it becomes unmanaged. Objects in the bucket are not touched.',
          confirmLabel: 'Detach',
          tone: 'danger',
        })
        if (!ok) return
        await api.send('upstream.bucket.detach', { api_key_id: apiKeyId, bucket: row.name })
        await refreshInventory()
        notify.success('Bucket detached', row.name)
      } catch (e) {
        notify.error(e, 'Could not detach the bucket')
      } finally {
        onClose()
      }
    })()
  })
  return null
}

// ---- inspect -------------------------------------------------------------------------------------------------------

const versioningLabel: Record<string, string> = {
  unversioned: 'Off',
  enabled: 'Enabled',
  suspended: 'Suspended',
  unknown: 'Unknown',
}

const useInspection = (apiKeyId: number, bucket: string) =>
  useWs('upstream.bucket.inspect', { api_key_id: apiKeyId, bucket }, { retry: false, select: d => d.inspection })

const InspectSheet = ({ apiKeyId, row, onClose, onLifecycle }: ActionProps & { onLifecycle: () => void }) => {
  const perms = useUpstreamPerms()
  const inspection = useInspection(apiKeyId, row.name)
  const owned = row.ownership === 'managed' || row.ownership === 'adopted'
  return (
    <Dialog open onOpenChange={open => !open && onClose()}>
      <SheetContent
        title={<BucketTitle row={row} />}
        description="Bucket-level configuration only; no objects are read."
        width="max-w-xl"
        footer={
          perms.configure && owned && !row.is_protected ?
            <Button size="sm" onClick={onLifecycle}>
              Edit lifecycle…
            </Button>
          : undefined
        }>
        <QueryState query={inspection}>{data => <InspectionView inspection={data} />}</QueryState>
      </SheetContent>
    </Dialog>
  )
}

const InspectionView = ({ inspection }: { inspection: Inspection }) => {
  const { config, bucket } = inspection
  return (
    <div className="space-y-5 text-sm">
      <DefinitionList
        items={[
          [
            'Region',
            <span key="r" className="font-mono text-xs">
              {config.region ?? bucket.region ?? DASH}
            </span>,
          ],
          ['Versioning', <span key="v">{versioningLabel[config.versioning] ?? config.versioning}</span>],
          [
            'Object lock',
            <span key="l">
              {config.object_lock === null || config.object_lock === undefined ?
                'Not readable with this credential'
              : config.object_lock ?
                'On'
              : 'Off'}
            </span>,
          ],
          ['Ownership', <span key="o">{bucket.ownership}</span>],
          ['Provisioning', <span key="p">{bucket.provisioning_state || DASH}</span>],
          [
            'Vault',
            isBound(bucket.vault_id) ?
              <Link key="vault" href={`/vaults/${bucket.vault_id}`} className="text-accent-text hover:underline">
                {bucket.vault_name || `Vault ${bucket.vault_id}`}
              </Link>
            : <span key="vault" className="text-fg-faint">
                {DASH}
              </span>,
          ],
        ]}
      />
      {config.warnings.length ?
        <ul className="rounded-control border-warn-line bg-warn-soft text-warn list-disc border py-2 pr-3 pl-7">
          {config.warnings.map(w => (
            <li key={w}>{w}</li>
          ))}
        </ul>
      : null}
      <section>
        <h3 className="text-fg mb-2 text-[13px] font-semibold">Lifecycle rules</h3>
        {!config.lifecycle_readable ?
          <p className="text-fg-subtle">Not readable with this credential.</p>
        : config.lifecycle.length === 0 ?
          <p className="text-fg-subtle">None.</p>
        : <ul className="divide-line rounded-card border-line divide-y border">
            {config.lifecycle.map(rule => (
              <LifecycleRuleRow key={rule.id || rule.prefix} rule={rule} />
            ))}
          </ul>
        }
      </section>
      <section>
        <h3 className="text-fg mb-2 text-[13px] font-semibold">Event notifications</h3>
        {!config.notifications_readable ?
          <p className="text-fg-subtle">Not readable with this credential.</p>
        : config.notifications.length === 0 ?
          <p className="text-fg-subtle">None.</p>
        : <ul className="divide-line rounded-card border-line divide-y border">
            {config.notifications.map(rule => (
              <NotificationRuleRow key={`${rule.id}-${rule.destination}`} rule={rule} />
            ))}
          </ul>
        }
        <p className="text-fg-subtle mt-2 text-xs">
          Other applications’ rules are listed read-only; Vaulthalla only ever changes its own.
        </p>
      </section>
    </div>
  )
}

const OwnerBadge = ({ foreign }: { foreign: boolean }) =>
  foreign ? <Badge tone="neutral">Other application</Badge> : <Badge tone="accent">Vaulthalla</Badge>

const LifecycleRuleRow = ({ rule }: { rule: LifecycleRule }) => {
  const parts: string[] = []
  if (rule.abort_incomplete_multipart_days)
    parts.push(`abort incomplete uploads after ${rule.abort_incomplete_multipart_days} d`)
  if (rule.expire_current_days) parts.push(`delete objects after ${rule.expire_current_days} d`)
  if (rule.expire_noncurrent_days) parts.push(`delete old versions after ${rule.expire_noncurrent_days} d`)
  return (
    <li className="px-3 py-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-fg font-mono text-xs">{rule.id || '(no id)'}</span>
        <OwnerBadge foreign={rule.foreign} />
        {!rule.enabled ?
          <Badge tone="neutral">Disabled</Badge>
        : null}
      </div>
      <p className="text-fg-subtle mt-1 text-xs">
        {rule.prefix ? `Prefix ${rule.prefix}: ` : 'Whole bucket: '}
        {parts.length ?
          parts.join(', ')
        : rule.foreign ?
          'actions Vaulthalla does not manage'
        : 'no actions'}
      </p>
    </li>
  )
}

const NotificationRuleRow = ({ rule }: { rule: NotificationRule }) => (
  <li className="px-3 py-2">
    <div className="flex flex-wrap items-center gap-2">
      <span className="text-fg font-mono text-xs">{rule.id || '(no id)'}</span>
      <OwnerBadge foreign={rule.foreign} />
    </div>
    <p className="text-fg-subtle mt-1 text-xs break-all">
      → {rule.destination_name || rule.destination || DASH}
      {rule.events.length ? ` · ${rule.events.join(', ')}` : ''}
      {rule.prefix ? ` · prefix ${rule.prefix}` : ''}
      {rule.suffix ? ` · suffix ${rule.suffix}` : ''}
    </p>
  </li>
)

// ---- lifecycle -----------------------------------------------------------------------------------------------------

const OUR_RULE_PREFIX = 'vaulthalla-'

const numberOrEmpty = (v: number | null | undefined) => (typeof v === 'number' && v > 0 ? String(v) : '')
const parseDays = (v: string): number | null => {
  const t = v.trim()
  if (!t) return 0
  const n = Number(t)
  return Number.isInteger(n) && n >= 0 && n <= 36500 ? n : null
}

const LifecycleDialog = ({ apiKeyId, row, onClose }: ActionProps) => {
  const inspection = useInspection(apiKeyId, row.name)
  return (
    <Dialog open onOpenChange={open => !open && onClose()}>
      <DialogContent
        size="md"
        title={
          <span>
            Lifecycle for <span className="font-mono">{row.name}</span>
          </span>
        }
        description="Vaulthalla keeps one rule of its own (vaulthalla-*). Every other rule on the bucket is preserved as it is.">
        <QueryState query={inspection}>
          {data => <LifecycleForm apiKeyId={apiKeyId} row={row} inspection={data} onClose={onClose} />}
        </QueryState>
      </DialogContent>
    </Dialog>
  )
}

const LifecycleForm = ({
  apiKeyId,
  row,
  inspection,
  onClose,
}: {
  apiKeyId: number
  row: BucketRow
  inspection: Inspection
  onClose: () => void
}) => {
  const ids = useId()
  const ours = inspection.config.lifecycle.find(r => !r.foreign && r.id.startsWith(OUR_RULE_PREFIX))
  const supports = (field: string) => inspection.supported_lifecycle_fields.includes(field)
  const [abort, setAbort] = useState(numberOrEmpty(ours?.abort_incomplete_multipart_days))
  const [expire, setExpire] = useState(numberOrEmpty(ours?.expire_current_days))
  const [noncurrent, setNoncurrent] = useState(numberOrEmpty(ours?.expire_noncurrent_days))
  const [prefix, setPrefix] = useState(ours?.prefix ?? '')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)

  const values = { abort: parseDays(abort), expire: parseDays(expire), noncurrent: parseDays(noncurrent) }
  const invalid = Object.values(values).some(v => v === null)
  const destructive = (values.expire ?? 0) > 0 || (values.noncurrent ?? 0) > 0

  const send = async (patch: LifecyclePatch) => {
    setBusy(true)
    setError(null)
    try {
      await withConfirmation(
        UPSTREAM_CODES.destructiveLifecycle,
        accepted =>
          api.send('upstream.bucket.lifecycle.set', {
            api_key_id: apiKeyId,
            bucket: row.name,
            ...patch,
            ...(accepted ? { accept_destructive: true } : {}),
          }),
        message => ({
          title: 'Delete objects automatically?',
          description: message,
          confirmLabel: 'Accept and save',
          tone: 'danger',
        }),
      )
      await refreshInventory()
      notify.success('Lifecycle saved', row.name)
      onClose()
    } catch (e) {
      if (!isWsError(e, 'needs_confirmation')) setError(e)
    } finally {
      setBusy(false)
    }
  }

  const save = () => {
    if (invalid) return
    const patch: LifecyclePatch = { prefix: prefix.trim() }
    if (supports('abort_incomplete_multipart_days')) patch.abort_incomplete_multipart_days = values.abort ?? 0
    if (supports('expire_current_days')) patch.expire_current_days = values.expire ?? 0
    if (supports('expire_noncurrent_days')) patch.expire_noncurrent_days = values.noncurrent ?? 0
    void send(patch)
  }

  const dayField = (label: string, id: string, value: string, set: (v: string) => void, hint: string) => (
    <Field label={label} htmlFor={id} hint={hint} error={parseDays(value) === null ? 'Whole days, 0–36500' : undefined}>
      <Input
        id={id}
        inputMode="numeric"
        placeholder="Off"
        className="tabular"
        value={value}
        onChange={e => set(e.target.value)}
      />
    </Field>
  )

  return (
    <div className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2">
        {supports('abort_incomplete_multipart_days') ?
          dayField(
            'Abort incomplete uploads after (days)',
            `${ids}-abort`,
            abort,
            setAbort,
            'Frees storage held by abandoned multipart uploads. Safe.',
          )
        : null}
        {supports('expire_current_days') ?
          dayField(
            'Delete objects after (days)',
            `${ids}-expire`,
            expire,
            setExpire,
            'Destructive: removes live objects, including vault files.',
          )
        : null}
        {supports('expire_noncurrent_days') ?
          dayField(
            'Delete old versions after (days)',
            `${ids}-noncurrent`,
            noncurrent,
            setNoncurrent,
            'Destructive: removes overwritten and deleted versions.',
          )
        : null}
        <Field label="Prefix" htmlFor={`${ids}-prefix`} hint="Empty applies the rule to the whole bucket.">
          <Input id={`${ids}-prefix`} className="font-mono" value={prefix} onChange={e => setPrefix(e.target.value)} />
        </Field>
      </div>
      {destructive ?
        <p
          role="alert"
          className="rounded-control border-danger-line bg-danger-soft text-danger border px-3 py-2 text-sm">
          This rule deletes data in the bucket automatically. The daemon asks for an explicit acceptance before saving
          it.
        </p>
      : null}
      <InlineError error={error} />
      <div className="flex flex-wrap justify-end gap-2">
        {ours ?
          <Button variant="ghost" onClick={() => void send({ clear: true })} disabled={busy}>
            Remove Vaulthalla’s rule
          </Button>
        : null}
        <Button variant="ghost" onClick={onClose}>
          Cancel
        </Button>
        <Button variant="primary" onClick={save} loading={busy} disabled={invalid}>
          Save
        </Button>
      </div>
    </div>
  )
}

// ---- adoption check ------------------------------------------------------------------------------------------------

const AdoptDialog = ({ apiKeyId, row, onClose }: ActionProps) => {
  const report = useWs(
    'upstream.bucket.adopt.preflight',
    { api_key_id: apiKeyId, bucket: row.name },
    { retry: false, staleTime: 0, select: d => d.report },
  )
  const perms = useUpstreamPerms()
  const blocked = Boolean(report.data?.blockers.length)
  return (
    <Dialog open onOpenChange={open => !open && onClose()}>
      <DialogContent
        size="lg"
        title={
          <span>
            Adoption check for <span className="font-mono">{row.name}</span>
          </span>
        }
        description="A read-only look at what is in the bucket: a bounded listing and a few metadata requests. Nothing is changed."
        footer={
          <>
            <Button variant="ghost" onClick={onClose}>
              Close
            </Button>
            {perms.provision && report.data && !blocked ?
              <Button asChild variant="primary">
                <Link
                  href={`/vaults/new?type=s3&api_key_id=${apiKeyId}&bucket=${encodeURIComponent(row.name)}&bucket_mode=adopt`}>
                  Create a vault from this bucket
                </Link>
              </Button>
            : null}
          </>
        }>
        <QueryState query={report}>{data => <AdmissionReportView report={data} />}</QueryState>
      </DialogContent>
    </Dialog>
  )
}

// ---- cleanup -------------------------------------------------------------------------------------------------------

const CleanupDialog = ({ apiKeyId, row, onClose }: ActionProps) => {
  const ids = useId()
  const plan = useWs(
    'upstream.bucket.cleanup.preflight',
    { api_key_id: apiKeyId, bucket: row.name },
    { retry: false, staleTime: 0, gcTime: 0, select: d => d.plan },
  )
  const [typed, setTyped] = useState('')
  const [deleteBucket, setDeleteBucket] = useState(true)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const [result, setResult] = useState<CleanupResult | null>(null)

  const run = async (p: CleanupPlan) => {
    setBusy(true)
    setError(null)
    try {
      const res = await api.send('upstream.bucket.cleanup', {
        api_key_id: apiKeyId,
        bucket: row.name,
        confirm_token: p.confirm_token,
        delete_bucket: deleteBucket,
      })
      setResult(res.result)
      await refreshInventory()
    } catch (e) {
      // An expired or stale preflight: count again before anyone confirms anything.
      if (isWsError(e, 'needs_confirmation') && e.code === UPSTREAM_CODES.cleanup) {
        setTyped('')
        void plan.refetch()
      }
      setError(e)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open onOpenChange={open => !open && !busy && onClose()}>
      <DialogContent
        size="lg"
        title={
          <span>
            Delete <span className="font-mono">{row.name}</span>?
          </span>
        }
        description="Deletes every object and version in this managed bucket, then (optionally) the bucket. Vaults are never deleted with it, and this can’t be undone.">
        {result ?
          <CleanupResultView result={result} onClose={onClose} />
        : <QueryState query={plan}>
            {p => {
              const blocked = p.blockers.length > 0
              return (
                <div className="space-y-4 text-sm">
                  {blocked ?
                    <div
                      role="alert"
                      className="rounded-control border-danger-line bg-danger-soft text-danger border px-3 py-2">
                      <p className="font-medium">Cleanup is refused:</p>
                      <ul className="mt-1 list-disc pl-5">
                        {p.blockers.map(b => (
                          <li key={b}>{b}</li>
                        ))}
                      </ul>
                    </div>
                  : null}
                  <DefinitionList
                    items={[
                      [
                        'Objects',
                        <span key="o" className="tabular">
                          {formatInt(p.objects)}
                          {p.truncated ? '+' : ''}
                        </span>,
                      ],
                      [
                        'Versions',
                        <span key="v" className="tabular">
                          {formatInt(p.versions)}
                        </span>,
                      ],
                      [
                        'Delete markers',
                        <span key="d" className="tabular">
                          {formatInt(p.delete_markers)}
                        </span>,
                      ],
                      [
                        'Size',
                        <span key="b" className="tabular">
                          {formatBytes(p.bytes)}
                          {p.truncated ? '+' : ''}
                        </span>,
                      ],
                      ['Versioning', <span key="ver">{versioningLabel[p.versioning] ?? p.versioning}</span>],
                      [
                        'Object lock',
                        <span key="l">
                          {p.object_lock === null || p.object_lock === undefined ?
                            'Unknown'
                          : p.object_lock ?
                            'On'
                          : 'Off'}
                        </span>,
                      ],
                      [
                        'Plan valid until',
                        <span key="e" className="tabular">
                          {formatDateTime(p.expires_at)}
                        </span>,
                      ],
                    ]}
                  />
                  {p.truncated ?
                    <p className="text-warn text-xs">
                      Counting stopped at the preflight limit: there is more than shown.
                    </p>
                  : null}
                  {p.sample_keys.length ?
                    <details className="rounded-card border-line border">
                      <summary className="text-fg-muted cursor-pointer px-3 py-2 text-xs select-none">
                        Sample keys
                      </summary>
                      <ul className="border-line text-fg-subtle max-h-40 overflow-y-auto border-t px-3 py-2 font-mono text-xs">
                        {p.sample_keys.map(k => (
                          <li key={k} className="truncate">
                            {k}
                          </li>
                        ))}
                      </ul>
                    </details>
                  : null}
                  {!blocked ?
                    <>
                      <label className="text-fg-muted flex items-center gap-2 text-sm">
                        <Checkbox checked={deleteBucket} onCheckedChange={v => setDeleteBucket(Boolean(v))} />
                        Delete the bucket itself once it is empty
                      </label>
                      <Field
                        label={
                          <span>
                            Type <span className="font-mono">{row.name}</span> to confirm
                          </span>
                        }
                        htmlFor={`${ids}-typed`}>
                        <Input
                          id={`${ids}-typed`}
                          className="font-mono"
                          autoComplete="off"
                          spellCheck={false}
                          value={typed}
                          onChange={e => setTyped(e.target.value)}
                        />
                      </Field>
                    </>
                  : null}
                  <InlineError error={error} />
                  <div className="flex flex-wrap justify-end gap-2">
                    <Button variant="ghost" onClick={onClose} disabled={busy}>
                      Cancel
                    </Button>
                    {!blocked ?
                      <Button
                        variant="danger-solid"
                        onClick={() => void run(p)}
                        loading={busy}
                        disabled={typed !== row.name}>
                        {busy ?
                          'Deleting…'
                        : deleteBucket ?
                          'Delete objects and bucket'
                        : 'Delete all objects'}
                      </Button>
                    : null}
                  </div>
                </div>
              )
            }}
          </QueryState>
        }
      </DialogContent>
    </Dialog>
  )
}

const outcomeText: Record<string, string> = {
  deleted: 'The bucket and everything in it were deleted.',
  emptied: 'Every object and version was deleted; the bucket was kept.',
  partial: 'Cleanup stopped partway: some objects were not deleted. Nothing is reported as done that wasn’t.',
  refused: 'The daemon refused the cleanup.',
}

const CleanupResultView = ({ result, onClose }: { result: CleanupResult; onClose: () => void }) => {
  const ok = result.outcome === 'deleted' || result.outcome === 'emptied'
  return (
    <div className="space-y-4 text-sm">
      <p role="status" className={ok ? 'text-ok' : 'text-warn'}>
        {outcomeText[result.outcome] ?? `Outcome: ${result.outcome}`}
      </p>
      <DefinitionList
        items={[
          [
            'Deleted',
            <span key="d" className="tabular">
              {formatInt(result.deleted)}
            </span>,
          ],
          [
            'Failed',
            <span key="f" className="tabular">
              {formatInt(result.failed)}
            </span>,
          ],
          ['Bucket deleted', <span key="b">{result.bucket_deleted ? 'Yes' : 'No'}</span>],
        ]}
      />
      {result.errors.length ?
        <ul className="rounded-control border-danger-line bg-danger-soft text-danger max-h-48 list-disc overflow-y-auto border py-2 pr-3 pl-7 text-xs">
          {result.errors.map((e, i) => (
            <li key={i}>{e}</li>
          ))}
        </ul>
      : null}
      <div className="flex justify-end">
        <Button onClick={onClose}>Close</Button>
      </div>
    </div>
  )
}
