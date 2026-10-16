'use client'

import React, { useId, useState } from 'react'
import { api } from '@/lib/session'
import { invalidate } from '@/lib/query'
import { isWsError } from '@/lib/ws/errors'
import { DASH, formatDateTime, formatInt, formatRelative } from '@/lib/format'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { confirm } from '@/components/ui/Confirm'
import { Field, Input, Select } from '@/components/ui/Field'
import { DefinitionList, Panel } from '@/components/ui/Panel'
import { InlineError } from '@/components/ui/State'
import { Spinner } from '@/components/ui/Spinner'
import { notify } from '@/components/ui/Toast'
import { ArrowsRotateIcon } from '@/components/ui/icons'
import { eventStateTone, useEventStatus, useUpstreamPerms } from '@/features/credentials/upstream/hooks'
import type { VaultDetail } from '@/features/vaults/model'
import type { EventStatus, ForeignObjects } from '@/models/upstream'

const refresh = () => invalidate('upstream.events.status', 'upstream.bucket.list')

const LIVE = new Set(['pending', 'active', 'failed', 'removing'])

// Event-driven sync (#96) for one S3 vault: the bucket notifies a Vaulthalla-owned queue and the daemon syncs only
// the keys that changed. Status comes from upstream.events.status (polled every 30 s); every value shown is the
// daemon's, unknown ones stay "—".
const EventSyncPanel = ({ vault }: { vault: VaultDetail }) => {
  const perms = useUpstreamPerms()
  const status = useEventStatus(vault.id, perms.view || perms.configure)

  if (!perms.view && !perms.configure) return null

  return (
    <Panel
      title="Event-driven sync"
      description="Changes made directly in the bucket sync within seconds, without listing it. A scheduled full sync still runs as the safety net."
      actions={status.data ? <StateBadge state={status.data.state} /> : null}>
      {status.isPending ?
        <div className="flex justify-center py-6">
          <Spinner className="size-5" label="Loading" />
        </div>
      : status.error ?
        <p className="text-fg-subtle text-sm">
          {isWsError(status.error, 'denied') ?
            'Your role can’t view event subscriptions for this vault.'
          : 'Event status is unavailable from this server.'}
        </p>
      : <EventBody vault={vault} status={status.data ?? null} />}
    </Panel>
  )
}

const StateBadge = ({ state }: { state: string }) => (
  <Badge tone={eventStateTone(state)} dot pulse={state === 'pending'}>
    {state === 'none' ? 'Off' : state}
  </Badge>
)

const EventBody = ({ vault, status }: { vault: VaultDetail; status: EventStatus | null }) => {
  const ids = useId()
  const perms = useUpstreamPerms()
  const [prefix, setPrefix] = useState('')
  const [foreign, setForeign] = useState<ForeignObjects>((status?.foreign_objects as ForeignObjects) || 'import')
  const [busy, setBusy] = useState<null | 'enable' | 'disable' | 'repair'>(null)
  const [error, setError] = useState<unknown>(null)
  const live = status ? LIVE.has(status.state) : false

  const run = async (kind: NonNullable<typeof busy>, fn: () => Promise<unknown>, done: string) => {
    setBusy(kind)
    setError(null)
    try {
      await fn()
      await refresh()
      notify.success(done, vault.name)
    } catch (e) {
      setError(e)
    } finally {
      setBusy(null)
    }
  }

  if (status && !status.supported)
    return (
      <p className="text-fg-subtle text-sm">
        {status.unsupported_reason
          || 'Not available for this vault: its credential needs provider administration (AWS S3 or Cloudflare R2).'}
      </p>
    )

  const ch = status?.channel ?? null
  return (
    <div className="space-y-4">
      {status && status.state !== 'none' ?
        <>
          <DefinitionList
            items={[
              [
                'Bucket',
                <span key="b" className="font-mono text-xs">
                  {status.bucket || vault.bucket || DASH}
                </span>,
              ],
              ['Initial listing', <span key="bl">{baselineLabel(status.baseline_state)}</span>],
              [
                'Objects added directly to the bucket',
                <span key="f">{status.foreign_objects === 'ignore' ? 'Ignored' : 'Imported into the vault'}</span>,
              ],
              [
                'Queue',
                ch ?
                  <span key="q" className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs">{ch.queue_name}</span>
                    <StateBadge state={ch.state} />
                  </span>
                : <span key="q" className="text-fg-faint">
                    {DASH}
                  </span>,
              ],
              [
                'Last poll',
                <span key="lp" className="tabular" title={formatDateTime(ch?.last_poll_at)}>
                  {formatRelative(ch?.last_poll_at)}
                </span>,
              ],
              [
                'Last event',
                <span key="le" className="tabular" title={formatDateTime(status.last_event_at)}>
                  {formatRelative(status.last_event_at)}
                </span>,
              ],
              [
                'Queue backlog',
                <span key="bk" className="tabular">
                  {ch?.backlog === null || ch?.backlog === undefined ? DASH : formatInt(ch.backlog)}
                </span>,
              ],
              [
                'Inbox',
                <span key="i" className="tabular">
                  {formatInt(status.inbox_pending)} pending · {formatInt(status.inbox_applied)} awaiting sync ·{' '}
                  {formatInt(status.inbox_failed)} failed
                </span>,
              ],
              [
                'Last 24 h',
                <span key="d" className="tabular">
                  {formatInt(status.inbox_done_24h)} synced · {formatInt(status.inbox_self_24h)} of Vaulthalla’s own
                  writes skipped
                </span>,
              ],
              [
                'Rules',
                <span key="r" className="font-mono text-xs">
                  {status.rule_ids.length ? status.rule_ids.join(', ') : DASH}
                  {status.foreign_rules ? ` (+${status.foreign_rules} from other applications, untouched)` : ''}
                </span>,
              ],
            ]}
          />
          {status.last_error || ch?.last_error ?
            <div
              role="alert"
              className="rounded-control border-danger-line bg-danger-soft text-danger border px-3 py-2 text-sm">
              {status.last_error ?
                <p>{status.last_error}</p>
              : null}
              {ch?.last_error ?
                <p className={status.last_error ? 'mt-1' : undefined}>
                  Queue: {ch.last_error}
                  {ch.consecutive_failures ? ` (${ch.consecutive_failures} failed polls in a row)` : ''}
                  {ch.last_error_at ? ` · ${formatRelative(ch.last_error_at)}` : ''}
                </p>
              : null}
            </div>
          : null}
        </>
      : <p className="text-fg-subtle text-sm">Off. The vault syncs on its schedule only.</p>}

      {perms.configure && !live ?
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Only keys under this prefix" htmlFor={`${ids}-prefix`} hint="Empty watches the whole bucket.">
            <Input
              id={`${ids}-prefix`}
              className="font-mono"
              value={prefix}
              onChange={e => setPrefix(e.target.value)}
            />
          </Field>
          <Field
            label="Objects added directly to the bucket"
            htmlFor={`${ids}-foreign`}
            hint={
              foreign === 'import' ?
                'Imported as vault files (sealed locally); Vaulthalla-encrypted objects must authenticate.'
              : 'Only objects Vaulthalla wrote are synced; others are skipped and counted.'
            }>
            <Select id={`${ids}-foreign`} value={foreign} onChange={e => setForeign(e.target.value as ForeignObjects)}>
              <option value="import">Import them</option>
              <option value="ignore">Ignore them</option>
            </Select>
          </Field>
        </div>
      : null}

      <InlineError error={error} />

      {perms.configure ?
        <div className="flex flex-wrap justify-end gap-2">
          {live ?
            <>
              <Button
                variant="ghost"
                onClick={() =>
                  void run(
                    'repair',
                    () => api.send('upstream.events.repair', { vault_id: vault.id }),
                    'Event subscription repaired',
                  )
                }
                loading={busy === 'repair'}
                disabled={busy !== null}>
                <ArrowsRotateIcon aria-hidden />
                Repair
              </Button>
              <Button
                variant="danger"
                loading={busy === 'disable'}
                disabled={busy !== null}
                onClick={async () => {
                  const ok = await confirm({
                    title: 'Turn off event-driven sync?',
                    description:
                      'Vaulthalla removes only its own notification rule from the bucket. The vault keeps syncing on its schedule.',
                    confirmLabel: 'Turn off',
                    tone: 'danger',
                  })
                  if (ok)
                    void run(
                      'disable',
                      () => api.send('upstream.events.disable', { vault_id: vault.id }),
                      'Event-driven sync turned off',
                    )
                }}>
                Turn off
              </Button>
            </>
          : <Button
              variant="primary"
              loading={busy === 'enable'}
              disabled={busy !== null}
              onClick={() =>
                void run(
                  'enable',
                  () =>
                    api.send('upstream.events.enable', {
                      vault_id: vault.id,
                      ...(prefix.trim() ? { prefix: prefix.trim() } : {}),
                      foreign_objects: foreign,
                    }),
                  'Event-driven sync turned on',
                )
              }>
              {busy === 'enable' ? 'Setting up the queue…' : 'Turn on event-driven sync'}
            </Button>
          }
        </div>
      : null}
    </div>
  )
}

const baselineLabel = (state: string) => {
  switch (state) {
    case 'done':
      return 'Done'
    case 'running':
      return 'Listing the bucket; events received meanwhile are held and replayed'
    case 'pending':
      return 'Waiting for the first full listing'
    case 'none':
      return 'Not needed'
    default:
      return state || DASH
  }
}

export default EventSyncPanel
