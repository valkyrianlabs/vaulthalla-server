'use client'

import React, { useState } from 'react'
import dynamic from 'next/dynamic'
import { api } from '@/lib/session'
import { useCan } from '@/lib/permissions'
import { formatBytes } from '@/lib/format'
import { PageHeader, Panel } from '@/components/ui/Panel'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { Meter } from '@/components/ui/Stat'
import { SwitchRow } from '@/components/ui/Choice'
import { EmptyState, InlineError, QueryState } from '@/components/ui/State'
import { confirm } from '@/components/ui/Confirm'
import { notify } from '@/components/ui/Toast'
import { COPY, planSentence } from '@/features/managedStorage/copy'
import {
  leaveUrl,
  listedVaults,
  offNeedsConfirm,
  progressRatio,
  stateTone,
  switchable,
  usageRatio,
  type StorageStatus,
  type StorageVault,
} from '@/features/managedStorage/model'
import {
  refreshManagedStorage,
  useCloudView,
  useHelloCapability,
  useManagedStorageCapability,
  useManagedStorageStatus,
} from '@/features/managedStorage/queries'

// The cloud relay's switch (design/cloud/relay.md) lives on this page, the server's cloud page; loaded only when the
// server announces it, so it stays out of the route's first load.
const RELAY_CAPABILITY = 'cloud.relay'
const RelayPanel = dynamic(() => import('@/features/cloudRelay/RelayPanel'), { ssr: false })

const when = (seconds: number | null | undefined) => (seconds ? new Date(seconds * 1000).toLocaleString() : '—')

const useAction = () => {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const run = async (fn: () => Promise<unknown>, done?: string) => {
    setBusy(true)
    setError(null)
    try {
      await fn()
      if (done) notify.success(done)
      await refreshManagedStorage()
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }
  return { busy, error, run }
}

export const ManagedStoragePage = () => {
  const canView = useCloudView()
  const capable = useManagedStorageCapability(canView)
  const relay = useHelloCapability(RELAY_CAPABILITY, canView)
  const status = useManagedStorageStatus(canView && capable)
  return (
    <div className="space-y-6">
      <PageHeader title={COPY.title} description={COPY.description} />
      {!canView || !capable ? (
        <EmptyState title={COPY.title} description={COPY.unavailable.unlinked} />
      ) : (
        <QueryState query={status}>{data => <Body status={data} />}</QueryState>
      )}
      {canView && relay ? <RelayPanel /> : null}
    </div>
  )
}

const Unavailable = ({ status }: { status: StorageStatus }) => {
  const why = !status.linked
    ? COPY.unavailable.unlinked
    : status.account_key === 'unconfirmed'
      ? COPY.unavailable.unconfirmed
      : status.account_key === 'tampered'
        ? COPY.unavailable.tampered
        : COPY.unavailable.noPlan
  return <EmptyState title={COPY.title} description={status.next_step ?? why} />
}

const Body = ({ status }: { status: StorageStatus }) => {
  const superAdmin = useCan({ superAdmin: true })
  const storagePerm = useCan({ permission: 'admin.cloud.storage' })
  const billingPerm = useCan({ permission: 'admin.cloud.billing' })
  const canStorage = superAdmin || storagePerm
  const canBilling = superAdmin || billingPerm
  const action = useAction()
  if (!status.available && !status.ended && status.vaults.every(v => v.storage !== 'managed')) return <Unavailable status={status} />

  const billing = (kind: 'portal' | 'checkout') =>
    action.run(async () => {
      const h = await api.send('cloud.storage.billing.handoff', { kind, plan: null })
      window.open(h.url, '_blank', 'noopener,noreferrer')
    })
  const leave = async () => {
    const url = leaveUrl(status)
    if (!(await confirm({ title: COPY.leave, description: COPY.leaveConfirm, confirmLabel: COPY.leave, tone: 'danger' }))) return
    if (url) window.open(url, '_blank', 'noopener,noreferrer')
    else await billing('portal')
  }
  const ratio = usageRatio(status)

  return (
    <div className="space-y-6" data-testid="managed-storage">
      <Panel
        title={planSentence(status.entitlement, status.plan)}
        description={status.fetched_at ? COPY.lastChecked(when(status.fetched_at)) : undefined}
        actions={
          canBilling ? (
            <>
              <Button variant="secondary" onClick={() => void billing(status.entitlement ? 'portal' : 'checkout')} loading={action.busy}>
                {status.entitlement ? COPY.manageBilling : COPY.choosePlan}
              </Button>
              {status.entitlement ? (
                <Button variant="secondary" onClick={() => void leave()}>
                  {COPY.leave}
                </Button>
              ) : null}
            </>
          ) : null
        }>
        <div className="space-y-3">
          {status.quota_bytes ? (
            <div className="space-y-1">
              <div className="flex flex-wrap justify-between gap-x-3 text-sm text-fg-muted">
                <span>{COPY.usageCaption(status.usage_day)}</span>
                <span className="tabular whitespace-nowrap">
                  {formatBytes(status.used_bytes)} / {formatBytes(status.quota_bytes)}
                </span>
              </div>
              <Meter ratio={ratio} label={COPY.usageCaption(status.usage_day)} />
            </div>
          ) : null}
          <p className="text-sm text-fg-muted">
            {COPY.localCaption}: {formatBytes(status.managed_local_bytes)}
          </p>
          {canStorage ? (
            <SwitchRow
              id="managed-storage-new-vaults"
              label={COPY.newVaultsLabel}
              hint={COPY.newVaultsHint}
              checked={status.new_vaults}
              disabled={action.busy}
              onCheckedChange={on => void action.run(() => api.send('cloud.storage.new_vaults', { enabled: on }))}
            />
          ) : null}
          <InlineError error={action.error} />
        </div>
      </Panel>

      {status.ended && !status.ended.confirmed_by ? (
        <Panel title={COPY.endedTitle} description={COPY.endedBody(when(status.ended.converts_at))}>
          {canStorage ? (
            <Button
              variant="danger"
              loading={action.busy}
              onClick={() => void action.run(() => api.send('cloud.storage.ended.confirm', null))}>
              {COPY.endedConfirm}
            </Button>
          ) : null}
        </Panel>
      ) : null}

      {status.offered.length > 0 ? (
        <Panel title={COPY.offerTitle(status.offered.length)} description={COPY.offerBody} id="managed-storage-offer">
          <ul className="mb-3 space-y-1 text-sm">
            {status.offered.map(v => (
              <li key={v.vault_id} className="flex justify-between">
                <span>{v.vault_name}</span>
                <span className="text-fg-muted">{formatBytes(v.local_bytes)}</span>
              </li>
            ))}
          </ul>
          {canStorage ? (
            <div className="flex gap-2">
              <Button
                variant="primary"
                loading={action.busy}
                onClick={() => void action.run(() => api.send('cloud.storage.offer.accept', { vault_ids: null }))}>
                {COPY.acceptAll}
              </Button>
              <Button
                variant="secondary"
                disabled={action.busy}
                onClick={() => void action.run(() => api.send('cloud.storage.offer.decline', { vault_ids: null }))}>
                {COPY.decline}
              </Button>
            </div>
          ) : null}
        </Panel>
      ) : null}

      <Panel title="Vaults">
        <ul className="divide-y divide-line" data-testid="managed-storage-vaults">
          {listedVaults(status).map(v => (
            <VaultRow key={v.vault_id} vault={v} canSwitch={canStorage} />
          ))}
        </ul>
      </Panel>
    </div>
  )
}

const VaultRow = ({ vault, canSwitch }: { vault: StorageVault; canSwitch: boolean }) => {
  const action = useAction()
  const ratio = progressRatio(vault)
  const on = vault.switch === 'on'
  const flip = async (next: boolean) => {
    let confirmName: string | null = null
    if (!next && offNeedsConfirm(vault)) {
      const ok = await confirm({
        title: COPY.turnOffTitle,
        description: COPY.turnOffBody,
        confirmLabel: COPY.turnOffConfirm,
        tone: 'danger',
        typeToConfirm: vault.vault_name,
      })
      if (!ok) return
      confirmName = vault.vault_name
    }
    await action.run(() =>
      api.send('cloud.storage.switch', { vault_id: vault.vault_id, enabled: next, confirm: confirmName }),
    )
  }
  return (
    <li className="space-y-2 py-3" data-testid={`managed-storage-vault-${vault.vault_id}`}>
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="truncate font-medium">{vault.vault_name}</div>
          <div className="text-sm text-fg-muted">
            {formatBytes(vault.local_bytes)} · {vault.summary}
          </div>
        </div>
        <Badge tone={stateTone(vault)} dot>
          {vault.storage === 'own' ? 'Own storage' : vault.state}
        </Badge>
      </div>
      {vault.state === 'attaching' || vault.state === 'detaching' ? <Meter ratio={ratio} label={vault.summary} /> : null}
      {canSwitch && switchable(vault) ? (
        <SwitchRow
          id={`managed-storage-switch-${vault.vault_id}`}
          label={COPY.switchLabel}
          hint={on ? COPY.switchHintOn : COPY.switchHintOff}
          checked={on}
          disabled={action.busy}
          onCheckedChange={next => void flip(next)}
        />
      ) : null}
      <InlineError error={action.error} />
    </li>
  )
}

export default ManagedStoragePage
