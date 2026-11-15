'use client'

import React, { useState } from 'react'
import { api } from '@/lib/session'
import { useCan } from '@/lib/permissions'
import { queryClient, useWs, wsKey } from '@/lib/query'
import type { Response } from '@/lib/ws/client'
import { DefinitionList, Panel } from '@/components/ui/Panel'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { SwitchRow } from '@/components/ui/Choice'
import { InlineError, QueryState } from '@/components/ui/State'
import { confirm } from '@/components/ui/Confirm'
import { notify } from '@/components/ui/Toast'
import { RELAY_COPY, relayStateText, relaySwitchable, relaySwitchedBy } from '@/features/cloudRelay/copy'

type RelayStatus = Response<'cloud.relay.status'>

const when = (seconds: number) => new Date(seconds * 1000).toLocaleString()

// The cloud relay's local switch (design/cloud/relay.md, "The switch"), shown on the cloud page when the server announces
// the cloud.relay capability, to super admins and the admin cloud View permission (the server's status rule). Only super
// admins get the switch; enabling is a device.trust step-up, which the ws client hands to the shell's Step-up dialog.
export const RelayPanel = () => {
  const status = useWs('cloud.relay.status', null, {
    refetchInterval: query => (query.state.data?.state === 'connecting' ? 5_000 : 30_000),
  })
  return (
    <Panel id="cloud-relay" className="scroll-mt-4" title={RELAY_COPY.title} description={RELAY_COPY.description}>
      <QueryState query={status}>{data => <Relay status={data} />}</QueryState>
    </Panel>
  )
}

const Relay = ({ status }: { status: RelayStatus }) => {
  const superAdmin = useCan({ superAdmin: true })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const words = relayStateText(status, when)
  const switchedBy = relaySwitchedBy(status, when)

  const send = async (on: boolean, toast?: string) => {
    setBusy(true)
    setError(null)
    try {
      const data = on ? await api.send('cloud.relay.enable', null) : await api.send('cloud.relay.disable', null)
      queryClient.setQueryData(wsKey('cloud.relay.status', null), data)
      if (toast) notify.success(toast)
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  const toggle = async (on: boolean) => {
    const ok = await confirm(
      on
        ? { title: RELAY_COPY.enableTitle, description: RELAY_COPY.enableBody, confirmLabel: RELAY_COPY.enableConfirm, tone: 'primary' }
        : { title: RELAY_COPY.disableTitle, description: RELAY_COPY.disableBody, confirmLabel: RELAY_COPY.disableConfirm, tone: 'danger' },
    )
    if (ok) await send(on, on ? RELAY_COPY.enabledToast : RELAY_COPY.disabledToast)
  }

  return (
    <div className="space-y-4" data-testid="cloud-relay">
      <div className="space-y-2 text-sm text-fg-muted">
        <p>{RELAY_COPY.what}</p>
        <p>{RELAY_COPY.sees}</p>
        <p className="text-fg-subtle">{RELAY_COPY.notOffered}</p>
      </div>
      {superAdmin ? (
        <SwitchRow
          id="cloud-relay-switch"
          label={RELAY_COPY.switchLabel}
          hint={status.enabled ? RELAY_COPY.switchHintOn : RELAY_COPY.switchHintOff}
          checked={status.enabled}
          disabled={busy || !relaySwitchable(status)}
          onCheckedChange={on => void toggle(on)}
        />
      ) : (
        <p className="text-sm text-fg-subtle">{RELAY_COPY.superAdminOnly}</p>
      )}
      <InlineError error={error} />
      <p className="text-sm text-fg-muted" data-testid="cloud-relay-detail">
        {words.detail}
      </p>
      {status.last_error && (status.state === 'backoff' || status.state === 'waiting' || status.state === 'stopped') ? (
        <p role="alert" className="rounded-control border border-warn-line bg-warn-soft px-3 py-2 text-sm text-warn" data-testid="cloud-relay-error">
          Last error: {status.last_error}
        </p>
      ) : null}
      {superAdmin && status.enabled && status.state === 'stopped' ? (
        <div className="flex flex-wrap items-center gap-3">
          <Button variant="secondary" loading={busy} onClick={() => void send(true)} data-testid="cloud-relay-retry">
            {RELAY_COPY.retry}
          </Button>
          <span className="text-xs text-fg-subtle">{RELAY_COPY.retryHint}</span>
        </div>
      ) : null}
      <DefinitionList
        items={[
          [
            'Status',
            <span key="s" data-testid="cloud-relay-state">
              <Badge tone={words.tone} dot={words.tone !== 'neutral'}>
                {words.label}
              </Badge>
            </span>,
          ],
          ...(switchedBy ? [['Switched on', <span key="w" data-testid="cloud-relay-switched-by">{switchedBy}</span>] as [string, React.ReactNode]] : []),
          [
            'Relayed connections',
            <span key="c" className="tabular" data-testid="cloud-relay-streams">
              {status.streams} open · {status.streams_accepted} accepted · {status.streams_refused} refused
            </span>,
          ],
        ]}
      />
    </div>
  )
}

export default RelayPanel
