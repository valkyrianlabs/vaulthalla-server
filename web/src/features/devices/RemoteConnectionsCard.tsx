'use client'

import React, { useState } from 'react'
import { api } from '@/lib/session'
import { queryClient, useWs, wsKey } from '@/lib/query'
import { Panel, DefinitionList } from '@/components/ui/Panel'
import { Badge } from '@/components/ui/Badge'
import { SwitchRow } from '@/components/ui/Choice'
import { QueryState, InlineError } from '@/components/ui/State'
import { confirm } from '@/components/ui/Confirm'
import { notify } from '@/components/ui/Toast'
import { CopyIcon, CheckIcon, TriangleExclamationIcon } from '@/components/ui/icons'
import { IconButton } from '@/components/ui/IconButton'
import { groupHex, type ListenerStatus } from '@/features/devices/model'

// Super admins: where the device listener (Vaulthalla Desktop's mutual-TLS endpoint) listens. Off = loopback only;
// on = every interface. The port comes from the daemon (device_server.port), never from this console.
export const RemoteConnectionsCard = () => {
  const status = useWs('device.remote.status', null, { refetchInterval: 30_000 })
  return (
    <Panel
      id="remote-connections"
      className="scroll-mt-4"
      title="Remote connections"
      description="Whether Vaulthalla Desktop on other machines can reach this server to pair and connect.">
      <QueryState query={status}>{data => <Remote status={data.status} />}</QueryState>
    </Panel>
  )
}

const listenerBadge = (s: ListenerStatus) => {
  if (!s.enabled) return <Badge tone="neutral">Turned off</Badge>
  if (s.listening) return <Badge tone="ok" dot>Listening</Badge>
  return <Badge tone="danger" dot>Not listening</Badge>
}

const Fingerprint = ({ hex }: { hex: string }) => {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(hex)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      notify.info('Copy it manually', 'Clipboard access isn’t available here.')
    }
  }
  return (
    <span className="flex items-start gap-1">
      <code className="font-mono text-xs break-all text-fg-muted" data-testid="remote-fingerprint">
        {groupHex(hex)}
      </code>
      <IconButton label={copied ? 'Copied' : 'Copy fingerprint'} icon={copied ? CheckIcon : CopyIcon} size="icon-sm" className="-mt-1.5 size-7" onClick={copy} />
    </span>
  )
}

const Remote = ({ status }: { status: ListenerStatus }) => {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)

  const toggle = async (on: boolean) => {
    const ok = await confirm(
      on
        ? {
            title: 'Allow remote connections?',
            description: `Macs on your network can pair and reconnect over port ${status.port}/tcp. Every connection still needs a paired key, but make sure that port is reachable only from networks you trust.`,
            confirmLabel: 'Allow',
            tone: 'primary',
          }
        : {
            title: 'Turn off remote connections?',
            description: 'Only this machine can pair and connect. Devices connected from other machines disconnect now; they reconnect when you turn this back on.',
            confirmLabel: 'Turn off',
            tone: 'danger',
          },
    )
    if (!ok) return
    setBusy(true)
    setError(null)
    try {
      const data = on ? await api.send('device.remote.enable', null) : await api.send('device.remote.disable', null)
      queryClient.setQueryData(wsKey('device.remote.status', null), data)
      notify.success(on ? 'Remote connections are on' : 'Remote connections are off', 'The listener moved now; no restart needed.')
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-4" data-testid="remote-connections">
      <SwitchRow
        id="device-remote-switch"
        label="Allow remote connections"
        hint={
          status.remote
            ? 'On: Macs on your network can pair and reconnect.'
            : 'Off: only this machine can pair and connect.'
        }
        checked={status.remote}
        disabled={busy || !status.enabled}
        onCheckedChange={on => void toggle(on)}
      />
      <InlineError error={error} />
      {status.error ? (
        <p role="alert" className="flex items-start gap-2 rounded-control border border-warn-line bg-warn-soft px-3 py-2 text-sm text-warn" data-testid="remote-error">
          <TriangleExclamationIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
          <span>
            {status.error}. The daemon retries every 30 seconds; nothing else is affected.
          </span>
        </p>
      ) : null}
      <DefinitionList
        items={[
          ['Status', <span key="s" data-testid="remote-state">{listenerBadge(status)}</span>],
          ['Bind address', <code key="a" className="font-mono text-xs" data-testid="remote-address">{status.address ?? (status.remote ? 'All interfaces' : 'Loopback only')}</code>],
          ['Port', <span key="p" className="tabular" data-testid="remote-port">{status.port}</span>],
          ['Connections', <span key="c" className="tabular">{status.connections}</span>],
          [
            'Server key',
            status.server_spki_sha256 ? <Fingerprint key="f" hex={status.server_spki_sha256} /> : <span key="f" className="text-fg-subtle">Not created yet</span>,
          ],
        ]}
      />
      <p className="text-xs text-fg-subtle">
        The server key fingerprint is what Desktop pins when it pairs. If it ever changes, every device has to pair again.
        {status.enabled ? null : ' The listener is turned off in config.yaml (device_server.enabled).'}
      </p>
    </div>
  )
}
