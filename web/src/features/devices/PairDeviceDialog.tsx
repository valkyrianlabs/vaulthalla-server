'use client'

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import Link from 'next/link'
import { api } from '@/lib/session'
import { invalidate, useWs } from '@/lib/query'
import { useCan } from '@/lib/permissions'
import { errorMessage, isWsError } from '@/lib/ws/errors'
import { Button } from '@/components/ui/Button'
import { Dialog, DialogClose, DialogContent } from '@/components/ui/Dialog'
import { Spinner } from '@/components/ui/Spinner'
import { InlineError } from '@/components/ui/State'
import { CircleCheckIcon, CircleInfoIcon, ClockIcon, TriangleExclamationIcon, XmarkIcon } from '@/components/ui/icons'
import { cn } from '@/util/cn'
import type { Device } from '@/models/device'
import {
  DEVICE_READS,
  deviceLabel,
  formatCode,
  platformLabel,
  shortDeviceId,
  type PairingWindow,
  type PendingRequest,
} from '@/features/devices/model'

// Pair a device by number matching (docs/pairing.md §3 in vaulthalla/desktop). Opening the dialog opens this account's
// pairing window on the node; requests from Vaulthalla Desktop appear with three codes, one of them the code the Mac
// shows. Clicking the matching one approves the request, any other declines it (the daemon decides; the real code
// never reaches the browser). Closing the dialog closes the window. Loaded with next/dynamic, mounted only while open.

const POLL_MS = 2_000

type Phase = 'opening' | 'open' | 'conflict' | 'error'
type Notice = { tone: 'danger' | 'info'; text: string }

const WRONG_CODE = 'That code didn’t match, so the request was declined. Start pairing again on the Mac.'
const EXPIRED_REQUEST = 'That request expired before it was approved. Start pairing again on the Mac.'

const useNow = (active: boolean) => {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!active) return
    setNow(Date.now())
    const timer = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(timer)
  }, [active])
  return now
}

const formatRemaining = (seconds: number) => {
  const s = Math.max(0, Math.floor(seconds))
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`
}

export default function PairDeviceDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const superAdmin = useCan({ superAdmin: true })
  const [phase, setPhase] = useState<Phase>('opening')
  const [window_, setWindow] = useState<PairingWindow | null>(null)
  const [failure, setFailure] = useState<unknown>(null)
  const [paired, setPaired] = useState<Device | null>(null)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  // Requests this dialog already approved, declined or saw expire: hidden at once, before the next poll drops them.
  const [handled, setHandled] = useState<Set<string>>(() => new Set())

  // Whether this dialog opened the window it is showing: only then does closing the dialog close it. A super admin's
  // device.pairing.close closes anyone's window, so a dialog that got `conflict` must never send it.
  const owns = useRef(false)
  const alive = useRef(true)
  const closeTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  // When the window was (re)opened: polls answered before that describe an older window.
  const openedAt = useRef(0)

  const openWindow = useCallback(async () => {
    try {
      const { window } = await api.send('device.pairing.open', null)
      if (!alive.current) {
        // Dismissed while the open was in flight: don't leave a window behind.
        void api.send('device.pairing.close', null).catch(() => undefined)
        return
      }
      owns.current = true
      openedAt.current = Date.now()
      setWindow(window)
      setPhase('open')
    } catch (error) {
      if (!alive.current) return
      setFailure(error)
      setPhase(isWsError(error, 'conflict') ? 'conflict' : 'error')
    }
  }, [])

  useEffect(() => {
    alive.current = true
    // React's development double-invoke re-runs this effect at once: keep the window instead of closing and reopening.
    if (closeTimer.current) {
      clearTimeout(closeTimer.current)
      closeTimer.current = null
    } else {
      void openWindow()
    }
    return () => {
      closeTimer.current = setTimeout(() => {
        closeTimer.current = null
        alive.current = false
        if (owns.current) {
          owns.current = false
          void api.send('device.pairing.close', null).catch(() => undefined)
        }
      }, 0)
    }
  }, [openWindow])

  const retry = () => {
    setFailure(null)
    setNotice(null)
    setPhase('opening')
    void openWindow()
  }

  const polling = phase === 'open' && !paired
  const pending = useWs('device.pairing.pending', null, { enabled: polling, refetchInterval: POLL_MS, staleTime: 0, gcTime: 0 })
  // The poll carries the window too (a reopen from the CLI extends it; a super admin may close it).
  const liveWindow = pending.data && pending.dataUpdatedAt >= openedAt.current ? pending.data.window : window_
  const now = useNow(phase === 'open')
  const remaining = liveWindow ? liveWindow.expires_at - now / 1000 : 0
  const expired = phase === 'open' && (!liveWindow || remaining <= 0)

  // An expired window is not ours to close any more (another user may open the next one).
  useEffect(() => {
    if (expired) owns.current = false
  }, [expired])

  const requests = useMemo(
    () => (pending.data?.requests ?? []).filter(r => !handled.has(r.request_id)),
    [pending.data, handled],
  )
  const hide = (request: PendingRequest) => setHandled(current => new Set(current).add(request.request_id))

  const approve = async (request: PendingRequest, code: string) => {
    setBusy(request.request_id)
    setNotice(null)
    try {
      const { device } = await api.send('device.pairing.approve', { request_id: request.request_id, code })
      hide(request)
      setPaired(device)
      void invalidate(...DEVICE_READS)
    } catch (error) {
      if (isWsError(error, 'invalid')) {
        hide(request)
        setNotice({ tone: 'danger', text: WRONG_CODE })
      } else if (isWsError(error, 'not_found')) {
        hide(request)
        setNotice({ tone: 'danger', text: EXPIRED_REQUEST })
      } else {
        setNotice({ tone: 'danger', text: errorMessage(error, 'The request was not approved') })
      }
    } finally {
      setBusy(null)
      void pending.refetch()
    }
  }

  const deny = async (request: PendingRequest) => {
    setBusy(request.request_id)
    setNotice(null)
    try {
      await api.send('device.pairing.deny', { request_id: request.request_id })
      hide(request)
      setNotice({ tone: 'info', text: `Declined the request from ${request.name}.` })
    } catch (error) {
      if (isWsError(error, 'not_found')) hide(request)
      else setNotice({ tone: 'danger', text: errorMessage(error, 'The request was not declined') })
    } finally {
      setBusy(null)
      void pending.refetch()
    }
  }

  const reopen = () => {
    setHandled(new Set())
    setNotice(null)
    setWindow(null)
    retry()
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        size="lg"
        title="Pair a device"
        description="Approve Vaulthalla Desktop on your Mac by matching the code it shows. No passwords, keys or certificates."
        data-testid="pair-dialog"
        footer={
          <>
            {phase === 'open' && liveWindow && !expired ? (
              <span className="mr-auto flex items-center gap-1.5 text-sm text-fg-subtle" data-testid="pair-countdown">
                <ClockIcon className="size-4" aria-hidden />
                Pairing stays open for <span className="tabular text-fg">{formatRemaining(remaining)}</span>
              </span>
            ) : null}
            <DialogClose asChild>
              <Button variant={paired ? 'primary' : 'secondary'}>{paired ? 'Done' : 'Close'}</Button>
            </DialogClose>
          </>
        }>
        {phase === 'opening' ? (
          <div className="flex items-center justify-center gap-3 py-12 text-sm text-fg-subtle">
            <Spinner className="size-5" label="Opening a pairing window" />
            Opening a pairing window…
          </div>
        ) : phase === 'conflict' ? (
          <Conflict detail={errorMessage(failure)} onRetry={retry} />
        ) : phase === 'error' ? (
          <div className="space-y-4 py-4">
            <InlineError error={failure} />
            <Button onClick={retry}>Try again</Button>
          </div>
        ) : paired ? (
          <Paired device={paired} onAnother={() => setPaired(null)} />
        ) : expired ? (
          <div className="flex flex-col items-center py-10 text-center" data-testid="pair-expired">
            <ClockIcon className="mb-3 size-6 text-fg-subtle" aria-hidden />
            <p className="font-medium text-fg">The pairing window closed</p>
            <p className="mt-1 max-w-sm text-sm text-fg-subtle">Requests that weren’t approved expired with it. Open it again to keep pairing.</p>
            <Button className="mt-5" variant="primary" onClick={reopen} data-testid="pair-reopen">
              Open again
            </Button>
          </div>
        ) : (
          <div className="space-y-5">
            <Instructions superAdmin={superAdmin} />
            {notice ? (
              <p
                role={notice.tone === 'danger' ? 'alert' : 'status'}
                data-testid="pair-notice"
                className={cn(
                  'flex items-start gap-2 rounded-control border px-3 py-2 text-sm',
                  notice.tone === 'danger' ? 'border-danger-line bg-danger-soft text-danger' : 'border-line bg-surface-1 text-fg-muted',
                )}>
                {notice.tone === 'danger' ? (
                  <TriangleExclamationIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
                ) : (
                  <CircleInfoIcon className="mt-0.5 size-4 shrink-0 text-accent-text" aria-hidden />
                )}
                {notice.text}
              </p>
            ) : null}
            {pending.error && !pending.data ? <InlineError error={pending.error} /> : null}
            {requests.length ? (
              <ul className="space-y-3" aria-label="Pairing requests">
                {requests.map(request => (
                  <RequestCard
                    key={request.request_id}
                    request={request}
                    busy={busy === request.request_id}
                    disabled={busy !== null}
                    onPick={code => void approve(request, code)}
                    onDeny={() => void deny(request)}
                  />
                ))}
              </ul>
            ) : (
              <div className="flex items-center gap-3 rounded-card border border-dashed border-line px-4 py-6 text-sm text-fg-subtle" data-testid="pair-waiting">
                <Spinner className="size-4" />
                Waiting for a request from Vaulthalla Desktop…
              </div>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}

const Instructions = ({ superAdmin }: { superAdmin: boolean }) => {
  // Only super admins may read the listener's settings; everyone else gets the steps without the port.
  const status = useWs('device.remote.status', null, { enabled: superAdmin })
  const listener = status.data?.status
  const host = typeof window === 'undefined' ? '' : window.location.hostname
  const local = ['localhost', '127.0.0.1', '::1', '[::1]'].includes(host)
  return (
    <div className="rounded-card border border-line bg-surface-1 px-4 py-3 text-sm" data-testid="pair-instructions">
      <ol className="list-decimal space-y-1.5 pl-5 text-fg-muted marker:text-fg-subtle">
        <li>
          <span className="text-fg">In Vaulthalla Desktop, add this server and choose Pair.</span>
          {host ? (
            <span className="ml-1">
              Server:{' '}
              <code className="font-mono text-xs text-fg" data-testid="pair-server-address">
                {host}
                {listener ? `:${listener.port}` : ''}
              </code>
            </span>
          ) : null}
        </li>
        <li>The Mac shows a six-digit code. Click the same code on its request below.</li>
        <li>A wrong code declines the request, so compare before you click.</li>
      </ol>
      {listener && !listener.remote && !local ? (
        <p className="mt-3 flex items-start gap-2 text-warn" data-testid="pair-remote-off">
          <TriangleExclamationIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
          <span>
            Remote connections are off, so only Vaulthalla Desktop on this server itself can pair.{' '}
            <Link href="/devices/all#remote-connections" className="underline underline-offset-2 hover:text-fg">
              Turn them on
            </Link>{' '}
            to pair a Mac on your network.
          </span>
        </p>
      ) : listener && listener.enabled && !listener.listening ? (
        <p className="mt-3 flex items-start gap-2 text-warn">
          <TriangleExclamationIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
          <span>The device listener isn’t listening{listener.error ? `: ${listener.error}` : ''}.</span>
        </p>
      ) : !superAdmin ? (
        <p className="mt-3 text-xs text-fg-subtle">If Desktop can’t reach this server, ask an administrator to turn on remote connections.</p>
      ) : null}
    </div>
  )
}

const RequestCard = ({
  request,
  busy,
  disabled,
  onPick,
  onDeny,
}: {
  request: PendingRequest
  busy: boolean
  disabled: boolean
  onPick: (code: string) => void
  onDeny: () => void
}) => (
  <li className="rounded-card border border-line bg-surface-1 p-4" data-testid="pair-request" data-request-id={request.request_id}>
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <p className="truncate font-medium text-fg" data-testid="pair-request-name">
          {request.name}
        </p>
        <p className="mt-0.5 text-xs text-fg-subtle">
          {platformLabel(request.platform, request.app_version)} · from{' '}
          <span className="font-mono text-fg-muted">{request.source_ip}</span> · device{' '}
          <span className="font-mono text-fg-muted" title={request.device_id}>
            {shortDeviceId(request.device_id)}
          </span>
        </p>
      </div>
      <Button size="sm" variant="ghost" onClick={onDeny} disabled={disabled} data-testid="pair-deny">
        <XmarkIcon aria-hidden />
        Deny
      </Button>
    </div>
    <p className="mt-4 mb-2 text-sm text-fg-muted">Which code does the Mac show?</p>
    <div className="grid grid-cols-1 gap-2 sm:grid-cols-3" role="group" aria-label={`Codes for ${request.name}`}>
      {request.code_choices.map(code => (
        <Button
          key={code}
          variant="secondary"
          size="lg"
          className="h-16 font-mono text-2xl tracking-wider tabular hover:border-accent"
          disabled={disabled}
          onClick={() => onPick(code)}
          data-testid="pair-code">
          {formatCode(code)}
        </Button>
      ))}
    </div>
    {busy ? (
      <p className="mt-2 flex items-center gap-2 text-xs text-fg-subtle">
        <Spinner className="size-3.5" /> Checking…
      </p>
    ) : null}
  </li>
)

const Conflict = ({ detail, onRetry }: { detail: string; onRetry: () => void }) => (
  <div className="flex flex-col items-center py-10 text-center" data-testid="pair-conflict">
    <ClockIcon className="mb-3 size-6 text-warn" aria-hidden />
    <p className="font-medium text-fg">Someone else is pairing a device</p>
    <p className="mt-1 max-w-md text-sm text-fg-subtle">
      Another user on this server has pairing open, and only one can be open at a time. Try again when they’re done.
    </p>
    {detail ? <p className="mt-2 max-w-md text-xs text-fg-faint">{detail}</p> : null}
    <Button className="mt-5" onClick={onRetry} data-testid="pair-retry">
      Try again
    </Button>
  </div>
)

const Paired = ({ device, onAnother }: { device: Device; onAnother: () => void }) => (
  <div className="flex flex-col items-center py-10 text-center" data-testid="pair-success">
    <div className="mb-4 grid size-12 place-items-center rounded-2xl border border-ok-line bg-ok-soft text-ok">
      <CircleCheckIcon className="size-6" aria-hidden />
    </div>
    <p className="text-lg font-semibold text-fg">Paired</p>
    <p className="mt-1 max-w-sm text-sm text-fg-subtle">
      <span className="text-fg">{deviceLabel(device)}</span> is now paired with your account. Desktop finishes connecting on its own.
    </p>
    <Button className="mt-5" variant="ghost" onClick={onAnother} data-testid="pair-another">
      Pair another device
    </Button>
  </div>
)
