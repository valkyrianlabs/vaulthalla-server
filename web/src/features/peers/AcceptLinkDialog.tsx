'use client'

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import Link from 'next/link'
import { api } from '@/lib/session'
import { invalidate, useWs } from '@/lib/query'
import type { Response } from '@/lib/ws/client'
import { isWsError } from '@/lib/ws/errors'
import { Button } from '@/components/ui/Button'
import { Dialog, DialogClose, DialogContent } from '@/components/ui/Dialog'
import { Spinner } from '@/components/ui/Spinner'
import { CircleCheckIcon, CircleInfoIcon, ClockIcon, TriangleExclamationIcon, XmarkIcon } from '@/components/ui/icons'
import { cn } from '@/util/cn'
import { PEERS_COPY } from '@/features/peers/copy'
import {
  PEER_READS,
  codeChoices,
  formatRemaining,
  groupHex,
  hostPort,
  peerLabel,
  secondsLeft,
  shortNodeId,
  type PeerWindow,
  type PendingLink,
} from '@/features/peers/model'
import { CopyButton, PeerError } from '@/features/peers/parts'

// Accept a link (design/peers/link.md, "Pairing", B's side): opening the dialog opens a 10-minute window
// (peer.pairing.open, node-wide with device pairing), shows what the other server needs (this server's addresses and
// key) and lists the servers that asked (peer.pairing.pending), each with three codes, one of them the code the
// dialling server shows. Clicking the matching one approves (peer.pairing.approve, the device.trust step-up through the
// shell's dialog), any other declines it; the real code never reaches the browser. Closing the dialog closes the window
// if this dialog opened it. Loaded with next/dynamic, mounted only while open.

const POLL_MS = 2_000

type Phase = 'opening' | 'open' | 'conflict' | 'error'
type Notice = { tone: 'danger' | 'info'; text: string }
type LinkedRow = Response<'peer.pairing.approve'>['peer']

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

export default function AcceptLinkDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const [phase, setPhase] = useState<Phase>('opening')
  const [opened, setOpened] = useState<PeerWindow | null>(null)
  // The node's clock minus the browser's (ms) when the window was opened: the countdown never trusts the browser's clock.
  const [openSkew, setOpenSkew] = useState(0)
  const [failure, setFailure] = useState<unknown>(null)
  const [linked, setLinked] = useState<LinkedRow | null>(null)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [busy, setBusy] = useState<string | null>(null)
  // Requests this dialog approved, declined or saw expire: hidden at once, before the next poll drops them.
  const [handled, setHandled] = useState<Set<string>>(() => new Set())

  // Whether this dialog opened the window it shows: only then does closing the dialog close it.
  const owns = useRef(false)
  const alive = useRef(true)
  const closeTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  // When the window was (re)opened: polls answered before that describe an older window.
  const openedAt = useRef(0)

  const openWindow = useCallback(async () => {
    try {
      const answer = await api.send('peer.pairing.open', null)
      if (!alive.current) {
        // Dismissed while the open was in flight: don't leave a window behind.
        void api.send('peer.pairing.close', null).catch(() => undefined)
        return
      }
      owns.current = true
      openedAt.current = Date.now()
      setOpenSkew(answer.server_time * 1000 - openedAt.current)
      setOpened(answer)
      setPhase('open')
    } catch (err) {
      if (!alive.current) return
      setFailure(err)
      setPhase(isWsError(err, 'conflict') ? 'conflict' : 'error')
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
          void api.send('peer.pairing.close', null).catch(() => undefined)
        }
      }, 0)
    }
  }, [openWindow])

  const retry = () => {
    setFailure(null)
    setNotice(null)
    setError(null)
    setPhase('opening')
    void openWindow()
  }

  const polling = phase === 'open' && !linked
  const pending = useWs('peer.pairing.pending', null, { enabled: polling, refetchInterval: POLL_MS, staleTime: 0, gcTime: 0 })
  const fresh = pending.data && pending.dataUpdatedAt >= openedAt.current ? pending.data : null
  const liveWindow = fresh ? fresh.window : (opened?.window ?? null)
  // Count down by the node's clock: each answer carries server_time, so the offset follows the latest one.
  const skew = fresh ? fresh.server_time * 1000 - pending.dataUpdatedAt : openSkew
  const now = useNow(phase === 'open')
  const remaining = secondsLeft(liveWindow?.expires_at, now, skew)
  const expired = phase === 'open' && !linked && remaining <= 0

  // An expired window is not ours to close any more (another admin may open the next one).
  useEffect(() => {
    if (expired) owns.current = false
  }, [expired])

  const requests = useMemo(() => (pending.data?.requests ?? []).filter(r => !handled.has(r.request_id)), [pending.data, handled])
  const hide = (request: PendingLink) => setHandled(current => new Set(current).add(request.request_id))

  const approve = async (request: PendingLink, code: string) => {
    setBusy(request.request_id)
    setNotice(null)
    setError(null)
    try {
      const { peer } = await api.send('peer.pairing.approve', { request_id: request.request_id, code })
      hide(request)
      // The server closed the window when it approved.
      owns.current = false
      setLinked(peer)
      void invalidate(...PEER_READS)
    } catch (err) {
      if (isWsError(err, 'invalid')) {
        hide(request)
        setNotice({ tone: 'danger', text: PEERS_COPY.wrongCode })
      } else if (isWsError(err, 'not_found')) {
        hide(request)
        setNotice({ tone: 'danger', text: PEERS_COPY.expiredRequest })
      } else {
        setError(err)
      }
    } finally {
      setBusy(null)
      void pending.refetch()
    }
  }

  const deny = async (request: PendingLink) => {
    setBusy(request.request_id)
    setNotice(null)
    setError(null)
    try {
      await api.send('peer.pairing.deny', { request_id: request.request_id })
      hide(request)
      setNotice({ tone: 'info', text: PEERS_COPY.declined(request.name) })
    } catch (err) {
      if (isWsError(err, 'not_found')) hide(request)
      else setError(err)
    } finally {
      setBusy(null)
      void pending.refetch()
    }
  }

  const reopen = () => {
    setHandled(new Set())
    setOpened(null)
    retry()
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        size="lg"
        title={PEERS_COPY.acceptTitle}
        description={PEERS_COPY.acceptDescription}
        data-testid="peer-accept-dialog"
        footer={
          <>
            {phase === 'open' && !linked && !expired ? (
              <span className="mr-auto flex items-center gap-1.5 text-sm text-fg-subtle" data-testid="peer-accept-countdown">
                <ClockIcon className="size-4" aria-hidden />
                {PEERS_COPY.windowLeft} <span className="tabular text-fg">{formatRemaining(remaining)}</span>
              </span>
            ) : null}
            <DialogClose asChild>
              <Button variant={linked ? 'primary' : 'secondary'}>{linked ? PEERS_COPY.done : PEERS_COPY.close}</Button>
            </DialogClose>
          </>
        }>
        {phase === 'opening' ? (
          <div className="flex items-center justify-center gap-3 py-12 text-sm text-fg-subtle">
            <Spinner className="size-5" label={PEERS_COPY.opening} />
            {PEERS_COPY.opening}
          </div>
        ) : phase === 'conflict' ? (
          <div className="flex flex-col items-center py-10 text-center" data-testid="peer-accept-conflict">
            <ClockIcon className="mb-3 size-6 text-warn" aria-hidden />
            <p className="font-medium text-fg">{PEERS_COPY.conflictTitle}</p>
            <p className="mt-1 max-w-md text-sm text-fg-subtle">{PEERS_COPY.conflictBody}</p>
            <PeerError error={failure} fallback={PEERS_COPY.conflictTitle} className="mt-3 max-w-md text-left" />
            <Button className="mt-5" onClick={retry} data-testid="peer-accept-retry">
              {PEERS_COPY.tryAgain}
            </Button>
          </div>
        ) : phase === 'error' ? (
          <div className="space-y-4 py-4">
            <PeerError error={failure} fallback={PEERS_COPY.notApproved} />
            <Button onClick={retry}>{PEERS_COPY.tryAgain}</Button>
          </div>
        ) : linked ? (
          <div className="flex flex-col items-center py-10 text-center" data-testid="peer-accept-linked">
            <div className="mb-4 grid size-12 place-items-center rounded-2xl border border-ok-line bg-ok-soft text-ok">
              <CircleCheckIcon className="size-6" aria-hidden />
            </div>
            <p className="text-lg font-semibold text-fg">{PEERS_COPY.linkedTitle}</p>
            <p className="mt-1 max-w-sm text-sm text-fg-subtle">{PEERS_COPY.linkedBody(peerLabel(linked))}</p>
          </div>
        ) : expired ? (
          <div className="flex flex-col items-center py-10 text-center" data-testid="peer-accept-expired">
            <ClockIcon className="mb-3 size-6 text-fg-subtle" aria-hidden />
            <p className="font-medium text-fg">{PEERS_COPY.windowClosedTitle}</p>
            <p className="mt-1 max-w-sm text-sm text-fg-subtle">{PEERS_COPY.windowClosedBody}</p>
            <Button className="mt-5" variant="primary" onClick={reopen} data-testid="peer-accept-reopen">
              {PEERS_COPY.openAgain}
            </Button>
          </div>
        ) : opened ? (
          <div className="space-y-5">
            <ThisServer opened={opened} />
            {notice ? (
              <p
                role={notice.tone === 'danger' ? 'alert' : 'status'}
                data-testid="peer-accept-notice"
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
            <PeerError error={error} fallback={PEERS_COPY.notApproved} />
            {pending.error && !pending.data ? <PeerError error={pending.error} fallback={PEERS_COPY.notApproved} /> : null}
            {requests.length ? (
              <ul className="space-y-3" aria-label="Link requests">
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
              <div className="flex items-center gap-3 rounded-card border border-dashed border-line px-4 py-6 text-sm text-fg-subtle" data-testid="peer-accept-waiting">
                <Spinner className="size-4" />
                {PEERS_COPY.waiting}
              </div>
            )}
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  )
}

// What the other server's admin needs: where to dial, and the key to pin if they want no trust on first use.
const ThisServer = ({ opened }: { opened: PeerWindow }) => {
  const host = typeof window === 'undefined' ? '' : window.location.hostname
  const local = ['localhost', '127.0.0.1', '::1', '[::1]'].includes(host)
  const candidates = opened.endpoints.candidates
  return (
    <div className="space-y-3 rounded-card border border-line bg-surface-1 px-4 py-3 text-sm" data-testid="peer-accept-this-server">
      <p className="text-fg">
        <span className="text-fg-subtle">{PEERS_COPY.thisServer}:</span> <span className="font-medium" data-testid="peer-accept-name">{opened.name}</span>{' '}
        <span className="font-mono text-xs text-fg-subtle" title={opened.node_id}>
          {shortNodeId(opened.node_id)}
        </span>
      </p>
      <div>
        <p className="mb-1 text-xs text-fg-subtle">{PEERS_COPY.thisKey}</p>
        <div className="flex items-start gap-1">
          <code className="min-w-0 flex-1 font-mono text-xs break-all text-fg-muted" data-testid="peer-accept-key">
            {groupHex(opened.spki_sha256)}
          </code>
          <CopyButton text={opened.spki_sha256} label="Copy this server’s key" className="-mt-1" />
        </div>
      </div>
      <div>
        <p className="mb-1 text-xs text-fg-subtle">{PEERS_COPY.thisAddresses}</p>
        {candidates.length ? (
          <div className="flex items-start gap-1">
            <ul className="flex min-w-0 flex-1 flex-wrap gap-1.5" aria-label="This server’s addresses">
              {candidates.map(c => (
                <li key={hostPort(c)} title={c.kind}>
                  <code className="rounded border border-line bg-surface-2 px-1.5 py-0.5 font-mono text-xs break-all text-fg-muted" data-testid="peer-accept-endpoint">
                    {hostPort(c)}
                  </code>
                </li>
              ))}
            </ul>
            <CopyButton text={candidates.map(hostPort).join('\n')} label="Copy addresses" className="-mt-1" />
          </div>
        ) : (
          <p className="text-xs text-fg-subtle">{PEERS_COPY.noAddresses}</p>
        )}
      </div>
      <ol className="list-decimal space-y-1.5 pl-5 text-fg-muted marker:text-fg-subtle" data-testid="peer-accept-steps">
        {PEERS_COPY.acceptSteps.map(step => (
          <li key={step}>{step}</li>
        ))}
      </ol>
      {!opened.endpoints.remote && !local ? (
        <p className="flex items-start gap-2 text-warn" data-testid="peer-accept-remote-off">
          <TriangleExclamationIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
          <span>
            {PEERS_COPY.remoteOff}{' '}
            <Link href="/devices/all#remote-connections" className="underline underline-offset-2 hover:text-fg">
              {PEERS_COPY.remoteOffLink}
            </Link>{' '}
            {PEERS_COPY.remoteOffAfter}
          </span>
        </p>
      ) : !opened.endpoints.listening ? (
        <p className="flex items-start gap-2 text-warn" data-testid="peer-accept-not-listening">
          <TriangleExclamationIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
          <span>{PEERS_COPY.notListening}</span>
        </p>
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
  request: PendingLink
  busy: boolean
  disabled: boolean
  onPick: (code: string) => void
  onDeny: () => void
}) => (
  <li className="rounded-card border border-line bg-surface-1 p-4" data-testid="peer-request" data-request-id={request.request_id}>
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <p className="truncate font-medium text-fg" data-testid="peer-request-name">
          {request.name}
        </p>
        <p className="mt-0.5 text-xs text-fg-subtle">
          {request.product_version ? `Vaulthalla ${request.product_version} · ` : ''}
          {PEERS_COPY.requestFrom(request.source_ip)} · node{' '}
          <span className="font-mono text-fg-muted" title={request.node_id}>
            {shortNodeId(request.node_id)}
          </span>
        </p>
        <p className="mt-1 font-mono text-xs break-all text-fg-muted" title="Its key" data-testid="peer-request-key">
          {groupHex(request.spki_sha256)}
        </p>
      </div>
      <Button size="sm" variant="ghost" onClick={onDeny} disabled={disabled} data-testid="peer-request-deny">
        <XmarkIcon aria-hidden />
        {PEERS_COPY.deny}
      </Button>
    </div>
    <p className="mt-4 mb-2 text-sm text-fg-muted">{PEERS_COPY.whichCode}</p>
    <div className="grid grid-cols-1 gap-2 sm:grid-cols-3" role="group" aria-label={PEERS_COPY.codesFor(request.name)}>
      {codeChoices(request).map(choice => (
        <Button
          key={choice.code}
          variant="secondary"
          size="lg"
          className="h-16 font-mono text-2xl tracking-wider tabular hover:border-accent"
          disabled={disabled}
          onClick={() => onPick(choice.code)}
          data-testid="peer-request-code">
          {choice.label}
        </Button>
      ))}
    </div>
    {busy ? (
      <p className="mt-2 flex items-center gap-2 text-xs text-fg-subtle">
        <Spinner className="size-3.5" /> {PEERS_COPY.checking}
      </p>
    ) : null}
  </li>
)
