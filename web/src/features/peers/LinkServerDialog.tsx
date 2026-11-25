'use client'

import React, { useEffect, useRef, useState } from 'react'
import { api } from '@/lib/session'
import { invalidate, useWs } from '@/lib/query'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Dialog, DialogClose, DialogContent } from '@/components/ui/Dialog'
import { Field, Input } from '@/components/ui/Field'
import { Spinner } from '@/components/ui/Spinner'
import { CircleCheckIcon, TriangleExclamationIcon } from '@/components/ui/icons'
import { PEERS_COPY } from '@/features/peers/copy'
import {
  ATTEMPT_TEXT,
  DEFAULT_DEVICE_PORT,
  PEER_READS,
  formatCode,
  groupHex,
  linkFinished,
  parseFingerprint,
  parseLinkTarget,
  shortNodeId,
  type LinkAttempt,
} from '@/features/peers/model'
import { PeerError } from '@/features/peers/parts'

// Link a server (design/peers/link.md, "Pairing", A's side): this server dials the other one, whose Accept a link window
// is open (peer.link.start, the device.trust step-up through the shell's dialog). With the other server's key it
// completes the connection with no other key; without it the key is trusted on first use and the code closes the gap.
// peer.link.status shows the code this server computed, to be picked on the other server, then the outcome. Closing the
// dialog stops an attempt that hasn't finished (peer.link.cancel), as Ctrl-C does for `vh peer link`. Loaded with
// next/dynamic, mounted only while open.

const POLL_MS = 1_500

export default function LinkServerDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const [attempt, setAttempt] = useState<LinkAttempt | null>(null)
  const status = useWs('peer.link.status', { link_id: attempt?.link_id ?? '' }, {
    enabled: !!attempt && !linkFinished(attempt.state),
    refetchInterval: POLL_MS,
    staleTime: 0,
    gcTime: 0,
  })
  const polled = status.data?.link
  const current = polled && attempt && polled.link_id === attempt.link_id && polled.updated_at >= attempt.updated_at ? polled : attempt

  // Keep the latest answer as the attempt: polling stops once it has finished.
  useEffect(() => {
    if (polled && attempt && polled.link_id === attempt.link_id && polled !== attempt && polled.updated_at >= attempt.updated_at) setAttempt(polled)
  }, [polled, attempt])

  const linked = current?.state === 'linked'
  useEffect(() => {
    if (linked) void invalidate(...PEER_READS)
  }, [linked])

  // An attempt still running when the dialog goes away is cancelled (deferred a tick: React's development double-invoke
  // re-runs the effect at once and must not cancel it).
  const running = useRef<string | null>(null)
  running.current = current && !linkFinished(current.state) ? current.link_id : null
  const cancelTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  useEffect(() => {
    if (cancelTimer.current) {
      clearTimeout(cancelTimer.current)
      cancelTimer.current = null
    }
    return () => {
      cancelTimer.current = setTimeout(() => {
        cancelTimer.current = null
        const id = running.current
        if (id) void api.send('peer.link.cancel', { link_id: id }).catch(() => undefined)
      }, 0)
    }
  }, [])

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        size="lg"
        title={PEERS_COPY.linkTitle}
        description={PEERS_COPY.linkDescription}
        data-testid="peer-link-dialog"
        footer={
          <>
            {current && !linkFinished(current.state) ? <span className="mr-auto text-xs text-fg-subtle">{PEERS_COPY.closeStops}</span> : null}
            <DialogClose asChild>
              <Button variant={linked ? 'primary' : 'secondary'}>{linked ? PEERS_COPY.done : PEERS_COPY.close}</Button>
            </DialogClose>
          </>
        }>
        {current ? (
          <Attempt attempt={current} pollError={status.error} onCancelled={setAttempt} onAgain={() => setAttempt(null)} />
        ) : (
          <StartForm onStarted={setAttempt} />
        )}
      </DialogContent>
    </Dialog>
  )
}

const StartForm = ({ onStarted }: { onStarted: (attempt: LinkAttempt) => void }) => {
  // The default port is this server's own device listener port (what `vh peer link <host>` assumes).
  const listener = useWs('device.remote.status', null)
  const ownPort = listener.data?.status.port
  const [address, setAddress] = useState('')
  const [port, setPort] = useState('')
  const [portTouched, setPortTouched] = useState(false)
  const [fingerprint, setFingerprint] = useState('')
  const [submitted, setSubmitted] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)

  const portText = portTouched ? port : String(ownPort ?? DEFAULT_DEVICE_PORT)
  const target = parseLinkTarget(address, portText)
  const key = parseFingerprint(fingerprint)

  const submit = async () => {
    setSubmitted(true)
    if (!target.ok || !key.ok) return
    setBusy(true)
    setError(null)
    try {
      const { link } = await api.send('peer.link.start', {
        endpoints: [{ host: target.value.host, port: target.value.port }],
        ...(key.value ? { expect_spki: key.value } : {}),
      })
      onStarted(link)
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <form
      noValidate
      className="space-y-4"
      data-testid="peer-link-form"
      onSubmit={event => {
        event.preventDefault()
        void submit()
      }}>
      <div className="grid gap-4 sm:grid-cols-[1fr_8rem]">
        <Field label={PEERS_COPY.addressLabel} htmlFor="peer-link-address" hint={PEERS_COPY.addressHint} error={submitted && !target.ok ? target.error : undefined}>
          <Input
            id="peer-link-address"
            value={address}
            autoFocus
            autoComplete="off"
            spellCheck={false}
            placeholder="vps.example.com"
            onChange={event => setAddress(event.target.value)}
            aria-invalid={(submitted && !target.ok) || undefined}
            data-testid="peer-link-address"
          />
        </Field>
        <Field label={PEERS_COPY.portLabel} htmlFor="peer-link-port" hint={PEERS_COPY.portHint}>
          <Input
            id="peer-link-port"
            value={portText}
            inputMode="numeric"
            onChange={event => {
              setPortTouched(true)
              setPort(event.target.value)
            }}
            data-testid="peer-link-port"
          />
        </Field>
      </div>
      <Field label={PEERS_COPY.fingerprintLabel} htmlFor="peer-link-key" hint={PEERS_COPY.fingerprintHint} error={submitted && !key.ok ? key.error : undefined}>
        <Input
          id="peer-link-key"
          value={fingerprint}
          autoComplete="off"
          spellCheck={false}
          className="font-mono text-xs"
          onChange={event => setFingerprint(event.target.value)}
          aria-invalid={(submitted && !key.ok) || undefined}
          data-testid="peer-link-key"
        />
      </Field>
      <PeerError error={error} fallback={PEERS_COPY.notStarted} />
      <div className="flex justify-end">
        <Button type="submit" variant="primary" loading={busy} data-testid="peer-link-start">
          {PEERS_COPY.start}
        </Button>
      </div>
    </form>
  )
}

const Attempt = ({
  attempt,
  pollError,
  onCancelled,
  onAgain,
}: {
  attempt: LinkAttempt
  pollError: unknown
  onCancelled: (attempt: LinkAttempt) => void
  onAgain: () => void
}) => {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const words = ATTEMPT_TEXT[attempt.state]
  const finished = linkFinished(attempt.state)
  const name = attempt.peer?.name || PEERS_COPY.otherServer

  const cancel = async () => {
    setBusy(true)
    setError(null)
    try {
      onCancelled((await api.send('peer.link.cancel', { link_id: attempt.link_id })).link)
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-4" data-testid="peer-link-attempt" data-state={attempt.state}>
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone={words.tone} dot pulse={!finished}>
          <span data-testid="peer-link-state">{words.label}</span>
        </Badge>
        {attempt.address ? <code className="font-mono text-xs text-fg-muted">{attempt.address}</code> : null}
      </div>

      {attempt.peer ? (
        <div className="space-y-1 rounded-card border border-line bg-surface-1 px-4 py-3 text-sm" data-testid="peer-link-peer">
          <p className="text-fg">
            <span className="font-medium" data-testid="peer-link-peer-name">{attempt.peer.name}</span>{' '}
            <span className="text-xs text-fg-subtle">
              {attempt.peer.product_version ? `Vaulthalla ${attempt.peer.product_version} · ` : ''}node{' '}
              <span className="font-mono" title={attempt.peer.node_id}>
                {shortNodeId(attempt.peer.node_id)}
              </span>
            </span>
          </p>
          <p className="text-xs text-fg-subtle">{PEERS_COPY.theirKey}</p>
          <p className="font-mono text-xs break-all text-fg-muted" data-testid="peer-link-peer-key">
            {groupHex(attempt.peer.spki_sha256)}
          </p>
        </div>
      ) : null}

      {attempt.state === 'connecting' ? (
        <p className="flex items-center gap-2 text-sm text-fg-subtle">
          <Spinner className="size-4" />
          {PEERS_COPY.connecting(attempt.address ?? '')}
        </p>
      ) : attempt.state === 'awaiting_approval' && attempt.code ? (
        <div className="rounded-card border border-accent/40 bg-surface-1 px-4 py-5 text-center">
          <p className="text-sm text-fg-muted">{PEERS_COPY.codeIntro}</p>
          <p className="my-2 font-mono text-4xl font-semibold tracking-wider text-fg tabular" data-testid="peer-link-code">
            {formatCode(attempt.code)}
          </p>
          <p className="mx-auto max-w-md text-sm text-fg-subtle">{PEERS_COPY.codeStep(name)}</p>
        </div>
      ) : attempt.state === 'linked' ? (
        <p className="flex items-start gap-2 rounded-control border border-ok-line bg-ok-soft px-3 py-2 text-sm text-ok" data-testid="peer-link-outcome">
          <CircleCheckIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
          {PEERS_COPY.linkedWith(name)}
        </p>
      ) : attempt.state === 'failed' ? (
        <p role="alert" className="flex items-start gap-2 rounded-control border border-danger-line bg-danger-soft px-3 py-2 text-sm text-danger" data-testid="peer-link-outcome">
          <TriangleExclamationIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
          <span className="min-w-0 break-words">
            {PEERS_COPY.linkFailed}
            {attempt.error ? `: ${attempt.error}` : '.'}
          </span>
        </p>
      ) : finished ? (
        <p className="rounded-control border border-line bg-surface-1 px-3 py-2 text-sm text-fg-muted" data-testid="peer-link-outcome">
          {attempt.state === 'denied' ? PEERS_COPY.linkDenied : attempt.state === 'expired' ? PEERS_COPY.linkExpired : PEERS_COPY.linkCancelled}
          {attempt.error && attempt.state !== 'cancelled' ? <span className="mt-1 block text-xs text-fg-subtle">{attempt.error}</span> : null}
        </p>
      ) : null}

      <PeerError error={error ?? pollError} fallback={PEERS_COPY.linkFailed} />

      <div className="flex justify-end gap-2">
        {finished ? (
          attempt.state === 'linked' ? null : (
            <Button variant="secondary" onClick={onAgain} data-testid="peer-link-again">
              {PEERS_COPY.startOver}
            </Button>
          )
        ) : (
          <Button variant="ghost" onClick={() => void cancel()} loading={busy} data-testid="peer-link-cancel">
            {PEERS_COPY.cancel}
          </Button>
        )}
      </div>
    </div>
  )
}
