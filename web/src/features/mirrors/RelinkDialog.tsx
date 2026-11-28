'use client'

import React, { useEffect, useId, useRef, useState } from 'react'
import { useWs, useWsMutation } from '@/lib/query'
import { formatInt } from '@/lib/format'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { Dialog, DialogClose, DialogContent } from '@/components/ui/Dialog'
import { Field, Input, Select } from '@/components/ui/Field'
import { Skeleton } from '@/components/ui/State'
import { notify } from '@/components/ui/Toast'
import { TriangleExclamationIcon } from '@/components/ui/icons'
import { PeerError } from '@/features/peers/parts'
import { MIRROR_READS, peerName, type MirroredVault } from '@/features/mirrors/model'
import { usePeers } from '@/features/mirrors/queries'
import {
  AWAITING_OTHER,
  DRIFT_KINDS,
  canKeepBoth,
  choicePayload,
  choiceText,
  coreName,
  countLines,
  gainsText,
  kindPayload,
  kindText,
  phaseText,
  winnerOf,
  type Choice,
  type DriftKind,
  type RelinkStatus,
} from '@/features/mirrors/relink'

const PAGE = 50
const RELINK_READS = ['mirror.relink.get', 'mirror.relink.entries'] as const
const ENDED = ['done', 'failed', 'stale', 'cancelled', 'declined', 'expired']

type Step = 'summary' | 'review' | 'confirm'

// Reconnect a vault both servers hold since their mirror ended (detached, orphaned, rejoining, forked): mirror.relink.*.
// Both servers agree, each by a super admin: opening asks the other server, and the dialog waits ("waiting for the other
// server's admin") until its admin accepts, then compares the two trees, shows the drift, and offers the two hard
// overrides (one server's tree wins everywhere) and the step-through (a choice per entry, in bulk by kind, the plan's
// gains and losses). Applying names the winning server and asks for the vault's name (the keys step-up runs through the
// shell's dialog); it proposes the outcome, which the other server's admin approves before anything changes, and this
// server then carries it out. Loaded with next/dynamic, mounted while open.
export default function RelinkDialog({ row, open, onOpenChange }: { row: MirroredVault; open: boolean; onOpenChange: (open: boolean) => void }) {
  const ids = useId()
  const { byId, linked } = usePeers()
  const own = row.peer && !row.peer.revoked ? row.peer.id : (linked.find(p => p.node_id === row.peer?.node_id)?.id ?? null)
  const [peerId, setPeerId] = useState<number | null>(own)
  const peer = peerId ? (byId.get(peerId)?.name ?? peerName(row)) : peerName(row)
  const [step, setStep] = useState<Step>('summary')
  const [keep, setKeep] = useState<'this' | 'theirs' | null>(null)
  const [typed, setTyped] = useState('')
  const [kind, setKind] = useState<DriftKind | ''>('')
  const [offset, setOffset] = useState(0)

  const status = useWs('mirror.relink.get', { vault_id: row.vault_id }, {
    enabled: open,
    refetchInterval: q => (phaseText(q.state.data as RelinkStatus | undefined).running ? 2_000 : false),
  })
  const s = status.data
  const phase = phaseText(s, peer)
  const isOpen = s?.relink?.phase === 'open' && s.relink.side === 'initiator'

  const compare = useWsMutation<'mirror.relink.compare', void>('mirror.relink.compare', {
    toPayload: () => ({ vault_id: row.vault_id, peer: String(peerId ?? '') }),
    invalidates: [...RELINK_READS],
  })
  // Asked (and compared) once on open when there is no relink to show, and compared once the other server's admin
  // accepted (a relink waiting or running is shown as it is).
  const relinkPhase = s?.relink?.phase
  const relinkSide = s?.relink?.side
  const relinkKey = s?.relink ? `${s.relink.relink_uid}:${relinkPhase}` : 'none'
  const comparedFor = useRef<string | null>(null)
  useEffect(() => {
    if (!open || !status.isSuccess || !peerId || compare.isPending || comparedFor.current === relinkKey) return
    const fresh = (!relinkPhase || ENDED.includes(relinkPhase)) && !compare.isSuccess && !compare.isError
    const accepted = relinkPhase === 'accepted' && relinkSide === 'initiator'
    if (!fresh && !accepted) return
    comparedFor.current = relinkKey
    compare.mutate()
  }, [open, status.isSuccess, relinkPhase, relinkSide, relinkKey, peerId, compare])
  const waiting = relinkSide === 'initiator' && !!relinkPhase && AWAITING_OTHER.includes(relinkPhase)

  const plan = useWsMutation<'mirror.relink.plan', Record<string, unknown>>('mirror.relink.plan', {
    toPayload: edit => ({ vault_id: row.vault_id, ...edit }),
    invalidates: [...RELINK_READS],
  })
  const apply = useWsMutation<'mirror.relink.apply', void>('mirror.relink.apply', {
    toPayload: () => ({ vault_id: row.vault_id, confirm: typed, ...(keep ? { keep, peer: String(peerId ?? '') } : {}) }),
    invalidates: [...RELINK_READS, ...MIRROR_READS, 'storage.vault.list', 'storage.vault.get'],
    onSuccess: data => {
      if (data.relink?.phase === 'proposed' || data.relink?.phase === 'requested')
        notify.info(`Waiting for ${peer}’s admin`, `Nothing changes on either server until ${peer}’s admin approves; this server carries it out then.`)
      else notify.success(`Relinking “${row.vault_name}” with ${peer}`, 'The vault is read-only here until the copy completes.')
      setStep('summary')
      setTyped('')
    },
  })
  const entries = useWs('mirror.relink.entries', { vault_id: row.vault_id, ...(kind ? { kind } : {}), offset, limit: PAGE }, {
    enabled: open && step === 'review' && isOpen,
  })

  const core = (s?.plan?.core ?? 'this') as 'this' | 'theirs'
  const winner = keep ?? core
  const blockers = s?.blockers ?? []
  const lines = countLines(s?.counts, peer)
  const total = Number((s?.counts as Record<string, number> | undefined)?.total ?? 0)
  const ready = typed === row.vault_name && !apply.isPending && blockers.length === 0
  const toConfirm = (which: 'this' | 'theirs' | null) => {
    setKeep(which)
    setTyped('')
    setStep('confirm')
  }

  const footer =
    step === 'confirm' ?
      <>
        <Button variant="ghost" onClick={() => setStep(keep ? 'summary' : 'review')} disabled={apply.isPending}>
          Back
        </Button>
        <Button variant="danger-solid" loading={apply.isPending} disabled={!ready} onClick={() => apply.mutate()} data-testid="mirror-relink-confirm">
          {keep ? `Keep ${coreName(keep, peer)}’s tree` : 'Apply the plan'}
        </Button>
      </>
    : <DialogClose asChild>
        <Button variant="secondary">Close</Button>
      </DialogClose>

  return (
    <Dialog open={open} onOpenChange={next => (apply.isPending ? undefined : onOpenChange(next))}>
      <DialogContent
        title={`Reconnect “${row.vault_name}”`}
        description={`Mirror it again with ${peer} and resolve how the two copies drifted. Nothing is dropped: the losing versions are kept as held changes or conflict copies.`}
        size="lg"
        footer={footer}
        data-testid="mirror-relink-dialog">
        <div className="space-y-4">
          {!own ?
            <Field label="Linked server" htmlFor={`${ids}-peer`}>
              <Select id={`${ids}-peer`} value={peerId ?? ''} onChange={e => setPeerId(Number(e.target.value) || null)}>
                <option value="">Choose…</option>
                {linked.map(p => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </Select>
            </Field>
          : null}

          {!s || compare.isPending ?
            <div className="space-y-2" aria-busy="true" aria-label="Comparing">
              <Skeleton />
              <Skeleton className="w-2/3" />
            </div>
          : <>
              <div className="flex flex-wrap items-center gap-2" data-testid="mirror-relink-phase">
                <Badge tone={phase.tone} dot>
                  {phase.text}
                </Badge>
                {!phase.running && relinkSide !== 'responder' ?
                  <Button variant="ghost" size="sm" onClick={() => compare.mutate()} disabled={!peerId} data-testid="mirror-relink-compare">
                    {relinkPhase && ENDED.includes(relinkPhase) && relinkPhase !== 'done' && relinkPhase !== 'stale' ? 'Ask again' : 'Compare again'}
                  </Button>
                : null}
                {waiting ?
                  <Button variant="ghost" size="sm" onClick={() => plan.mutate({ discard: true })} disabled={plan.isPending} data-testid="mirror-relink-cancel">
                    Cancel the request
                  </Button>
                : null}
              </div>
              {waiting && s.relink?.phase === 'proposed' && s.handshake?.proposal ?
                <ul className="space-y-1 text-xs text-fg-subtle" data-testid="mirror-relink-proposed">
                  <li>
                    Proposed: {coreName(s.handshake.proposal.core, peer)} becomes the core ({s.handshake.proposal.mode === 'override' ? 'its tree wins everywhere' : 'the plan decides each entry'}).
                  </li>
                  <li>This server {gainsText(s.handshake.proposal.this)}.</li>
                  <li>
                    {peer} {gainsText(s.handshake.proposal.theirs)}.
                  </li>
                </ul>
              : null}
              {s.relink && (s.relink.phase === 'bring' || s.relink.phase === 'copying') && s.progress ?
                <p className="text-sm text-fg-muted tabular">
                  {formatInt(Number((s.progress as Record<string, unknown>).bring_done ?? 0))} of{' '}
                  {formatInt(Number((s.progress as Record<string, unknown>).bring_total ?? 0))} brought onto the core
                </p>
              : null}

              {step === 'summary' && isOpen ?
                <div className="space-y-3" data-testid="mirror-relink-summary">
                  <p className="text-sm text-fg">
                    {total ? `${formatInt(total)} entr${total === 1 ? 'y differs' : 'ies differ'}` : 'Both trees are the same.'}
                  </p>
                  {lines.length ?
                    <ul className="grid grid-cols-2 gap-x-6 gap-y-1 text-sm text-fg-muted">
                      {lines.map(l => (
                        <li key={l.kind} className="flex justify-between gap-3">
                          <span>{l.label}</span>
                          <span className="tabular text-fg">{formatInt(l.count)}</span>
                        </li>
                      ))}
                    </ul>
                  : null}
                  {blockers.length ?
                    <div className="rounded-control border border-warn-line bg-warn-soft p-3" role="note" data-testid="mirror-relink-blockers">
                      {blockers.map(b => (
                        <p key={b.code + b.side} className="flex items-start gap-2 text-sm text-warn">
                          <TriangleExclamationIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
                          {b.message}
                        </p>
                      ))}
                    </div>
                  : null}
                  <div className="grid gap-2 sm:grid-cols-3">
                    <Button variant="secondary" disabled={blockers.length > 0} onClick={() => toConfirm('this')} data-testid="mirror-relink-keep-this">
                      Keep this server’s
                    </Button>
                    <Button variant="secondary" disabled={blockers.length > 0} onClick={() => toConfirm('theirs')} data-testid="mirror-relink-keep-theirs">
                      Keep {peer}’s
                    </Button>
                    <Button variant="secondary" disabled={blockers.length > 0 || total === 0} onClick={() => setStep('review')} data-testid="mirror-relink-review">
                      Review each change…
                    </Button>
                  </div>
                </div>
              : null}

              {step === 'review' && isOpen ?
                <div className="space-y-3" data-testid="mirror-relink-plan">
                  <div className="grid gap-3 sm:grid-cols-2">
                    <Field label="The core (its tree is the truth)" htmlFor={`${ids}-core`}>
                      <Select id={`${ids}-core`} value={core} onChange={e => plan.mutate({ core: e.target.value })}>
                        <option value="this">This server</option>
                        <option value="theirs">{peer}</option>
                      </Select>
                    </Field>
                    <Field label="Entries left unset" htmlFor={`${ids}-default`}>
                      <Select id={`${ids}-default`} value={s.plan?.default_choice ?? ''} onChange={e => plan.mutate({ default: e.target.value })}>
                        <option value="">The core’s version</option>
                        <option value="this">{choiceText('this', peer)}</option>
                        <option value="theirs">{choiceText('theirs', peer)}</option>
                        <option value="both">{choiceText('both', peer)}</option>
                      </Select>
                    </Field>
                  </div>
                  <ul className="space-y-1 text-xs text-fg-subtle">
                    <li>This server {gainsText(s.plan?.this)}.</li>
                    <li>
                      {peer} {gainsText(s.plan?.theirs)}.
                    </li>
                  </ul>
                  <div className="flex flex-wrap items-end gap-2">
                    <Field label="Show" htmlFor={`${ids}-kind`}>
                      <Select
                        id={`${ids}-kind`}
                        value={kind}
                        onChange={e => {
                          setKind(e.target.value as DriftKind | '')
                          setOffset(0)
                        }}>
                        <option value="">Every kind</option>
                        {DRIFT_KINDS.map(k => (
                          <option key={k} value={k}>
                            {kindText(k, peer)}
                          </option>
                        ))}
                      </Select>
                    </Field>
                    <Select aria-label="Set every shown entry" value="" onChange={e => e.target.value && plan.mutate(kindPayload(kind, e.target.value === 'default' ? '' : (e.target.value as Choice)))}>
                      <option value="">Set all shown…</option>
                      <option value="this">{choiceText('this', peer)}</option>
                      <option value="theirs">{choiceText('theirs', peer)}</option>
                      <option value="both">{choiceText('both', peer)} (files)</option>
                      <option value="default">The default</option>
                    </Select>
                  </div>
                  {entries.data ?
                    <ul className="max-h-72 divide-y divide-line overflow-y-auto rounded-control border border-line" data-testid="mirror-relink-entries">
                      {entries.data.entries.map(e => (
                        <li key={e.uid} className="flex items-center justify-between gap-3 px-3 py-2">
                          <span className="min-w-0">
                            <span className="block truncate font-mono text-xs text-fg" title={e.path}>
                              {e.path}
                            </span>
                            <span className="text-xs text-fg-subtle">
                              {kindText(e.kind, peer)}
                              {e.aspects.length ? ` · ${e.aspects.join(', ')}` : ''}
                            </span>
                          </span>
                          <Select
                            aria-label={`Choice for ${e.path}`}
                            value={e.choice ?? ''}
                            onChange={ev => plan.mutate(choicePayload(e.uid, ev.target.value as Choice | ''))}
                            className="w-44 shrink-0">
                            <option value="">Default ({choiceText(winnerOf(e.resolution, core), peer).toLowerCase()})</option>
                            <option value="this">{choiceText('this', peer)}</option>
                            <option value="theirs">{choiceText('theirs', peer)}</option>
                            {canKeepBoth(e) ? <option value="both">{choiceText('both', peer)}</option> : null}
                          </Select>
                        </li>
                      ))}
                    </ul>
                  : <Skeleton />}
                  {entries.data && entries.data.total > PAGE ?
                    <div className="flex items-center justify-between text-xs text-fg-subtle tabular">
                      <span>
                        {offset + 1}–{Math.min(offset + PAGE, entries.data.total)} of {formatInt(entries.data.total)}
                      </span>
                      <span className="flex gap-2">
                        <Button variant="ghost" size="sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
                          Previous
                        </Button>
                        <Button variant="ghost" size="sm" disabled={offset + PAGE >= entries.data.total} onClick={() => setOffset(offset + PAGE)}>
                          Next
                        </Button>
                      </span>
                    </div>
                  : null}
                  <div className="flex justify-between gap-2">
                    <Button variant="ghost" onClick={() => setStep('summary')}>
                      Back
                    </Button>
                    <Button variant="primary" onClick={() => toConfirm(null)} disabled={blockers.length > 0} data-testid="mirror-relink-to-apply">
                      Apply this plan…
                    </Button>
                  </div>
                  <PeerError error={plan.error} fallback="The plan was not changed" />
                </div>
              : null}

              {step === 'confirm' ?
                <div className="space-y-3" data-testid="mirror-relink-confirm-step">
                  <div className="rounded-control border border-warn-line bg-warn-soft p-3" role="note">
                    <p className="text-sm font-semibold text-warn">
                      {keep ? `${coreName(winner, peer)}’s data wins everywhere` : `${coreName(core, peer)} becomes the core; the plan decides each entry`}
                    </p>
                    <p className="mt-1 text-sm text-fg-muted">
                      {`${coreName(keep ?? core, peer)} becomes the vault’s core and the other server its mirror. What the other server held that differs is kept there as held changes, with its bytes. ${peer}’s admin approves this outcome before anything changes on either server.`}
                    </p>
                  </div>
                  <Field label={`Type “${row.vault_name}” to confirm`} htmlFor={`${ids}-typed`}>
                    <Input id={`${ids}-typed`} value={typed} autoComplete="off" onChange={e => setTyped(e.target.value)} data-testid="mirror-relink-typed" />
                  </Field>
                </div>
              : null}
            </>
          }
          <PeerError error={compare.error ?? status.error} fallback="The two servers could not be compared" />
          <PeerError error={apply.error} fallback="The vault was not relinked" />
        </div>
      </DialogContent>
    </Dialog>
  )
}
