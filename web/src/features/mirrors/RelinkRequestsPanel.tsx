'use client'

import React, { useId, useState } from 'react'
import { useWsMutation } from '@/lib/query'
import { formatRelative } from '@/lib/format'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { confirm } from '@/components/ui/Confirm'
import { Dialog, DialogClose, DialogContent } from '@/components/ui/Dialog'
import { Field, Input } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import { notify } from '@/components/ui/Toast'
import { PeerError } from '@/features/peers/parts'
import { MIRROR_READS } from '@/features/mirrors/model'
import { gainsText, requestAsk, type RelinkRequest } from '@/features/mirrors/relink'

const RELINK_REQUEST_READS = ['mirror.relink.pending', 'mirror.relink.get', ...MIRROR_READS] as const

// The relinks linked servers ask of this server's vaults (mirror.relink.pending): both servers agree, each by a super
// admin. A request is accepted first (the other server may then compare its copy with this vault: names, places,
// hashes, never contents), then the outcome it proposes is approved (which server becomes the core, and what this
// vault gains and loses) before anything changes here. Declining ends it on both servers. Loaded with next/dynamic,
// only while one is listed.
export default function RelinkRequestsPanel({ requests }: { requests: RelinkRequest[] }) {
  const [error, setError] = useState<{ error: unknown; fallback: string } | null>(null)
  const [approving, setApproving] = useState<RelinkRequest | null>(null)

  const accept = useWsMutation('mirror.relink.accept', {
    toPayload: (q: RelinkRequest) => ({ vault_id: q.vault_id }),
    invalidates: [...RELINK_REQUEST_READS],
    onSuccess: data => notify.success(`Accepted ${data.peer.name}’s request for “${data.vault_name}”`, 'It compares its copy next; the outcome waits for approval here.'),
  })
  const decline = useWsMutation('mirror.relink.decline', {
    toPayload: (q: RelinkRequest) => ({ vault_id: q.vault_id }),
    invalidates: [...RELINK_REQUEST_READS],
    onSuccess: data => notify.success(`Declined ${data.peer.name}’s relink of “${data.vault_name}”`, 'Neither copy changed.'),
  })

  const askAccept = async (q: RelinkRequest) => {
    const ok = await confirm({
      title: `Let ${q.peer.name} compare “${q.vault_name}”?`,
      description: q.handshake?.discloses ?? '',
      confirmLabel: 'Accept',
      tone: 'primary',
    })
    if (!ok) return
    setError(null)
    accept.mutate(q, { onError: e => setError({ error: e, fallback: 'The request was not accepted' }) })
  }
  const askDecline = async (q: RelinkRequest) => {
    const ok = await confirm({
      title: `Decline ${q.peer.name}’s relink of “${q.vault_name}”?`,
      description: 'The relink ends on both servers. Neither copy changes.',
      confirmLabel: 'Decline',
      tone: 'danger',
    })
    if (!ok) return
    setError(null)
    decline.mutate(q, { onError: e => setError({ error: e, fallback: 'The relink was not declined' }) })
  }
  const busy = (q: RelinkRequest) =>
    (accept.isPending && accept.variables?.vault_id === q.vault_id) || (decline.isPending && decline.variables?.vault_id === q.vault_id)

  return (
    <Panel
      title="Relink requests"
      description="Linked servers that hold a vault of this server since a mirror between them ended ask to mirror it again. A super admin here accepts the comparison, then approves the outcome."
      className="mb-6"
      id="mirror-relink-requests">
      <PeerError error={error?.error} fallback={error?.fallback ?? ''} className="mb-3" />
      <ul className="divide-y divide-line/60" data-testid="mirror-relink-requests">
        {requests.map(q => (
          <li key={q.relink_uid} className="flex flex-wrap items-start justify-between gap-3 py-3 first:pt-0 last:pb-0" data-testid="mirror-relink-request">
            <div className="min-w-0 space-y-1">
              <p className="text-sm text-fg">
                <span className="font-medium">{q.vault_name}</span> <span className="text-fg-subtle">{requestAsk(q)}</span>
              </p>
              {q.phase === 'requested' && q.handshake?.discloses ? <p className="text-xs text-fg-muted">{q.handshake.discloses}</p> : null}
              {q.phase === 'proposed' && q.handshake?.outcome ?
                <p className="text-xs text-fg-muted" data-testid="mirror-relink-request-outcome">
                  {q.handshake.outcome}
                </p>
              : null}
              <p className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-fg-subtle">
                <Badge className="h-5 px-2 text-[11px]">{q.phase}</Badge>
                {q.status ? <span>this server: {q.status}</span> : null}
                {q.handshake?.expires_at ? <span>expires {formatRelative(q.handshake.expires_at)}</span> : null}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Button variant="ghost" size="sm" disabled={busy(q)} onClick={() => void askDecline(q)} data-testid={`mirror-relink-decline-${q.vault_id}`}>
                Decline
              </Button>
              {q.phase === 'requested' ?
                <Button
                  variant="primary"
                  size="sm"
                  disabled={busy(q)}
                  loading={accept.isPending && accept.variables?.vault_id === q.vault_id}
                  onClick={() => void askAccept(q)}
                  data-testid={`mirror-relink-accept-${q.vault_id}`}>
                  Accept…
                </Button>
              : null}
              {q.phase === 'proposed' ?
                <Button variant="primary" size="sm" disabled={busy(q)} onClick={() => setApproving(q)} data-testid={`mirror-relink-approve-${q.vault_id}`}>
                  Review and approve…
                </Button>
              : null}
            </div>
          </li>
        ))}
      </ul>
      {approving ? <ApproveDialog request={approving} onClose={() => setApproving(null)} /> : null}
    </Panel>
  )
}

// The outcome, in plain words and counts, approved with the vault's name typed (the keys step-up runs through the
// shell's dialog).
const ApproveDialog = ({ request: q, onClose }: { request: RelinkRequest; onClose: () => void }) => {
  const ids = useId()
  const [typed, setTyped] = useState('')
  const approve = useWsMutation<'mirror.relink.approve', void>('mirror.relink.approve', {
    toPayload: () => ({ vault_id: q.vault_id, confirm: typed }),
    invalidates: [...RELINK_REQUEST_READS],
    onSuccess: () => {
      notify.success(`Approved ${q.peer.name}’s relink of “${q.vault_name}”`, `${q.peer.name} carries it out now.`)
      onClose()
    },
  })
  const p = q.handshake?.proposal
  return (
    <Dialog open onOpenChange={next => (!next && !approve.isPending ? onClose() : undefined)}>
      <DialogContent
        title={`Approve ${q.peer.name}’s relink of “${q.vault_name}”?`}
        description="Nothing changes on either server before you approve. A changed plan or a change to this vault since voids the approval."
        footer={
          <>
            <DialogClose asChild>
              <Button variant="ghost" disabled={approve.isPending}>
                Cancel
              </Button>
            </DialogClose>
            <Button
              variant="danger-solid"
              loading={approve.isPending}
              disabled={typed !== q.vault_name || approve.isPending}
              onClick={() => approve.mutate()}
              data-testid="mirror-relink-approve-confirm">
              Approve
            </Button>
          </>
        }
        data-testid="mirror-relink-approve-dialog">
        <div className="space-y-3">
          <div className="rounded-control border border-warn-line bg-warn-soft p-3" role="note">
            <p className="text-sm text-fg">{q.handshake?.outcome}</p>
          </div>
          {p ?
            <ul className="space-y-1 text-xs text-fg-subtle">
              <li>This server {gainsText(p.this)}.</li>
              <li>
                {q.peer.name} {gainsText(p.theirs)}.
              </li>
              <li>{p.mode === 'override' ? 'The hard override: one tree wins everywhere.' : `A plan of ${p.entries} drifted entr${p.entries === 1 ? 'y' : 'ies'}.`}</li>
            </ul>
          : null}
          <Field label={`Type “${q.vault_name}” to confirm`} htmlFor={`${ids}-typed`}>
            <Input id={`${ids}-typed`} value={typed} autoComplete="off" onChange={e => setTyped(e.target.value)} data-testid="mirror-relink-approve-typed" />
          </Field>
          <PeerError error={approve.error} fallback="The outcome was not approved" />
        </div>
      </DialogContent>
    </Dialog>
  )
}
