'use client'

import React, { useMemo, useState } from 'react'
import dynamic from 'next/dynamic'
import { useWsMutation } from '@/lib/query'
import { formatDateTime, formatRelative } from '@/lib/format'
import { DataTable, type Column } from '@/components/ui/DataTable'
import { Badge } from '@/components/ui/Badge'
import { Checkbox } from '@/components/ui/Choice'
import { IconButton } from '@/components/ui/IconButton'
import { Label } from '@/components/ui/Field'
import { confirm } from '@/components/ui/Confirm'
import { notify } from '@/components/ui/Toast'
import { BanIcon, PenIcon } from '@/components/ui/icons'
import { COMPARED_BY, COMPARED_BY_HINT, PEERS_COPY } from '@/features/peers/copy'
import {
  PEER_READS,
  byStatus,
  groupHex,
  healthText,
  peerLabel,
  peerVersion,
  shortKey,
  shortNodeId,
  type LinkedPeer,
} from '@/features/peers/model'
import { CopyButton, PeerError } from '@/features/peers/parts'

// Mounted only while renaming (Radix Dialog stays out of the route's first load).
const RenamePeerDialog = dynamic(() => import('@/features/peers/RenamePeerDialog'), { ssr: false })

const when = (unix: number) => formatRelative(unix)

const Health = ({ peer }: { peer: LinkedPeer }) => {
  const h = healthText(peer, when)
  return (
    <span className="flex min-w-0 flex-col gap-0.5" data-testid="peer-health">
      <span>
        <Badge tone={h.tone} dot className="h-5 px-2 text-[11px]">
          <span data-testid="peer-health-label">{h.label}</span>
        </Badge>
      </span>
      {h.facts.length ? (
        <span className="text-xs break-words text-fg-subtle" data-testid="peer-health-facts">
          {h.facts.join(' · ')}
        </span>
      ) : null}
    </span>
  )
}

// The linked servers (peer.list {all: true}): name, node id, key, how the code was compared, when it was linked and the
// link's live health; rename and unlink. Unlinked rows stay listed behind a switch, as `vh peer list --all` shows them.
export const PeerTable = ({ peers, empty }: { peers: LinkedPeer[]; empty: React.ReactNode }) => {
  const [showUnlinked, setShowUnlinked] = useState(false)
  const [renaming, setRenaming] = useState<LinkedPeer | null>(null)
  const [error, setError] = useState<unknown>(null)
  const unlinkedCount = peers.filter(p => p.revoked).length
  const rows = useMemo(() => [...peers].filter(p => showUnlinked || !p.revoked).sort(byStatus), [peers, showUnlinked])

  const unlink = useWsMutation('peer.unlink', {
    toPayload: (peer: LinkedPeer) => ({ peer: String(peer.id) }),
    invalidates: [...PEER_READS],
    onSuccess: data => notify.success(PEERS_COPY.unlinked(peerLabel(data.peer)), PEERS_COPY.unlinkedHint),
  })

  const askUnlink = async (peer: LinkedPeer) => {
    const name = peerLabel(peer)
    const ok = await confirm({
      title: PEERS_COPY.unlinkTitle(name),
      description: PEERS_COPY.unlinkBody(name),
      confirmLabel: PEERS_COPY.unlinkConfirm,
      tone: 'danger',
    })
    if (!ok) return
    setError(null)
    unlink.mutate(peer, { onError: setError })
  }

  const columns: Column<LinkedPeer>[] = [
    {
      key: 'name',
      header: 'Name',
      sortValue: p => p.name.toLowerCase(),
      cell: p => (
        <span className="flex min-w-0 items-center gap-2">
          <span className="truncate font-medium text-fg" data-testid="peer-name">
            {peerLabel(p)}
          </span>
          {p.revoked ? (
            <Badge tone="neutral" className="h-5 px-2 text-[11px]" title={p.revoked_at ? `Unlinked ${formatDateTime(p.revoked_at)}` : undefined}>
              Unlinked
            </Badge>
          ) : null}
        </span>
      ),
    },
    {
      key: 'health',
      header: 'Link',
      sortValue: p => (p.revoked ? 2 : p.health.connected ? 0 : 1),
      cell: p => <Health peer={p} />,
    },
    {
      key: 'node',
      header: 'Node',
      sortValue: p => p.node_id,
      cell: p => (
        <code className="font-mono text-xs whitespace-nowrap text-fg-muted" title={p.node_id} data-testid="peer-node">
          {shortNodeId(p.node_id)}
        </code>
      ),
      hideBelow: 'md',
    },
    {
      key: 'key',
      header: 'Key',
      cell: p => (
        <span className="inline-flex items-center gap-1">
          <code className="font-mono text-xs whitespace-nowrap text-fg-muted" title={groupHex(p.spki_sha256)} data-testid="peer-key">
            {groupHex(shortKey(p.spki_sha256))}
          </code>
          <CopyButton text={p.spki_sha256} label={`Copy ${peerLabel(p)}’s key`} />
        </span>
      ),
      hideBelow: 'lg',
    },
    {
      key: 'compared',
      header: 'Code compared by',
      sortValue: p => p.compared_by,
      cell: p => (
        <span title={COMPARED_BY_HINT[p.compared_by]} data-testid="peer-compared-by">
          {COMPARED_BY[p.compared_by] ?? p.compared_by}
        </span>
      ),
      hideBelow: 'xl',
    },
    {
      key: 'version',
      header: 'Version',
      sortValue: p => peerVersion(p) ?? '',
      cell: p => <span className="tabular">{peerVersion(p) ?? '—'}</span>,
      hideBelow: 'lg',
    },
    {
      key: 'linked',
      header: 'Linked',
      sortValue: p => p.linked_at,
      cell: p => (
        <span className="tabular text-fg-muted" title={formatDateTime(p.linked_at)} data-testid="peer-linked-at">
          {formatRelative(p.linked_at)}
        </span>
      ),
      hideBelow: 'md',
    },
  ]

  return (
    <>
      <PeerError error={error} fallback={PEERS_COPY.unlinkFailed} className="mb-3" />
      <DataTable
        rows={rows}
        columns={columns}
        rowKey={p => p.id}
        empty={empty}
        filter={(p, q) => [p.name, p.node_id, p.spki_sha256, peerVersion(p) ?? ''].some(v => v.toLowerCase().includes(q))}
        filterPlaceholder={PEERS_COPY.filter}
        toolbar={
          unlinkedCount ? (
            <span className="flex items-center gap-2">
              <Checkbox id="peers-show-unlinked" checked={showUnlinked} onCheckedChange={setShowUnlinked} data-testid="peers-show-unlinked" />
              <Label htmlFor="peers-show-unlinked" className="text-fg-muted">
                {PEERS_COPY.showUnlinked(unlinkedCount)}
              </Label>
            </span>
          ) : null
        }
        rowActions={p =>
          p.revoked ? null : (
            <span className="inline-flex items-center gap-0.5">
              <IconButton label={`Rename ${peerLabel(p)}`} icon={PenIcon} size="icon-sm" onClick={() => setRenaming(p)} data-testid={`peer-rename-${p.id}`} />
              <IconButton
                label={`Unlink ${peerLabel(p)}`}
                icon={BanIcon}
                size="icon-sm"
                className="hover:text-danger"
                disabled={unlink.isPending && unlink.variables?.id === p.id}
                onClick={() => void askUnlink(p)}
                data-testid={`peer-unlink-${p.id}`}
              />
            </span>
          )
        }
      />
      {renaming ? <RenamePeerDialog peer={renaming} open onOpenChange={open => !open && setRenaming(null)} /> : null}
    </>
  )
}
