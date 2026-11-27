'use client'

import React from 'react'
import { DataTable, type Column } from '@/components/ui/DataTable'
import { IconButton } from '@/components/ui/IconButton'
import { BanIcon } from '@/components/ui/icons'
import type { LinkedPeer } from '@/features/peers/model'
import { MIRROR_COPY as C } from '@/features/mirrors/copy'
import { actionsFor, peerName, positionText, statusText, unconfirmed, type MirroredVault } from '@/features/mirrors/model'
import { MirrorStatus, RoleBadge, date } from '@/features/mirrors/parts'
import { linkUpOf } from '@/features/mirrors/queries'

export const mirrorHref = (row: Pick<MirroredVault, 'vault_id'>) => `/linked-servers/mirrors/${row.vault_id}`

// Live and running ones first, then the ones that need someone (stopped, orphaned), then ended ones.
const ORDER: Record<string, number> = { core: 0, mirror: 0, starting: 1, orphaned: 2, detached: 3, none: 4 }

// Every mirrored vault here (mirror.list): the vault, the other server, this server's role, the state with its reason,
// where the two copies stand and the changes held here. A row opens the vault's mirror page; a start whose vault
// doesn't exist here yet can only be cancelled.
export const MirrorTable = ({
  rows,
  peers,
  held,
  empty,
  onCancelStart,
}: {
  rows: MirroredVault[]
  peers: Map<number, LinkedPeer>
  held: Map<number, number>
  empty: React.ReactNode
  onCancelStart: (row: MirroredVault) => void
}) => {
  const sorted = [...rows].sort((a, b) => (ORDER[a.role] ?? 5) - (ORDER[b.role] ?? 5) || a.vault_name.localeCompare(b.vault_name))
  const columns: Column<MirroredVault>[] = [
    {
      key: 'vault',
      header: C.colVault,
      sortValue: r => r.vault_name.toLowerCase(),
      cell: r => (
        <span className="flex min-w-0 flex-col items-start gap-1">
          <span className="truncate font-medium" data-testid="mirror-vault-name">
            {r.vault_name || r.start?.name || '—'}
          </span>
          {/* The role column is hidden on a phone: the badge sits under the name there. */}
          <span className="sm:hidden">
            <RoleBadge role={r.role} testId="mirror-role-narrow" />
          </span>
        </span>
      ),
      className: 'py-2.5',
    },
    {
      key: 'server',
      header: C.colServer,
      sortValue: r => peerName(r).toLowerCase(),
      cell: r => (
        <span className="text-fg-muted" data-testid="mirror-peer">
          {peerName(r)}
        </span>
      ),
      hideBelow: 'md',
    },
    {
      key: 'role',
      header: C.colRole,
      sortValue: r => r.role,
      cell: r => <RoleBadge role={r.role} />,
      hideBelow: 'sm',
    },
    {
      key: 'state',
      header: C.colState,
      sortValue: r => statusText(r, { linkUp: linkUpOf(peers, r.peer?.id), date }).label,
      cell: r => <MirrorStatus row={r} facts={{ linkUp: linkUpOf(peers, r.peer?.id) }} className="max-w-md min-w-48" />,
      className: 'py-2.5',
    },
    {
      key: 'position',
      header: C.colPosition,
      cell: r => {
        const behind = unconfirmed(r)
        return (
          <span className="flex flex-col text-xs text-fg-muted tabular" data-testid="mirror-position">
            <span>{positionText(r)}</span>
            {behind ? <span className="text-fg-subtle">{C.unconfirmed(behind)}</span> : null}
          </span>
        )
      },
      hideBelow: 'xl',
    },
    {
      key: 'held',
      header: C.colHeld,
      sortValue: r => held.get(r.vault_id) ?? 0,
      cell: r => {
        const n = held.get(r.vault_id) ?? 0
        return (
          <span className={n ? 'font-medium whitespace-nowrap text-warn tabular' : 'text-fg-faint'} data-testid="mirror-held-count">
            {n ? C.heldCount(n) : C.heldNone}
          </span>
        )
      },
      hideBelow: 'md',
    },
  ]
  return (
    <DataTable
      rows={sorted}
      columns={columns}
      rowKey={r => `${r.vault_id}-${r.start?.id ?? 0}-${r.role}`}
      rowHref={r => (r.vault_id > 0 ? mirrorHref(r) : undefined) as string}
      empty={empty}
      filter={(r, q) => [r.vault_name, peerName(r), r.role, r.state ?? ''].some(v => v.toLowerCase().includes(q))}
      filterPlaceholder={C.filter}
      rowActions={r =>
        r.vault_id > 0 || !actionsFor(r).includes('cancel') ? null : (
          <IconButton
            label={C.cancelStartTitle(r.start?.name ?? r.vault_name)}
            icon={BanIcon}
            size="icon-sm"
            className="hover:text-danger"
            onClick={() => onCancelStart(r)}
            data-testid={`mirror-cancel-start-${r.start?.id ?? 0}`}
          />
        )
      }
    />
  )
}
