'use client'

import React, { useMemo } from 'react'
import dynamic from 'next/dynamic'
import Link from 'next/link'
import { PageHeader } from '@/components/ui/Panel'
import { Button } from '@/components/ui/Button'
import { Badge, SeverityBadge } from '@/components/ui/Badge'
import { DataTable, type Column } from '@/components/ui/DataTable'
import { EmptyState, QueryState } from '@/components/ui/State'
import { PlusIcon, VaultIcon } from '@/components/ui/icons'
import { useCan } from '@/lib/permissions'
import { formatDate } from '@/lib/format'
import { titleCase } from '@/lib/format'
import { useCredentials, useStorageOverview, useUserNames, useVaultList, VAULT_CREATE, VAULT_REMOVE } from '@/features/vaults/hooks'
import { providerLabel, vaultTypeLabel, type VaultRow } from '@/features/vaults/model'
import { UsageCell, VaultGlyph, type BackendEntry } from '@/features/vaults/parts'

// Pending and purged-with-key deletions (#162); only for accounts that may delete vaults.
const DeletedVaults = dynamic(() => import('@/features/vaults/DeletedVaults'), { ssr: false })

export const VaultsPage = () => {
  const vaults = useVaultList()
  const canCreate = useCan(VAULT_CREATE)
  const canRemove = useCan(VAULT_REMOVE)
  const credentials = useCredentials()
  const { names } = useUserNames()
  const storage = useStorageOverview()

  const backend = useMemo(() => {
    const map = new Map<number, BackendEntry>()
    const rows = (storage.data?.stats as unknown as { vaults?: BackendEntry[] } | undefined)?.vaults ?? []
    for (const row of rows) map.set(row.vault_id, row)
    return map
  }, [storage.data])

  const columns: Column<VaultRow>[] = [
    {
      key: 'name',
      header: 'Name',
      sortValue: v => v.name.toLowerCase(),
      cell: v => (
        <span className="flex min-w-0 items-center gap-3">
          <VaultGlyph type={v.type} />
          <span className="min-w-0">
            <span className="block truncate">{v.name}</span>
            {v.description ? <span className="block max-w-[12rem] truncate text-xs font-normal text-fg-subtle sm:max-w-[28rem]">{v.description}</span> : null}
          </span>
        </span>
      ),
    },
    {
      key: 'type',
      header: 'Storage',
      hideBelow: 'sm',
      sortValue: v => providerLabel(v, credentials.data),
      cell: v => (
        <span className="text-fg-muted">
          {providerLabel(v, credentials.data)}
          {v.type === 's3' && v.bucket ? <span className="block font-mono text-xs text-fg-subtle">{v.bucket}</span> : null}
        </span>
      ),
    },
    {
      key: 'owner',
      header: 'Owner',
      hideBelow: 'md',
      sortValue: v => names.get(v.owner_id) ?? '',
      cell: v => <OwnerName id={v.owner_id} name={names.get(v.owner_id)} />,
    },
    {
      key: 'usage',
      header: 'Usage',
      hideBelow: 'lg',
      sortValue: v => backend.get(v.id)?.vault_size_bytes ?? null,
      cell: v => <UsageCell used={backend.get(v.id)?.vault_size_bytes} quota={v.quota} />,
    },
    {
      key: 'status',
      header: 'Status',
      sortValue: v => (v.is_active ? backend.get(v.id)?.backend_status ?? 'active' : 'inactive'),
      cell: v => {
        if (!v.is_active) return <Badge tone="neutral">Inactive</Badge>
        const status = backend.get(v.id)?.backend_status
        return status ? <SeverityBadge severity={status} label={titleCase(status)} /> : <Badge tone="neutral">Active</Badge>
      },
    },
    {
      key: 'created',
      header: 'Created',
      hideBelow: 'xl',
      sortValue: v => v.created_at,
      cell: v => <span className="text-fg-subtle tabular">{formatDate(v.created_at)}</span>,
    },
  ]

  return (
    <>
      <PageHeader
        title="Vaults"
        description="Where files live: a directory on this server, encrypted at rest, or an S3 bucket. Open one for its health, access, sharing and sync settings."
        actions={
          canCreate ? (
            <Button asChild variant="primary">
              <Link href="/vaults/new">
                <PlusIcon aria-hidden />
                New vault
              </Link>
            </Button>
          ) : null
        }
      />
      <QueryState query={vaults}>
        {rows =>
          rows.length ? (
            <DataTable
              rows={rows}
              columns={columns}
              rowKey={v => v.id}
              rowHref={v => `/vaults/${v.id}`}
              initialSort={{ key: 'name', dir: 'asc' }}
              filter={(v, q) =>
                [v.name, v.description, v.slug, v.bucket, vaultTypeLabel(v.type), names.get(v.owner_id)]
                  .filter(Boolean)
                  .some(text => String(text).toLowerCase().includes(q))
              }
              filterPlaceholder="Filter vaults…"
              toolbar={<span className="text-xs text-fg-subtle tabular">{rows.length === 1 ? '1 vault' : `${rows.length} vaults`}</span>}
            />
          ) : (
            <div className="panel">
              <EmptyState
                icon={VaultIcon}
                title="No vaults yet"
                description="A vault is where files live: a directory on this server, or an S3 bucket with an encrypted local cache."
                action={
                  canCreate ? (
                    <Button asChild variant="primary">
                      <Link href="/vaults/new">
                        <PlusIcon aria-hidden />
                        New vault
                      </Link>
                    </Button>
                  ) : undefined
                }
              />
            </div>
          )
        }
      </QueryState>
      {canRemove ? <DeletedVaults /> : null}
    </>
  )
}

// The list payload only carries owner_id; names come from auth.users.list when this account may read it.
export const OwnerName = ({ id, name }: { id: number; name?: string }) => {
  if (!id) return <span className="text-fg-faint">No owner</span>
  if (!name) return <span className="text-fg-subtle tabular">User #{id}</span>
  return <span className="block max-w-[11rem] truncate text-fg-muted" title={name}>{name}</span>
}

export default VaultsPage
