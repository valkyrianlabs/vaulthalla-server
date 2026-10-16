'use client'

import React from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { PageHeader } from '@/components/ui/Panel'
import { Button } from '@/components/ui/Button'
import { IconButton } from '@/components/ui/IconButton'
import { Badge } from '@/components/ui/Badge'
import { DataTable, type Column } from '@/components/ui/DataTable'
import { DropdownMenu } from '@/components/ui/Menu'
import { EmptyState, QueryState } from '@/components/ui/State'
import { BucketIcon, EllipsisIcon, KeySkeletonIcon, PenIcon, PlusIcon, TrashIcon } from '@/components/ui/icons'
import { DASH, formatDate, formatRelative } from '@/lib/format'
import { maskAccessKey, type ProviderCredential } from '@/features/credentials/types'
import { useCredentialList, useCredentialPerms, useCredentialUsage } from '@/features/credentials/useCredentials'
import { deleteCredential } from '@/features/credentials/deleteCredential'
import { useUpstreamPerms } from '@/features/credentials/upstream/hooks'

const host = (endpoint: string) => {
  try {
    return new URL(endpoint).host
  } catch {
    return endpoint
  }
}

export const CredentialsPage = () => {
  const router = useRouter()
  const can = useCredentialPerms()
  const list = useCredentialList(can.view)
  const { usage } = useCredentialUsage(can.view)
  const upstream = useUpstreamPerms()

  const columns: Column<ProviderCredential>[] = [
    {
      key: 'name',
      header: 'Name',
      sortValue: row => row.name.toLowerCase(),
      cell: row => <span className="font-medium">{row.name || `Credential ${row.api_key_id}`}</span>,
    },
    {
      key: 'provider',
      header: 'Provider',
      sortValue: row => row.provider,
      cell: row => (
        <span className="flex flex-wrap items-center gap-1.5">
          {row.provider ?
            <Badge>{row.provider}</Badge>
          : <span className="text-fg-faint">{DASH}</span>}
          {row.admin_enabled ?
            <Badge tone="accent" title="Provider administration is enabled: Vaulthalla can create, adopt and watch buckets">
              Admin
            </Badge>
          : null}
        </span>
      ),
    },
    {
      key: 'endpoint',
      header: 'Endpoint',
      hideBelow: 'lg',
      cell: row => (
        <span className="text-fg-muted block max-w-[18rem] truncate font-mono text-xs" title={row.endpoint}>
          {host(row.endpoint) || DASH}
        </span>
      ),
    },
    {
      key: 'region',
      header: 'Region',
      hideBelow: 'md',
      cell: row => <span className="text-fg-muted font-mono text-xs">{row.region || DASH}</span>,
    },
    {
      key: 'access_key',
      header: 'Access key',
      hideBelow: 'md',
      cell: row => (
        <span className="tabular text-fg-subtle font-mono text-xs">{maskAccessKey(row.access_key) || DASH}</span>
      ),
    },
    {
      key: 'usage',
      header: 'Used by',
      sortValue: row => usage?.get(row.api_key_id)?.length ?? null,
      cell: row => {
        if (!usage) return <span className="text-fg-faint">{DASH}</span>
        const vaults = usage.get(row.api_key_id) ?? []
        if (vaults.length === 0) return <span className="text-fg-subtle">No vaults</span>
        return (
          <span
            title={vaults.map(v => v.name).join(', ')}
            className="tabular text-fg-muted decoration-line-strong underline decoration-dotted underline-offset-4">
            {vaults.length === 1 ? vaults[0].name : `${vaults.length} vaults`}
          </span>
        )
      },
    },
    {
      key: 'created',
      header: 'Added',
      hideBelow: 'sm',
      sortValue: row => row.created_at,
      cell: row => (
        <span className="tabular text-fg-subtle" title={formatDate(row.created_at)}>
          {formatRelative(row.created_at)}
        </span>
      ),
    },
  ]

  return (
    <>
      <PageHeader
        title="Provider credentials"
        description="Access keys for upstream S3-compatible storage (AWS, Cloudflare R2, …). S3 vaults and remote-cache buckets use them to reach their bucket. These are not the keys clients use to talk to the Vaulthalla S3 gateway."
        actions={
          can.create ?
            <Button asChild variant="primary">
              <Link href="/credentials/new">
                <PlusIcon aria-hidden />
                Add credential
              </Link>
            </Button>
          : null
        }
      />
      {!can.view ?
        <EmptyState
          className="panel"
          title="You don't have access to this"
          description="Viewing provider credentials needs an admin.keys.api permission."
        />
      : <QueryState query={list}>
          {rows =>
            rows.length === 0 ?
              <EmptyState
                className="panel"
                icon={KeySkeletonIcon}
                title="No provider credentials yet"
                description="Add an access key for your S3 or R2 account, then create an S3 vault that uses it."
                action={
                  can.create ?
                    <Button asChild variant="primary">
                      <Link href="/credentials/new">
                        <PlusIcon aria-hidden />
                        Add credential
                      </Link>
                    </Button>
                  : undefined
                }
              />
            : <DataTable
                rows={rows}
                columns={columns}
                rowKey={row => row.api_key_id}
                rowHref={row => `/credentials/${row.api_key_id}`}
                initialSort={{ key: 'name', dir: 'asc' }}
                filter={(row, q) =>
                  `${row.name} ${row.provider} ${row.endpoint} ${row.region}`.toLowerCase().includes(q)
                }
                filterPlaceholder="Filter credentials…"
                rowActions={row =>
                  can.edit || can.remove || (row.admin_enabled && upstream.view) ?
                    <DropdownMenu
                      label={`Actions for ${row.name}`}
                      trigger={
                        <IconButton
                          label={`Actions for ${row.name}`}
                          icon={EllipsisIcon}
                          size="icon-sm"
                          tooltip={false}
                        />
                      }
                      entries={[
                        ...(row.admin_enabled && upstream.view ?
                          [
                            {
                              key: 'buckets',
                              label: 'Buckets',
                              icon: BucketIcon,
                              onSelect: () => router.push(`/credentials/${row.api_key_id}/buckets`),
                            },
                          ]
                        : []),
                        ...(can.edit ?
                          [
                            {
                              key: 'edit',
                              label: 'Edit',
                              icon: PenIcon,
                              onSelect: () => router.push(`/credentials/${row.api_key_id}`),
                            },
                          ]
                        : []),
                        ...(can.remove ?
                          [
                            {
                              key: 'delete',
                              label: 'Delete',
                              icon: TrashIcon,
                              danger: true,
                              onSelect: () =>
                                void deleteCredential(row, usage ? (usage.get(row.api_key_id) ?? []) : null),
                            },
                          ]
                        : []),
                      ]}
                    />
                  : null
                }
              />
          }
        </QueryState>
      }
    </>
  )
}
