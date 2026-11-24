'use client'

import React from 'react'
import { api } from '@/lib/session'
import { DataTable, type Column } from '@/components/ui/DataTable'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { IconButton } from '@/components/ui/IconButton'
import { DropdownMenu } from '@/components/ui/Menu'
import { EmptyState, QueryState } from '@/components/ui/State'
import { confirm } from '@/components/ui/Confirm'
import { notify } from '@/components/ui/Toast'
import { BanIcon, EllipsisIcon, KeyIcon, PlusIcon, SlidersIcon } from '@/components/ui/icons'
import { DASH, formatDateTime, formatRelative, parseDate } from '@/lib/format'
import { scopeModeLabel, upstreamLabel, type GatewayCredential } from '@/features/gateway/model'
import { refreshCredentials, useGatewayCredentials } from '@/features/gateway/queries'

const expired = (c: GatewayCredential) => {
  const d = parseDate(c.expires_at)
  return d ? d.getTime() < Date.now() : false
}

export const credentialState = (c: GatewayCredential): { label: string; tone: 'neutral' | 'accent' | 'unknown' } => {
  if (c.enabled === null) return { label: 'Unknown', tone: 'unknown' }
  if (!c.enabled) return { label: 'Revoked', tone: 'neutral' }
  if (expired(c)) return { label: 'Expired', tone: 'neutral' }
  return { label: 'Active', tone: 'accent' }
}

export const revokeCredential = async (c: GatewayCredential) => {
  const ok = await confirm({
    title: `Revoke “${c.name}”?`,
    description:
      'Clients using this access key are refused from now on. A revoked key can’t be turned back on; create a new one instead.',
    confirmLabel: 'Revoke key',
  })
  if (!ok) return false
  try {
    await api.send('s3.gateway.credentials.revoke', { access_key: c.access_key })
    await refreshCredentials()
    notify.success('Key revoked', c.name)
    return true
  } catch (error) {
    notify.error(error, 'Could not revoke the key')
    return false
  }
}

export const CredentialsTab = ({
  onCreate,
  onOpen,
}: {
  onCreate: () => void
  onOpen: (c: GatewayCredential) => void
}) => {
  const list = useGatewayCredentials()

  const columns: Column<GatewayCredential>[] = [
    {
      key: 'name',
      header: 'Name',
      sortValue: c => c.name.toLowerCase(),
      cell: c => (
        <div className="min-w-0 py-1.5">
          <div className="text-fg font-medium" data-testid="s3-gateway-credential-name">
            {c.name}
          </div>
          <div className="text-fg-subtle max-w-[16rem] truncate font-mono text-xs" title={c.access_key}>
            {c.access_key}
          </div>
        </div>
      ),
    },
    {
      key: 'principal',
      header: 'Acts as',
      hideBelow: 'md',
      sortValue: c => c.principal_user?.name ?? null,
      cell: c => (
        <span className="text-fg-muted">
          {c.principal_user?.name ?? (c.principal_user_id ? `User ${c.principal_user_id}` : DASH)}
        </span>
      ),
    },
    {
      key: 'scope',
      header: 'Access',
      hideBelow: 'sm',
      cell: c => <span className="text-fg-muted">{scopeModeLabel(c.scope_mode)}</span>,
    },
    {
      key: 'upstream',
      header: 'New buckets',
      hideBelow: 'lg',
      cell: c => (
        <span className={c.upstream.problem ? 'text-warn' : 'text-fg-subtle'} title={c.upstream.problem ?? undefined}>
          {upstreamLabel(c.upstream)}
        </span>
      ),
    },
    {
      key: 'state',
      header: 'Status',
      sortValue: c => credentialState(c).label,
      cell: c => {
        const s = credentialState(c)
        return <Badge tone={s.tone}>{s.label}</Badge>
      },
    },
    {
      key: 'used',
      header: 'Last used',
      hideBelow: 'lg',
      sortValue: c => c.last_used_at,
      cell: c => (
        <span className="tabular text-fg-subtle whitespace-nowrap" title={formatDateTime(c.last_used_at)}>
          {c.last_used_at ? formatRelative(c.last_used_at) : 'Never'}
        </span>
      ),
    },
    {
      key: 'expires',
      header: 'Expires',
      hideBelow: 'lg',
      cell: c => (
        <span className="tabular text-fg-subtle whitespace-nowrap">
          {c.expires_at ? formatDateTime(c.expires_at) : 'Never'}
        </span>
      ),
    },
  ]

  return (
    <QueryState query={list}>
      {rows =>
        rows.length === 0 ?
          <EmptyState
            className="panel"
            icon={KeyIcon}
            title="No gateway keys yet"
            description="A gateway key lets an S3 client (aws, rclone, mc, backup tools) read and write bound buckets as a Vaulthalla user."
            action={
              <Button variant="secondary" onClick={onCreate}>
                <PlusIcon aria-hidden />
                Create key
              </Button>
            }
          />
        : <DataTable
            rows={rows}
            columns={columns}
            rowKey={c => c.id}
            onRowClick={onOpen}
            initialSort={{ key: 'name', dir: 'asc' }}
            filter={(c, q) => `${c.name} ${c.access_key} ${c.principal_user?.name ?? ''}`.toLowerCase().includes(q)}
            filterPlaceholder="Filter keys…"
            rowActions={c => (
              <DropdownMenu
                label={`Actions for ${c.name}`}
                trigger={
                  <IconButton label={`Actions for ${c.name}`} icon={EllipsisIcon} size="icon-sm" tooltip={false} />
                }
                entries={[
                  { key: 'open', label: 'Access & budget', icon: SlidersIcon, onSelect: () => onOpen(c) },
                  ...(c.enabled ?
                    [
                      'separator' as const,
                      {
                        key: 'revoke',
                        label: 'Revoke',
                        icon: BanIcon,
                        danger: true,
                        onSelect: () => void revokeCredential(c),
                      },
                    ]
                  : []),
                ]}
              />
            )}
          />
      }
    </QueryState>
  )
}
