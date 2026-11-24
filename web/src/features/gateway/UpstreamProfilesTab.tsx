'use client'

import React from 'react'
import { api } from '@/lib/session'
import { DataTable, type Column } from '@/components/ui/DataTable'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { EmptyState, QueryState } from '@/components/ui/State'
import { confirm } from '@/components/ui/Confirm'
import { notify } from '@/components/ui/Toast'
import { CloudIcon, PenIcon, PlusIcon, TrashIcon } from '@/components/ui/icons'
import { DASH } from '@/lib/format'
import { Section } from '@/features/cost/bits'
import { CONFLICT_OPTIONS, STRATEGY_OPTIONS } from '@/features/vaults/syncPolicy'
import type { UpstreamProfile } from '@/features/gateway/model'
import { refreshProfiles, useGatewayPerms, useUpstreamProfiles } from '@/features/gateway/queries'

const remove = async (p: UpstreamProfile) => {
  const ok = await confirm({
    title: `Delete upstream profile “${p.name}”?`,
    description: 'Buckets already created from it stay as they are. Keys that use it must be pointed elsewhere first.',
    confirmLabel: 'Delete profile',
  })
  if (!ok) return
  try {
    await api.send('s3.gateway.upstreamProfiles.delete', { profile_id: p.id })
    await refreshProfiles()
    notify.success('Profile deleted', p.name)
  } catch (error) {
    notify.error(error, 'Could not delete the profile')
  }
}

export const syncSummary = (p: UpstreamProfile) =>
  `${STRATEGY_OPTIONS.find(o => o.value === p.sync_strategy)?.label ?? p.sync_strategy ?? DASH}, ${
    CONFLICT_OPTIONS.find(o => o.value === p.conflict_policy)?.label ?? p.conflict_policy ?? DASH
  }`

export const UpstreamProfilesTab = ({ onEdit }: { onEdit: (profile: UpstreamProfile | null) => void }) => {
  const can = useGatewayPerms()
  const query = useUpstreamProfiles()
  const columns: Column<UpstreamProfile>[] = [
    {
      key: 'name',
      header: 'Profile',
      sortValue: p => p.name,
      cell: p => (
        <span className="flex flex-wrap items-center gap-2">
          <span className="text-fg font-mono text-sm" data-testid="s3-gateway-upstream-profile">
            {p.name}
          </span>
          {p.server_default ?
            <Badge tone="accent">Server default</Badge>
          : null}
        </span>
      ),
    },
    {
      key: 'key',
      header: 'Provider credential',
      sortValue: p => p.api_key_name,
      cell: p => (
        <span className="text-fg-muted">
          {p.api_key_name ?? `#${p.api_key_id ?? DASH}`}
          {p.provider ?
            <span className="text-fg-subtle"> · {p.provider}</span>
          : null}
        </span>
      ),
    },
    {
      key: 'encryption',
      header: 'Upstream encryption',
      hideBelow: 'md',
      cell: p => (
        <span className="text-fg-subtle">
          {p.encrypt_upstream === null ?
            DASH
          : p.encrypt_upstream ?
            'On'
          : 'Off'}
        </span>
      ),
    },
    { key: 'sync', header: 'Sync', hideBelow: 'md', cell: p => <span className="text-fg-subtle">{syncSummary(p)}</span> },
    {
      key: 'bucket',
      header: 'Upstream bucket',
      hideBelow: 'lg',
      cell: p => <span className="text-fg-subtle font-mono text-xs">{p.bucket_prefix}&lt;bucket&gt;</span>,
    },
  ]
  return (
    <Section
      id="upstream-profiles"
      title="Upstream profiles"
      description={
        <span>
          What a CreateBucket through the gateway creates. A key with a profile gets an S3 vault over a new bucket in
          that provider account instead of a local vault; clients can also pick a profile per request by sending its
          name as their region.
          {query.data?.default_profile ? ` Server default: ${query.data.default_profile}.` : ''}
        </span>
      }
      actions={
        can.buckets ?
          <Button size="sm" variant="secondary" data-testid="s3-gateway-open-upstream-profile" onClick={() => onEdit(null)}>
            <PlusIcon aria-hidden />
            New profile
          </Button>
        : null
      }>
      <div data-testid="s3-gateway-section-upstream-profiles">
        <QueryState query={query}>
          {data =>
            data.profiles.length === 0 ?
              <EmptyState
                className="panel"
                icon={CloudIcon}
                title="No upstream profiles"
                description="Without one, every bucket an S3 client creates is a local vault. Add a profile to create buckets in a provider account instead."
              />
            : <DataTable
                rows={data.profiles}
                columns={columns}
                rowKey={p => String(p.id)}
                initialSort={{ key: 'name', dir: 'asc' }}
                rowActions={p =>
                  can.buckets ?
                    <span className="flex items-center gap-1">
                      <Button size="icon-sm" variant="ghost" aria-label={`Edit ${p.name}`} onClick={() => onEdit(p)}>
                        <PenIcon aria-hidden />
                      </Button>
                      <Button size="icon-sm" variant="ghost" aria-label={`Delete ${p.name}`} onClick={() => void remove(p)}>
                        <TrashIcon aria-hidden />
                      </Button>
                    </span>
                  : null
                }
              />
          }
        </QueryState>
      </div>
    </Section>
  )
}
