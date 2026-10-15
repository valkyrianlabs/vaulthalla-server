'use client'

import React, { useEffect, useState } from 'react'
import dynamic from 'next/dynamic'
import Link from 'next/link'
import { useWs } from '@/lib/query'
import { DASH, formatRelative } from '@/lib/format'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { IconButton } from '@/components/ui/IconButton'
import { Input } from '@/components/ui/Field'
import { DataTable, type Column } from '@/components/ui/DataTable'
import { DropdownMenu, type MenuEntry } from '@/components/ui/Menu'
import { PageHeader, Panel } from '@/components/ui/Panel'
import { Segmented } from '@/components/ui/Tabs'
import { EmptyState, QueryState } from '@/components/ui/State'
import {
  ArrowLeftIcon,
  BucketIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  EllipsisIcon,
  EyeIcon,
  LockIcon,
  ShieldCheckIcon,
  SlidersIcon,
  TrashIcon,
  RouteIcon,
  CircleXmarkIcon,
} from '@/components/ui/icons'
import { useCredential } from '@/features/credentials/useCredentials'
import {
  bucketStateLabel,
  bucketStateTone,
  eventStateTone,
  isBound,
  useUpstreamPerms,
} from '@/features/credentials/upstream/hooks'
import { BUCKET_STATES, type BucketRow, type BucketState } from '@/models/upstream'
import type { BucketActionKind } from '@/features/credentials/upstream/BucketActions'

// Every dialog and the inspect sheet live in one lazy chunk, loaded on the first action.
const BucketActions = dynamic(() => import('@/features/credentials/upstream/BucketActions'), { ssr: false })

const PAGE_SIZE = 200

type StateFilter = 'all' | BucketState

// Account-level inventory of an admin-enabled credential (#237): one ListBuckets page at a time, merged by the daemon
// with what Vaulthalla knows (managed, adopted, protected). Bucket names only; nothing here reads objects.
export const BucketsPage = ({ apiKeyId }: { apiKeyId: number }) => {
  const perms = useUpstreamPerms()
  const credential = useCredential(apiKeyId)
  const [state, setState] = useState<StateFilter>('all')
  const [filterText, setFilterText] = useState('')
  const [filter, setFilter] = useState('')
  // Page tokens seen so far; the last one is the page shown ('' = first page).
  const [tokens, setTokens] = useState<string[]>([''])
  const [action, setAction] = useState<{ kind: BucketActionKind; row: BucketRow } | null>(null)

  useEffect(() => {
    const t = setTimeout(() => setFilter(filterText.trim()), 300)
    return () => clearTimeout(t)
  }, [filterText])
  // A new filter starts from the first page.
  useEffect(() => setTokens(['']), [state, filter])

  const token = tokens[tokens.length - 1]
  const inventory = useWs(
    'upstream.bucket.list',
    {
      api_key_id: apiKeyId,
      max: PAGE_SIZE,
      ...(token ? { token } : {}),
      ...(state !== 'all' ? { state } : {}),
      ...(filter ? { filter } : {}),
    },
    { enabled: perms.view, retry: false, select: d => d.inventory, placeholderData: prev => prev },
  )

  const open = (kind: BucketActionKind, row: BucketRow) => setAction({ kind, row })

  const actionsFor = (row: BucketRow): MenuEntry[] => {
    const bound = isBound(row.vault_id)
    const owned = row.ownership === 'managed' || row.ownership === 'adopted'
    if (row.is_protected)
      return perms.unprotect ?
          [{ key: 'unprotect', label: 'Unprotect…', icon: ShieldCheckIcon, onSelect: () => open('unprotect', row) }]
        : [{ key: 'none', label: 'Protected: every action is blocked', disabled: true, onSelect: () => {} }]
    const entries: MenuEntry[] = []
    if (perms.view)
      entries.push({ key: 'inspect', label: 'Inspect', icon: EyeIcon, onSelect: () => open('inspect', row) })
    if (perms.configure && owned)
      entries.push({ key: 'lifecycle', label: 'Lifecycle…', icon: SlidersIcon, onSelect: () => open('lifecycle', row) })
    if (perms.provision && !owned && !bound)
      entries.push({ key: 'adopt', label: 'Adoption check…', icon: RouteIcon, onSelect: () => open('adopt', row) })
    if (perms.protect) {
      if (entries.length) entries.push('separator')
      entries.push({ key: 'protect', label: 'Protect…', icon: LockIcon, onSelect: () => open('protect', row) })
    }
    if (perms.destroy && owned && !bound) {
      entries.push('separator')
      entries.push({ key: 'detach', label: 'Detach…', icon: CircleXmarkIcon, onSelect: () => open('detach', row) })
      if (row.ownership === 'managed')
        entries.push({
          key: 'cleanup',
          label: 'Delete bucket…',
          icon: TrashIcon,
          danger: true,
          onSelect: () => open('cleanup', row),
        })
    }
    return entries
  }

  const columns: Column<BucketRow>[] = [
    {
      key: 'name',
      header: 'Bucket',
      sortValue: row => row.name,
      cell: row => (
        <span className="flex min-w-0 items-center gap-2">
          {row.is_protected ?
            <LockIcon className="text-warn size-3.5 shrink-0" aria-label="Protected" />
          : null}
          <span className="truncate font-mono text-[13px]" title={row.protection_reason ?? row.name}>
            {row.name}
          </span>
          {!row.listed ?
            <Badge tone="unknown" title="Known to Vaulthalla but not in the provider's listing">
              Not listed
            </Badge>
          : null}
        </span>
      ),
    },
    {
      key: 'state',
      header: 'State',
      sortValue: row => row.state,
      cell: row => (
        <Badge
          tone={bucketStateTone[row.state] ?? 'unknown'}
          title={row.is_protected ? (row.protection_reason ?? undefined) : undefined}>
          {bucketStateLabel[row.state] ?? row.state}
        </Badge>
      ),
    },
    {
      key: 'region',
      header: 'Region',
      hideBelow: 'md',
      cell: row => <span className="text-fg-muted font-mono text-xs">{row.region || DASH}</span>,
    },
    {
      key: 'vault',
      header: 'Vault',
      sortValue: row => row.vault_name ?? null,
      cell: row =>
        isBound(row.vault_id) ?
          <Link
            href={`/vaults/${row.vault_id}`}
            className="text-accent-text hover:underline"
            onClick={e => e.stopPropagation()}>
            {row.vault_name || `Vault ${row.vault_id}`}
          </Link>
        : <span className="text-fg-faint">{DASH}</span>,
    },
    {
      key: 'events',
      header: 'Events',
      hideBelow: 'lg',
      cell: row =>
        row.events_state ?
          <Badge tone={eventStateTone(row.events_state)} dot>
            {row.events_state}
          </Badge>
        : <span className="text-fg-faint">{DASH}</span>,
    },
    {
      key: 'seen',
      header: 'Last seen',
      hideBelow: 'lg',
      sortValue: row => row.last_seen_at ?? null,
      cell: row => <span className="tabular text-fg-subtle text-xs">{formatRelative(row.last_seen_at)}</span>,
    },
  ]

  const name = credential.data?.name || `Credential ${apiKeyId}`

  return (
    <>
      <Button asChild variant="ghost" size="sm" className="mb-3 -ml-2">
        <Link href={`/credentials/${apiKeyId}`}>
          <ArrowLeftIcon aria-hidden />
          {name}
        </Link>
      </Button>
      <PageHeader
        title="Upstream buckets"
        description={
          inventory.data ?
            `${inventory.data.provider || credential.data?.provider || ''} account ${inventory.data.account_ref || DASH}. Protected buckets are excluded from everything Vaulthalla does; their names still show here.`
          : 'Buckets this credential can see, and which ones Vaulthalla manages.'
        }
      />
      {!perms.view ?
        <Panel>
          <EmptyState
            icon={BucketIcon}
            title="You can’t view upstream buckets"
            description="Your role doesn’t include admin.upstream.view. Ask an administrator."
          />
        </Panel>
      : <Panel padded={false}>
          <div className="flex flex-wrap items-center gap-3 px-5 pt-4">
            <Segmented<StateFilter>
              label="Bucket state"
              value={state}
              onChange={setState}
              options={[
                { value: 'all', label: 'All' },
                ...BUCKET_STATES.map(s => ({ value: s, label: bucketStateLabel[s] })),
              ]}
            />
            <Input
              aria-label="Filter buckets by name"
              placeholder="Filter by name…"
              className="h-8 w-56"
              value={filterText}
              onChange={e => setFilterText(e.target.value)}
            />
          </div>
          <div className="px-2 pt-3 pb-2">
            <QueryState query={inventory}>
              {data =>
                data.buckets.length === 0 ?
                  <EmptyState
                    icon={BucketIcon}
                    title={state === 'all' && !filter ? 'No buckets in this account' : 'No buckets match'}
                    description={
                      state === 'all' && !filter ? 'Create one while creating a vault.' : 'Try another state or name.'
                    }
                  />
                : <DataTable
                    rows={data.buckets}
                    columns={columns}
                    rowKey={row => row.name}
                    initialSort={{ key: 'name', dir: 'asc' }}
                    onRowClick={row => (row.is_protected || !perms.view ? undefined : open('inspect', row))}
                    rowActions={row => {
                      const entries = actionsFor(row)
                      return entries.length ?
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
                            entries={entries}
                          />
                        : null
                    }}
                  />
              }
            </QueryState>
          </div>
          <div className="border-line flex items-center justify-between gap-2 border-t px-5 py-2.5">
            <span className="text-fg-subtle text-xs">Page {tokens.length}</span>
            <div className="flex gap-2">
              <Button
                size="sm"
                variant="ghost"
                disabled={tokens.length <= 1}
                onClick={() => setTokens(t => t.slice(0, -1))}>
                <ChevronLeftIcon aria-hidden />
                Previous
              </Button>
              <Button
                size="sm"
                variant="ghost"
                disabled={!inventory.data?.next_token || inventory.isFetching}
                onClick={() => inventory.data?.next_token && setTokens(t => [...t, inventory.data!.next_token])}>
                Next
                <ChevronRightIcon aria-hidden />
              </Button>
            </div>
          </div>
        </Panel>
      }
      {perms.view ?
        <AuditPanel accountRef={inventory.data?.account_ref} provider={inventory.data?.provider} />
      : null}
      {action ?
        <BucketActions
          apiKeyId={apiKeyId}
          provider={credential.data?.provider ?? ''}
          kind={action.kind}
          row={action.row}
          onClose={() => setAction(null)}
        />
      : null}
    </>
  )
}

const AuditPanel = ({ accountRef, provider }: { accountRef?: string; provider?: string }) => {
  const [open, setOpen] = useState(false)
  const audit = useWs(
    'upstream.audit.list',
    { limit: 100 },
    { enabled: open, retry: false, select: d => d.entries ?? [] },
  )
  const rows = (audit.data ?? []).filter(
    e => (!accountRef || e.account_ref === accountRef) && (!provider || !e.provider || e.provider === provider),
  )
  return (
    <Panel
      className="mt-4"
      title="Activity"
      description="Upstream changes and refusals recorded by the daemon for this account."
      actions={
        <Button size="sm" variant="ghost" onClick={() => setOpen(v => !v)}>
          {open ? 'Hide' : 'Show'}
        </Button>
      }>
      {open ?
        <QueryState query={audit}>
          {() =>
            rows.length === 0 ?
              <p className="text-fg-subtle text-sm">Nothing recorded yet.</p>
            : <ul className="divide-line divide-y text-sm">
                {rows.map(entry => (
                  <li key={entry.id} className="flex flex-wrap items-baseline gap-x-3 gap-y-1 py-2">
                    <span className="tabular text-fg-subtle w-28 shrink-0 text-xs">{formatRelative(entry.at)}</span>
                    <Badge
                      tone={
                        entry.outcome === 'ok' ? 'ok'
                        : entry.outcome === 'partial' ?
                          'warn'
                        : entry.outcome === 'refused' ?
                          'neutral'
                        : 'danger'
                      }>
                      {entry.outcome}
                    </Badge>
                    <span className="text-fg font-medium">{entry.action}</span>
                    {entry.bucket ?
                      <span className="text-fg-muted font-mono text-xs">{entry.bucket}</span>
                    : null}
                    <span className="text-fg-subtle text-xs">{entry.user_name ?? 'system'}</span>
                  </li>
                ))}
              </ul>
          }
        </QueryState>
      : null}
    </Panel>
  )
}
