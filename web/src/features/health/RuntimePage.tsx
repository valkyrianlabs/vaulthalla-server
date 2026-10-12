'use client'

import React from 'react'
import { cn } from '@/util/cn'
import { useWs } from '@/lib/query'
import { DataTable, type Column } from '@/components/ui/DataTable'
import { Badge } from '@/components/ui/Badge'
import { DefinitionList } from '@/components/ui/Panel'
import { StatGrid, StatTile } from '@/components/ui/Stat'
import { formatDuration, formatInt, titleCase } from '@/lib/format'
import { detailPoll, useHealthCards } from '@/features/health/hooks'
import { Fact, HealthSection, SubHeading } from '@/features/health/components'
import { Donut } from '@/features/health/charts'
import { statusTone } from '@/features/health/model'
import { bool, int, num, obj, pair, seconds, type Raw } from '@/features/health/read'

const CARDS = ['system.health', 'system.threadpools', 'system.connections']


// A string value is a neutral statement (e.g. "Disabled in this build"), not a yes/no fact.
const FactGrid = ({ items, className = 'sm:grid-cols-2 xl:grid-cols-3' }: { items: [string, boolean | string | null, string?, string?][]; className?: string }) => (
  <ul className={cn('grid grid-cols-1 gap-2 text-sm', className)}>
    {items.map(([label, value, yes, no]) => (
      <li key={label} className="flex items-center justify-between gap-3 rounded-control bg-surface-1 px-3 py-2">
        <span className="truncate text-fg-muted">{label}</span>
        {typeof value === 'string' ? <span className="text-fg-muted">{value}</span> : <Fact value={value} yes={yes} no={no} />}
      </li>
    ))}
  </ul>
)

const DEP_LABELS: Record<string, string> = {
  storage_manager: 'Storage manager',
  api_key_manager: 'Provider credentials',
  auth_manager: 'Auth manager',
  session_manager: 'Session manager',
  secrets_manager: 'Secrets manager',
  sync_controller: 'Sync controller',
  fs_cache: 'FS cache',
  shell_usage_manager: 'Shell usage',
  http_cache_stats: 'HTTP cache stats',
  fuse_session: 'FUSE session',
}

// Configured mode next to what the mount actually is (the backend never reports a configured mount as mounted).
const mountSummary = (deps: Raw): string => {
  const mode = String(deps.fuse_mount)
  const state = typeof deps.mount_state === 'string' ? deps.mount_state : null
  if (mode === 'disabled') return 'Disabled'
  if (!state) return mode
  const label = state === 'mounted' ? `${mode}: mounted` : `${mode}: ${state.replace('_', ' ')}`
  const isolation = state === 'mounted' && typeof deps.mount_isolation === 'string' ? ` (isolation ${deps.mount_isolation})` : ''
  const detail = state !== 'mounted' && typeof deps.mount_detail === 'string' ? ` — ${deps.mount_detail}` : ''
  return label + isolation + detail
}

const SystemHealthBody = ({ stats }: { stats: Raw }) => {
  const summary = obj(stats.summary)
  const runtime = obj(stats.runtime)
  const protocols = obj(stats.protocols)
  const deps = obj(stats.deps)
  const shell = obj(stats.shell)
  const db = stats.database ? obj(stats.database) : null
  const gateway = stats.s3_gateway ? obj(stats.s3_gateway) : null
  const services = Array.isArray(runtime.services) ? runtime.services.map(obj) : []
  const adminBound = bool(shell.admin_uid_bound)

  return (
    <div className="space-y-6">
      <StatGrid>
        <StatTile label="Services running" value={pair(summary.services_ready, summary.services_total, '/')} />
        <StatTile label="Protocols ready" value={pair(summary.protocols_ready, summary.protocols_total, '/')} />
        <StatTile label="Dependencies ready" value={pair(summary.deps_ready, summary.deps_total, '/')} />
        <StatTile label="CLI shell admin" value={adminBound === null ? null : adminBound ? 'Bound' : 'Not configured'} />
      </StatGrid>

      <div>
        <SubHeading>Runtime services</SubHeading>
        <FactGrid
          items={services.map(s => [
            String(s.entry_name ?? s.service_name ?? 'service'),
            s.interrupted === true ? false : bool(s.running),
            'Running',
            s.interrupted === true ? 'Interrupted' : 'Stopped',
          ])}
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <div>
          <SubHeading>Protocols</SubHeading>
          <FactGrid
            className="sm:grid-cols-2"
            items={[
              ['Protocol service', bool(protocols.running), 'Running', 'Stopped'],
              ['I/O context', bool(protocols.io_context_initialized), 'Initialized', 'Not initialized'],
              ['WebSocket', protocols.websocket_configured === false ? null : bool(protocols.websocket_ready)],
              ['HTTP preview', protocols.http_preview_configured === false ? null : bool(protocols.http_preview_ready)],
            ]}
          />
        </div>
        <div>
          <SubHeading>Dependencies</SubHeading>
          <FactGrid
            className="sm:grid-cols-2"
            items={[
              ...Object.keys(DEP_LABELS)
                .filter(k => k in deps && !(k === 'fuse_session' && deps.fuse_mount === 'disabled'))
                .map((k): [string, boolean | null] => [DEP_LABELS[k], bool(deps[k])]),
              ...(typeof deps.fuse_mount === 'string' ? [['Filesystem mount', mountSummary(deps)] as [string, string]] : []),
              ...(typeof deps.secrets_backend === 'string' && deps.secrets_backend
                ? [['Secrets backend', deps.secrets_backend === 'file' ? 'file (development, no hardware binding)' : deps.secrets_backend] as [string, string]]
                : []),
            ]}
          />
        </div>
      </div>

      {db ? (
        <div>
          <SubHeading>Database pool</SubHeading>
          <StatGrid className="xl:grid-cols-5">
            <StatTile label="Reachable" value={<Fact value={bool(db.reachable)} yes="Yes" no="No" />} />
            <StatTile label="In use / pool" value={pair(db.in_use, db.pool_size)} />
            <StatTile label="Idle" value={int(db.idle)} />
            <StatTile label="Probe latency" value={num(db.probe_latency_ms) !== null ? `${db.probe_latency_ms} ms` : null} />
            <StatTile label="Acquire timeouts" value={int(db.acquire_timeouts)} />
            <StatTile label="Broken idle" value={int(db.broken_idle)} />
            <StatTile label="Reconnects" value={int(db.reconnects)} />
            <StatTile label="Reconnect failures" value={int(db.reconnect_failures)} hint={num(db.consecutive_reconnect_failures) ? `${db.consecutive_reconnect_failures} in a row` : undefined} />
          </StatGrid>
          {typeof db.probe_error === 'string' && db.probe_error ? (
            <p className="mt-2 rounded-control border border-line bg-surface-1 px-3 py-2 font-mono text-xs text-fg-muted">{db.probe_error}</p>
          ) : null}
        </div>
      ) : null}

      {gateway ? (
        <div>
          <SubHeading>S3 gateway</SubHeading>
          <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,2fr)]">
            <DefinitionList
              items={[
                ['Configured', <Fact key="c" value={bool(gateway.configured)} yes="Yes" no="No" />],
                ['Running', <Fact key="r" value={bool(gateway.running)} yes="Running" no="Stopped" />],
                ['Ready', <Fact key="y" value={bool(gateway.ready)} />],
                ['Listening on', typeof gateway.host === 'string' && num(gateway.port) !== null ? <span className="font-mono text-xs tabular">{`${gateway.host}:${gateway.port}`}</span> : <span className="text-fg-faint">not available</span>],
              ]}
            />
            <StatGrid className="sm:grid-cols-3 xl:grid-cols-3">
              <StatTile label="Active sessions" value={int(gateway.active_sessions)} />
              <StatTile label="Requests" value={int(gateway.total_requests)} />
              <StatTile label="Failed requests" value={int(gateway.failed_requests)} />
            </StatGrid>
          </div>
        </div>
      ) : null}
    </div>
  )
}

interface Pool {
  name: string
  status: string
  worker_count: number | null
  busy_worker_count: number | null
  idle_worker_count: number | null
  queue_depth: number | null
  pressure_ratio: number | null
  stopped: boolean | null
}

const poolColumns: Column<Pool>[] = [
  { key: 'name', header: 'Pool', cell: p => <span className="font-medium text-fg">{p.name}</span>, sortValue: p => p.name },
  { key: 'status', header: 'Status', cell: p => <Badge tone={statusTone(p.status)} dot>{p.stopped ? 'Stopped' : titleCase(p.status || 'unknown')}</Badge> },
  { key: 'workers', header: 'Workers', cell: p => <span className="tabular">{formatInt(p.worker_count)}</span>, sortValue: p => p.worker_count, className: 'text-right', headerClassName: 'text-right', hideBelow: 'sm' },
  { key: 'busy', header: 'Busy', cell: p => <span className="tabular">{formatInt(p.busy_worker_count)}</span>, sortValue: p => p.busy_worker_count, className: 'text-right', headerClassName: 'text-right', hideBelow: 'sm' },
  { key: 'idle', header: 'Idle', cell: p => <span className="tabular">{formatInt(p.idle_worker_count)}</span>, className: 'text-right', headerClassName: 'text-right', hideBelow: 'md' },
  { key: 'queue', header: 'Queue', cell: p => <span className="tabular">{formatInt(p.queue_depth)}</span>, sortValue: p => p.queue_depth, className: 'text-right', headerClassName: 'text-right' },
  {
    key: 'pressure',
    header: 'Pressure',
    cell: p => <span className="tabular">{p.pressure_ratio === null ? '—' : `${p.pressure_ratio.toFixed(2)}×`}</span>,
    sortValue: p => p.pressure_ratio,
    className: 'text-right',
    headerClassName: 'text-right',
  },
]

const ThreadPoolsBody = ({ stats }: { stats: Raw }) => {
  const pools: Pool[] = (Array.isArray(stats.pools) ? stats.pools : []).map(raw => {
    const p = obj(raw)
    return {
      name: String(p.name ?? ''),
      status: typeof p.status === 'string' ? p.status : 'unknown',
      worker_count: num(p.worker_count),
      busy_worker_count: num(p.busy_worker_count),
      idle_worker_count: num(p.idle_worker_count),
      queue_depth: num(p.queue_depth),
      pressure_ratio: num(p.pressure_ratio),
      stopped: bool(p.stopped),
    }
  })
  const max = num(stats.max_pressure_ratio)
  return (
    <div className="space-y-4">
      <StatGrid className="xl:grid-cols-5">
        <StatTile label="Workers" value={int(stats.total_worker_count)} hint={num(stats.total_idle_worker_count) !== null ? `${stats.total_idle_worker_count} idle` : undefined} />
        <StatTile label="Queued tasks" value={int(stats.total_queue_depth)} />
        <StatTile label="Max pressure" value={max === null ? null : `${max.toFixed(2)}×`} hint="queued work per worker" />
        <StatTile label="Pressured pools" value={int(stats.pressured_pool_count)} />
        <StatTile label="Saturated pools" value={int(stats.saturated_pool_count)} />
      </StatGrid>
      <DataTable rows={pools} columns={poolColumns} rowKey={p => p.name} empty="No thread pools reported." />
    </div>
  )
}

const ConnectionsBody = ({ stats }: { stats: Raw }) => {
  const modes = [
    { label: 'Human', value: num(stats.active_human_sessions) },
    { label: 'Share', value: num(stats.active_share_sessions) },
    { label: 'Share pending', value: num(stats.active_share_pending_sessions) },
    { label: 'Unauthenticated', value: num(stats.active_unauthenticated_sessions) },
  ]
  const total = num(stats.active_ws_sessions_total)
  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.6fr)]">
      <Donut data={modes} center={total ?? '—'} caption="sessions" label="Websocket sessions by mode" />
      <div className="space-y-4">
        <StatGrid className="sm:grid-cols-3 xl:grid-cols-3">
          <StatTile label="Oldest session" value={seconds(stats.oldest_session_age_seconds)} />
          <StatTile label="Oldest unauthenticated" value={num(stats.oldest_unauthenticated_session_age_seconds) === null && num(stats.active_unauthenticated_sessions) === 0 ? 'none' : seconds(stats.oldest_unauthenticated_session_age_seconds)} />
          <StatTile label="Idle timeout" value={num(stats.idle_timeout_minutes) === null ? null : formatDuration(Number(stats.idle_timeout_minutes) * 60)} />
          <StatTile label="Unauthenticated timeout" value={seconds(stats.unauthenticated_timeout_seconds)} />
          <StatTile label="Sweep interval" value={seconds(stats.sweep_interval_seconds)} />
          <StatTile label="Errors (24 h)" value={int(stats.connection_errors_24h)} />
        </StatGrid>
        <p className="text-xs text-fg-subtle">
          24-hour open/close counters and client breakdowns are not collected by this daemon yet; they show as not available.
        </p>
      </div>
    </div>
  )
}

export function RuntimePage() {
  const { cards, pending } = useHealthCards(CARDS)
  const health = useWs('stats.system.health', null, detailPoll)
  const pools = useWs('stats.system.threadpools', null, detailPoll)
  const connections = useWs('stats.system.connections', null, detailPoll)
  return (
    <div className="space-y-5">
      <HealthSection id="system-health" title="System health" card={cards.get('system.health')} cardPending={pending} query={health}>
        {data => <SystemHealthBody stats={obj(data.stats)} />}
      </HealthSection>
      <HealthSection id="thread-pools" title="Thread pools" card={cards.get('system.threadpools')} cardPending={pending} query={pools}>
        {data => <ThreadPoolsBody stats={obj(data.stats)} />}
      </HealthSection>
      <HealthSection id="connections" title="Connections" card={cards.get('system.connections')} cardPending={pending} query={connections}>
        {data => <ConnectionsBody stats={obj(data.stats)} />}
      </HealthSection>
    </div>
  )
}
