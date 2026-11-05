'use client'

import React, { useMemo, useState } from 'react'
import { api } from '@/lib/session'
import { useWs, useWsMutation } from '@/lib/query'
import type { Response } from '@/lib/ws/client'
import { WsError } from '@/lib/ws/errors'
import { useCan } from '@/lib/permissions'
import { formatDateTime, formatInt } from '@/lib/format'
import { PageHeader, Panel } from '@/components/ui/Panel'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { DataTable, type Column } from '@/components/ui/DataTable'
import { Input, Select } from '@/components/ui/Field'
import { EmptyState, ErrorState, QueryState } from '@/components/ui/State'
import { notify } from '@/components/ui/Toast'
import type { Tone } from '@/lib/tone'

type AuditEvent = Response<'audit.list'>['events'][number]
type Verification = Response<'audit.verify'>['verification']

const AUDITS_VIEW = { permission: 'admin.audits.view' } as const
const PAGE = 100

const OUTCOME_TONE: Record<string, Tone> = { success: 'ok', failure: 'danger', denied: 'warn', info: 'neutral' }

const COLUMNS: Column<AuditEvent>[] = [
  { key: 'seq', header: '#', cell: e => <span className="tabular-nums text-fg-subtle">{e.seq}</span>, hideBelow: 'md' },
  { key: 'time', header: 'Time', cell: e => <span className="whitespace-nowrap">{formatDateTime(e.occurred_at)}</span> },
  { key: 'action', header: 'Action', cell: e => <code className="text-xs">{e.action}</code> },
  { key: 'outcome', header: 'Outcome', cell: e => <Badge tone={OUTCOME_TONE[e.outcome] ?? 'neutral'}>{e.outcome}</Badge> },
  { key: 'actor', header: 'Actor', cell: e => e.actor || '—', hideBelow: 'sm' },
  { key: 'message', header: 'Event', cell: e => <span className="break-words text-fg-muted">{e.message}</span> },
]

const VerificationPanel = ({ v }: { v: Verification }) => (
  <Panel className="mb-6">
    <div className="flex flex-wrap items-center gap-3">
      <Badge tone={v.ok ? 'ok' : 'danger'}>{v.ok ? 'Intact' : 'Failed verification'}</Badge>
      <span className="text-sm text-fg-muted">
        {formatInt(v.events_checked)} events checked
        {v.first_seq !== null ? ` (${v.first_seq}–${v.last_seq ?? v.first_seq})` : ''}; {formatInt(v.heads_valid)} signed
        head(s) valid, {formatInt(v.heads_invalid)} invalid; {formatInt(v.unsigned_events)} event(s) since the last
        signed head.
      </span>
    </div>
    {v.broken_at !== null ? (
      <p className="mt-3 text-sm text-danger">
        Broken at event {v.broken_at}: {v.problem}
      </p>
    ) : null}
    {v.head_problems.length ? (
      <ul className="mt-2 list-disc pl-5 text-sm text-danger">
        {v.head_problems.map(p => (
          <li key={p}>{p}</li>
        ))}
      </ul>
    ) : null}
  </Panel>
)

const downloadText = (name: string, text: string) => {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/x-ndjson' }))
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

// The tamper-evident audit trail (#323): every event hash-chained in the database, heads signed by this node.
export function AuditPage() {
  const canView = useCan(AUDITS_VIEW)
  const [action, setAction] = useState('')
  const [outcome, setOutcome] = useState('')
  const [older, setOlder] = useState<AuditEvent[]>([])
  const [nextBefore, setNextBefore] = useState<number | null | undefined>(undefined)
  const [loadingOlder, setLoadingOlder] = useState(false)
  const [exporting, setExporting] = useState(false)

  const filter = useMemo(
    () => ({ action: action.trim() || null, outcome: (outcome || null) as AuditEvent['outcome'] | null }),
    [action, outcome],
  )
  const first = useWs('audit.list', { ...filter, limit: PAGE }, { enabled: canView })
  const verify = useWsMutation('audit.verify')

  if (!canView) return <ErrorState error={new WsError('denied', 'The audit trail needs the "view audits" admin permission.')} />

  const cursor = nextBefore === undefined ? first.data?.next_before ?? null : nextBefore
  const loadOlder = async () => {
    if (cursor === null) return
    setLoadingOlder(true)
    try {
      const page = await api.send('audit.list', { ...filter, limit: PAGE, before_seq: cursor })
      setOlder(prev => [...prev, ...page.events])
      setNextBefore(page.next_before)
    } catch (error) {
      notify.error(error, 'Could not load older events')
    } finally {
      setLoadingOlder(false)
    }
  }

  const exportAll = async () => {
    setExporting(true)
    try {
      const res = await api.send('audit.export', {})
      downloadText(`vaulthalla-audit-${new Date().toISOString().slice(0, 10)}.ndjson`, res.ndjson)
      notify.success(`Exported ${formatInt(res.events)} events`, 'Verify the file offline with tools/audit/verify_export.py.')
    } catch (error) {
      notify.error(error, 'Export failed')
    } finally {
      setExporting(false)
    }
  }

  const resetPaging = () => {
    setOlder([])
    setNextBefore(undefined)
  }

  return (
    <div className="w-full">
      <PageHeader
        title="Audit trail"
        description="Who did what, when. Every event is hash-chained and the chain head is signed by this server, so edits, insertions and deletions are detectable. Files are named by id, never by name."
        actions={
          <>
            <Button variant="secondary" loading={verify.isPending} onClick={() => verify.mutate(null)}>
              Verify chain
            </Button>
            <Button variant="secondary" loading={exporting} onClick={() => void exportAll()}>
              Export
            </Button>
          </>
        }
      />
      {verify.data ? <VerificationPanel v={verify.data.verification} /> : null}
      {verify.error ? <ErrorState className="mb-6" error={verify.error} /> : null}

      <div className="mb-4 flex flex-wrap gap-3">
        <Input
          aria-label="Action prefix"
          placeholder="Action prefix (auth., rbac., fs.)"
          className="w-64"
          value={action}
          onChange={e => {
            setAction(e.target.value)
            resetPaging()
          }}
        />
        <Select
          aria-label="Outcome"
          className="w-40"
          value={outcome}
          onChange={e => {
            setOutcome(e.target.value)
            resetPaging()
          }}
        >
          <option value="">Any outcome</option>
          <option value="success">Success</option>
          <option value="failure">Failure</option>
          <option value="denied">Denied</option>
          <option value="info">Info</option>
        </Select>
      </div>

      <QueryState query={first}>
        {data => {
          const rows = [...data.events, ...older]
          if (!rows.length) return <EmptyState title="No audit events" description="Nothing matches these filters." />
          return (
            <>
              <DataTable rows={rows} columns={COLUMNS} rowKey={e => e.seq} />
              {cursor !== null ? (
                <div className="mt-4 flex justify-center">
                  <Button variant="ghost" loading={loadingOlder} onClick={() => void loadOlder()}>
                    Load older events
                  </Button>
                </div>
              ) : null}
            </>
          )
        }}
      </QueryState>
    </div>
  )
}
