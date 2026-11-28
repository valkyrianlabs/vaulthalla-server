'use client'

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import dynamic from 'next/dynamic'
import Link from 'next/link'
import { cn } from '@/util/cn'
import { useWs, useWsMutation } from '@/lib/query'
import { queryClient, wsKey } from '@/lib/query'
import { severityTone, toneClasses } from '@/lib/tone'
import { errorMessage } from '@/lib/ws/errors'
import { formatRelative } from '@/lib/format'
import { Button } from '@/components/ui/Button'
import { Field, Select } from '@/components/ui/Field'
import { Panel } from '@/components/ui/Panel'
import { InlineError, Skeleton } from '@/components/ui/State'
import { confirm } from '@/components/ui/Confirm'
import { notify } from '@/components/ui/Toast'
import { PlusIcon, SlidersIcon } from '@/components/ui/icons'
import { DASHBOARD_HOME_PREFERENCE_KEY } from '@/models/dashboard/dashboardPreferences'
import { DASHBOARD_LAYOUT_STORAGE_KEY, dashboardLayoutInstanceId } from '@/models/dashboard/dashboardLayout'
import {
  CATALOG_BY_ID,
  HERO_CARD_ID,
  PRESETS,
  defaultLayout,
  layoutFromCards,
  layoutKey,
  normalizeLayout,
  overviewPayload,
  sizesFor,
  toPreference,
  visibleCards,
  withMoved,
  type CardSize,
  type CardVariant,
  type LayoutCard,
} from '@/features/health/catalog'
import { useOverview } from '@/features/health/hooks'
import { HealthBadge, IssueList, LiveStatus, SeverityIcon } from '@/features/health/components'
import { OverviewCard, type CustomizeHandlers } from '@/features/health/OverviewCard'
import { healthHref, issueCountText, metricDisplay, metricTone, severityText, type Card, type Overview } from '@/features/health/model'
import { FindingsPanel } from '@/features/health/findings/FindingsPanel'
import { useHealthFindings } from '@/features/health/findings/queries'

const PREF = { preference_key: DASHBOARD_HOME_PREFERENCE_KEY }

const AddCardDialog = dynamic(() => import('@/features/health/AddCardDialog'), { ssr: false })

// A layout saved by the old console in this browser, used once when the account has none on the server.
const legacyLocalLayout = (): LayoutCard[] | null => {
  try {
    const raw = window.localStorage.getItem(DASHBOARD_LAYOUT_STORAGE_KEY)
    return raw ? normalizeLayout(JSON.parse(raw)) : null
  } catch {
    return null
  }
}

// The daemon's overall status in words. `info` means nothing is wrong but some cards carry notes (no traffic yet,
// telemetry warming up), so it doesn't read as an alert.
const headline = (status: Overview['overallStatus']) =>
  status === 'info' ? 'No issues' : status === 'healthy' ? 'Healthy' : status === 'unavailable' ? 'Not reporting' : severityText(status)

const Hero = ({
  overview,
  query,
  actions,
}: {
  overview: Overview | undefined
  query: Parameters<typeof LiveStatus>[0]['query'] & { isPending: boolean }
  actions: React.ReactNode
}) => {
  const hero = overview?.cards.find(card => card.id === HERO_CARD_ID)
  const status = overview?.overallStatus ?? 'unknown'
  const tone = toneClasses[severityTone(status)]
  const counts = overview ? issueCountText(overview.errorCount, overview.warningCount) : ''
  const failed = query.isError && !overview
  const sections = (overview?.sections ?? []).filter(s => s.id !== 'trends')

  return (
    <section aria-labelledby="health-status" className="glass relative overflow-hidden rounded-panel p-5 sm:p-6">
      {/* One soft glow in the backend's tone: the overview's single bit of drama. */}
      <div aria-hidden className={cn('pointer-events-none absolute -top-24 -left-16 size-72 rounded-full opacity-25 blur-3xl', tone.dot)} />
      <div className="relative flex flex-col gap-6 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs font-medium tracking-wide text-fg-subtle uppercase">
            Command center
            <LiveStatus query={query} className="normal-case" />
          </div>
          <div className="mt-3 flex items-center gap-3.5">
            <span className={cn('grid size-12 shrink-0 place-items-center rounded-2xl border', tone.border, tone.bg)}>
              {query.isPending ? null : <SeverityIcon severity={status} className="size-6" />}
            </span>
            <div className="min-w-0">
              <h2 id="health-status" className="text-2xl font-semibold tracking-tight text-fg">
                {query.isPending ? <Skeleton className="h-7 w-40" /> : failed ? 'Status unknown' : headline(status)}
              </h2>
              <p className="mt-0.5 text-sm text-fg-muted">
                {query.isPending
                  ? 'Asking the daemon…'
                  : failed
                    ? `The overview could not be loaded: ${errorMessage(query.error)}`
                    : counts || (status === 'unknown' || status === 'unavailable' ? 'Some telemetry is not reporting.' : 'No warnings or errors reported.')}
                {overview?.checkedAt ? <span className="text-fg-subtle"> · checked {formatRelative(overview.checkedAt)}</span> : null}
              </p>
            </div>
          </div>
          {hero?.metrics.length ? (
            <ul className="mt-4 flex flex-wrap gap-2" aria-label="Runtime readiness">
              {hero.metrics.map(metric => {
                const value = metricDisplay(metric)
                const t = metricTone(metric)
                return (
                  <li key={metric.key}>
                    <Link
                      href={healthHref(metric.href ?? hero.href, '/health/runtime#system-health')}
                      className="inline-flex h-7 items-center gap-2 rounded-full border border-line bg-surface-1 px-3 text-xs transition-colors hover:border-line-strong">
                      <span className="text-fg-subtle">{metric.label}</span>
                      <span className={cn('font-medium text-fg tabular', value === null && 'font-normal text-fg-faint', t && toneClasses[t].text)}>
                        {value ?? 'not available'}
                      </span>
                    </Link>
                  </li>
                )
              })}
            </ul>
          ) : null}
        </div>
        <div className="flex shrink-0 flex-col gap-3 lg:items-end">
          <div className="flex flex-wrap gap-2 lg:justify-end">{actions}</div>
          {sections.length ? (
            <ul className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:w-[26rem]" aria-label="Sections">
              {sections.map(section => {
                const st = toneClasses[severityTone(section.severity)]
                return (
                  <li key={section.id}>
                    <Link
                      href={healthHref(section.href)}
                      className="flex h-full flex-col rounded-card border border-line bg-surface-1 px-3 py-2 transition-colors hover:border-line-strong hover:bg-surface-2">
                      <span className="flex items-center gap-1.5 text-xs font-medium text-fg">
                        <span className={cn('size-1.5 shrink-0 rounded-full', st.dot)} aria-hidden />
                        {section.title}
                      </span>
                      <span className={cn('mt-0.5 truncate text-[11px]', section.errorCount || section.warningCount ? st.text : 'text-fg-subtle')}>
                        {issueCountText(section.errorCount, section.warningCount) || severityText(section.severity)}
                      </span>
                    </Link>
                  </li>
                )
              })}
            </ul>
          ) : null}
        </div>
      </div>
    </section>
  )
}

export function OverviewPage() {
  const prefs = useWs('dashboard.preferences.get', PREF, { staleTime: Infinity, retry: false })
  const [layout, setLayout] = useState<LayoutCard[] | null>(null)
  const [saved, setSaved] = useState<LayoutCard[] | null>(null)
  const [needsSave, setNeedsSave] = useState(false)
  const [customizing, setCustomizing] = useState(false)
  const [preset, setPreset] = useState('')
  const [adding, setAdding] = useState(false)
  const [dragId, setDragId] = useState<string | null>(null)
  const [dropId, setDropId] = useState<string | null>(null)
  const initialized = useRef(false)

  // The layout starts from the account's saved preference (or the old browser-local layout, or the default) once.
  useEffect(() => {
    if (initialized.current || prefs.isPending) return
    initialized.current = true
    const pref = prefs.data?.preferences
    let initial: LayoutCard[]
    let migrate = false
    if (pref?.exists && pref.layout && Array.isArray(pref.layout.cards)) initial = normalizeLayout(pref.layout)
    else {
      const local = legacyLocalLayout()
      migrate = Boolean(local)
      initial = local ?? defaultLayout()
    }
    setLayout(initial)
    setSaved(initial)
    setNeedsSave(migrate)
  }, [prefs.isPending, prefs.data])

  const current = layout ?? defaultLayout()
  const payload = useMemo(() => overviewPayload(current), [current])
  const overview = useOverview(payload, undefined, layout !== null)
  const data = overview.data
  // Findings with their state (health.findings.list). Until they load, or if they can't be, the overview's own
  // attention list stands in, without state or controls.
  const findings = useHealthFindings()

  const visible = useMemo(() => visibleCards(current), [current])
  const dirty = Boolean(layout && saved && layoutKey(layout) !== layoutKey(saved))

  // Response cards come back in request order (hero first); match by position, then by id + variant.
  const cardFor = useCallback(
    (lc: LayoutCard, index: number): Card | null => {
      if (!data) return null
      const cards = data.cards.filter(c => c.id !== HERO_CARD_ID)
      const byIndex = cards[index]
      if (byIndex && byIndex.id === lc.id && byIndex.variant === lc.variant) return byIndex
      return cards.find(c => c.id === lc.id && c.variant === lc.variant) ?? null
    },
    [data],
  )

  const attention = useMemo(() => {
    if (!data) return []
    const ids = new Set([HERO_CARD_ID, ...visible.map(c => c.id)])
    const seen = new Set<string>()
    return data.attention.filter(issue => {
      const key = `${issue.code}|${issue.message}`
      if (!ids.has(issue.cardId ?? '') || seen.has(key)) return false
      seen.add(key)
      return true
    })
  }, [data, visible])

  const update = (fn: (layout: LayoutCard[]) => LayoutCard[]) => {
    setPreset('')
    setLayout(prev => normalizeLayout(fn(prev ?? defaultLayout())))
  }

  const save = useWsMutation('dashboard.preferences.update', {
    toPayload: (next: LayoutCard[]) => ({ ...PREF, layout: toPreference(next) }),
    onSuccess: (response, next) => {
      const stored = response.preferences?.layout ? normalizeLayout(response.preferences.layout) : next
      queryClient.setQueryData(wsKey('dashboard.preferences.get', PREF), response)
      setLayout(stored)
      setSaved(stored)
      setNeedsSave(false)
    },
  })
  const reset = useWsMutation('dashboard.preferences.reset', { invalidates: ['dashboard.preferences.get'] })

  const onSave = async () => {
    if (!layout) return
    try {
      await save.mutateAsync(layout)
      setCustomizing(false)
      notify.success('Layout saved', 'It follows your account to any browser.')
    } catch (error) {
      notify.error(error, 'The layout could not be saved')
    }
  }

  const onCancel = () => {
    if (saved) setLayout(saved)
    setPreset('')
    setCustomizing(false)
  }

  const onReset = async () => {
    const ok = await confirm({
      title: 'Reset the overview layout?',
      description: 'Your saved card layout is deleted and the default cards come back.',
      confirmLabel: 'Reset layout',
      tone: 'danger',
    })
    if (!ok) return
    try {
      await reset.mutateAsync(PREF)
      try {
        window.localStorage.removeItem(DASHBOARD_LAYOUT_STORAGE_KEY)
      } catch {
        // Nothing stored.
      }
      const fresh = defaultLayout()
      setLayout(fresh)
      setSaved(fresh)
      setNeedsSave(false)
      setPreset('')
      setCustomizing(false)
      notify.success('Layout reset')
    } catch (error) {
      notify.error(error, 'The layout could not be reset')
    }
  }

  const addCard = (id: string, variant: CardVariant) => {
    const item = CATALOG_BY_ID.get(id)
    if (!item) return
    const sizes = sizesFor(item, variant)
    const size: CardSize = sizes.includes(item.defaultSize) ? item.defaultSize : sizes[0]
    update(prev => [
      ...visibleCards(prev),
      { instanceId: dashboardLayoutInstanceId(id, variant), id, size, variant, visible: true, order: visibleCards(prev).length },
    ])
    setAdding(false)
  }

  const handlers = (lc: LayoutCard, index: number): CustomizeHandlers => ({
    index,
    total: visible.length,
    onMove: (instanceId, to) => update(prev => withMoved(prev, instanceId, to)),
    onRemove: instanceId => update(prev => visibleCards(prev).filter(c => c.instanceId !== instanceId)),
    onSize: (instanceId, size) => update(prev => prev.map(c => (c.instanceId === instanceId ? { ...c, size } : c))),
    onVariant: (instanceId, variant) =>
      update(prev =>
        prev.some(c => c.visible && c.id === lc.id && c.variant === variant && c.instanceId !== instanceId)
          ? prev
          : prev.map(c => (c.instanceId === instanceId ? { ...c, variant, instanceId: dashboardLayoutInstanceId(c.id, variant) } : c)),
      ),
    onDragStart: setDragId,
    onDragEnter: instanceId => {
      if (!dragId || dragId === instanceId) return
      setDropId(instanceId)
      const to = visible.findIndex(c => c.instanceId === instanceId)
      update(prev => withMoved(prev, dragId, to))
    },
    onDragEnd: () => {
      setDragId(null)
      setDropId(null)
    },
    dragging: dragId === lc.instanceId,
    dropTarget: dropId === lc.instanceId && dragId !== lc.instanceId,
  })

  const heroActions = customizing ? null : (
    <Button variant="secondary" size="sm" onClick={() => setCustomizing(true)} disabled={!layout}>
      <SlidersIcon aria-hidden />
      Customize
    </Button>
  )

  return (
    <div className="space-y-5">
      <Hero overview={data} query={overview} actions={heroActions} />

      {customizing ? (
        <Panel className="glass" bodyClassName="flex flex-wrap items-end gap-3">
          <Field label="Start from a preset" htmlFor="health-preset" className="w-full sm:w-56">
            <Select
              id="health-preset"
              value={preset}
              onChange={event => {
                const next = PRESETS.find(p => p.id === event.target.value)
                if (!next) return
                setLayout(layoutFromCards(next.cards))
                setPreset(next.id)
              }}>
              <option value="">Current layout</option>
              {PRESETS.map(p => (
                <option key={p.id} value={p.id}>
                  {p.title}
                </option>
              ))}
            </Select>
          </Field>
          <Button variant="secondary" onClick={() => setAdding(true)}>
            <PlusIcon aria-hidden />
            Add card
          </Button>
          <p className="min-w-48 flex-1 text-xs text-fg-subtle">
            Drag a card&apos;s handle (or focus it and use the arrow keys) to reorder.
            {needsSave ? ' A layout from this browser was loaded; save it to keep it on your account.' : ''}
            {dirty ? ' Unsaved changes.' : ''}
          </p>
          <div className="flex flex-wrap gap-2">
            <Button variant="ghost" onClick={onReset} loading={reset.isPending}>
              Reset to default
            </Button>
            <Button variant="secondary" onClick={onCancel} disabled={save.isPending}>
              Cancel
            </Button>
            <Button variant="primary" onClick={onSave} loading={save.isPending} disabled={!dirty && !needsSave}>
              Save layout
            </Button>
          </div>
          {prefs.isError ? (
            <InlineError className="w-full" error={`Your saved layout could not be loaded (${errorMessage(prefs.error)}); showing the default.`} />
          ) : null}
        </Panel>
      ) : null}

      {findings.data ? (
        <FindingsPanel health={findings.data} />
      ) : attention.length ? (
        <Panel
          title={
            <span className="inline-flex items-center gap-2">
              Needs attention
              <HealthBadge severity={data?.overallStatus} errors={data?.errorCount} warnings={data?.warningCount} />
            </span>
          }
          bodyClassName="px-3 pb-2 pt-1">
          <IssueList issues={attention} limit={6} />
        </Panel>
      ) : null}

      <div className="grid grid-flow-row-dense auto-rows-[minmax(10.5rem,auto)] grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        {visible.map((lc, index) => {
          const item = CATALOG_BY_ID.get(lc.id)
          if (!item) return null
          const card = cardFor(lc, index)
          // No answer at all, or an answer that doesn't include this card: unknown, never an endless skeleton.
          const missing = (overview.isError && !data) || Boolean(data && !overview.isPlaceholderData && !card)
          return (
            <OverviewCard
              key={lc.instanceId}
              layout={lc}
              item={item}
              card={card}
              failed={missing}
              customize={customizing ? handlers(lc, index) : undefined}
            />
          )
        })}
      </div>

      {adding ? <AddCardDialog open onOpenChange={setAdding} layout={current} onAdd={addCard} /> : null}
    </div>
  )
}
