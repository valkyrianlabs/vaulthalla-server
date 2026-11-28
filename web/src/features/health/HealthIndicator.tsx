'use client'

import React from 'react'
import Link from 'next/link'
import { cn } from '@/util/cn'
import { useWs } from '@/lib/query'
import { STATS_VIEW, useCan } from '@/lib/permissions'
import { toneClasses } from '@/lib/tone'
import { isWsError } from '@/lib/ws/errors'
import { badgeFor } from '@/features/health/findings/model'
import { useHealthPush } from '@/features/health/findings/push'

const POLL_MS = 30_000

// Daemons without stats.dashboard.severity answer "Unknown command"; the indicator then stays out of the way.
const unsupported = (error: unknown) => isWsError(error) && /unknown command/i.test(error.message)

// Top-bar health dot for accounts with admin.stats.view. Reads the cheap severity rollup only (never the full
// overview) and links to /health. It counts what nobody has acknowledged or silenced (the unattended counts,
// design/health/findings.md §3); the health pages keep the true severity. It follows health.changed while the server
// pushes it and polls only otherwise. Renders nothing without the permission, on daemons without the command, and
// before the first answer.
export const HealthIndicator = ({ className }: { className?: string }) => {
  const canView = useCan(STATS_VIEW)
  const pushed = useHealthPush(canView)
  const query = useWs('stats.dashboard.severity', null, {
    enabled: canView,
    staleTime: pushed ? Infinity : POLL_MS - 5_000,
    retry: false,
    refetchInterval: q => (pushed || unsupported(q.state.error) || isWsError(q.state.error, 'denied') ? false : POLL_MS),
  })

  if (!canView || query.isPending) return null
  if (query.error && (unsupported(query.error) || isWsError(query.error, 'denied'))) return null

  // A failed refresh keeps the last answer only while it is still fresh enough to trust; otherwise it's unknown.
  const raw = query.data as { stats?: Record<string, unknown> } & Record<string, unknown> | undefined
  const badge = badgeFor((raw?.stats ?? raw) as Record<string, unknown> | undefined, query.isError)
  const tone = toneClasses[badge.tone]

  return (
    <Link
      href="/health"
      title={badge.title}
      aria-label={badge.title}
      className={cn(
        'inline-flex h-8 items-center gap-2 rounded-full border border-line bg-surface-1 px-2.5 text-xs text-fg-muted transition-colors hover:border-line-strong hover:text-fg',
        className,
      )}>
      <span className="relative flex size-2 shrink-0" aria-hidden>
        {badge.alert ? <span className={cn('absolute inline-flex size-full animate-ping rounded-full opacity-60', tone.dot)} /> : null}
        <span className={cn('relative inline-flex size-2 rounded-full', tone.dot)} />
      </span>
      <span className={cn('hidden whitespace-nowrap sm:inline', (badge.tone === 'danger' || badge.tone === 'warn') && tone.text)}>{badge.label}</span>
    </Link>
  )
}
