// Health findings in the console (design/health/findings.md §3, §8, §11; ws health.*): what each finding's state
// reads as, which controls an account gets, the silence lengths, the note limit, the two lists and the top bar badge.
// The server owns severity and state; nothing here invents either. Pure: see model.test.ts.
import type { WsModels } from '@/util/generated/wsContract'
import { formatDateTime, formatRelative } from '../../../lib/format.ts'
import { FINDINGS_COPY as C, SILENCE_LABELS } from './copy.ts'

export type HealthFindings = WsModels['HealthFindings']
export type Finding = WsModels['HealthFinding']
export type Mark = WsModels['HealthFindingMark']
export type Remedy = WsModels['HealthRemedy']
export type FindingSeverity = Finding['severity']

// The one read every health view shares: the catalog rides along for the titles of silences whose class is not active.
export const FINDINGS_PAYLOAD = { include_catalog: true } as const
// meta.hello capability for health.subscribe / health.changed (§6).
export const PUSH_CAPABILITY = 'health.push'
// core ops::health kMaxNoteLength. The server counts the trimmed note's UTF-8 bytes, so that is what is counted here.
export const NOTE_MAX = 500

export type SilenceChoice = keyof typeof SILENCE_LABELS
export const SILENCE_CHOICES: { id: SilenceChoice; label: string; seconds: number | null }[] = [
  { id: 'hour', label: SILENCE_LABELS.hour, seconds: 3_600 },
  { id: 'day', label: SILENCE_LABELS.day, seconds: 86_400 },
  { id: 'week', label: SILENCE_LABELS.week, seconds: 7 * 86_400 },
  { id: 'forever', label: SILENCE_LABELS.forever, seconds: null },
]

const who = (mark: Pick<Mark, 'set_by_name'>) => mark.set_by_name || C.someone

// A mark in words: who acknowledged it and when, or who silenced it and until when.
export const markText = (mark: Pick<Mark, 'state' | 'set_by_name' | 'set_at' | 'expires_at'>, now = Date.now()) => {
  if (mark.state === 'acknowledged') return C.acknowledged(who(mark), formatRelative(mark.set_at, '', now))
  return mark.expires_at ? C.silencedUntil(who(mark), formatDateTime(mark.expires_at)) : C.silencedForever(who(mark))
}

// A finding's state in words. The state is the server's: an `active` finding has no mark that covers it.
export const stateText = (finding: Pick<Finding, 'state' | 'mark'>, now = Date.now()) =>
  finding.state === 'active' || !finding.mark ? C.active : markText(finding.mark, now)

// Remedies the console offers as links (§8): kind `open` with a console route. A `command` remedy names a ws command
// this list does not run, and an href that is not a path on this console is never made a link.
export const openRemedies = (remedies: Remedy[]): (Remedy & { href: string })[] =>
  remedies.filter((r): r is Remedy & { href: string } => r.kind === 'open' && typeof r.href === 'string' && /^\/(?!\/)/.test(r.href))

export interface Controls {
  acknowledge: boolean
  silence: boolean
  turnBackOn: boolean
  remedies: (Remedy & { href: string })[]
}

// Which controls apply (§3, §4, §11). Without admin.stats.manage (`can_manage`) there are none. Acknowledging is only
// for an active finding (the server refuses a silenced one); a silence can replace an acknowledgement; Turn back on
// removes either.
export const controlsFor = (finding: Pick<Finding, 'state' | 'remedies'>, canManage: boolean): Controls => {
  const none: Controls = { acknowledge: false, silence: false, turnBackOn: false, remedies: [] }
  if (!canManage) return none
  const remedies = openRemedies(finding.remedies)
  switch (finding.state) {
    case 'active':
      return { acknowledge: true, silence: true, turnBackOn: false, remedies }
    case 'acknowledged':
      return { acknowledge: false, silence: true, turnBackOn: true, remedies }
    case 'silenced':
      return { acknowledge: false, silence: false, turnBackOn: true, remedies }
    default:
      return none
  }
}

// The trimmed note as the server stores it, its length as the server counts it, and whether it is too long.
export const noteOf = (raw: string) => {
  const text = raw.trim()
  const length = new TextEncoder().encode(text).length
  return { text: text || null, length, tooLong: length > NOTE_MAX }
}

export const silencePayload = (finding: Pick<Finding, 'class' | 'subject'>, choice: SilenceChoice, note: string) => {
  const seconds = SILENCE_CHOICES.find(c => c.id === choice)?.seconds ?? null
  const { text } = noteOf(note)
  return {
    class: finding.class,
    ...(finding.subject ? { subject: finding.subject } : {}),
    ...(seconds === null ? {} : { for_seconds: seconds }),
    ...(text ? { note: text } : {}),
  }
}

const RANK: Record<string, number> = { error: 2, warning: 1 }
const STATE_RANK: Record<string, number> = { active: 0, acknowledged: 1, silenced: 2 }

export interface SilencedRow {
  key: string
  class: string
  subject: string
  title: string
  severity: FindingSeverity
  // The finding is raised right now (a silenced finding), or only its silence is set (§3: it survives a clear).
  activeNow: boolean
  mark: Mark
}

// "Needs attention" (every finding that is not silenced: worst first, unacknowledged before acknowledged) and
// "Silenced" (silenced findings, then silences whose class is not active). Nothing is dropped.
export const splitFindings = (health: HealthFindings) => {
  const titles = new Map((health.catalog ?? []).map(c => [c.class, c.title]))
  const attention = health.findings
    .filter(f => f.state !== 'silenced')
    .sort((a, b) => (RANK[b.severity] ?? 0) - (RANK[a.severity] ?? 0) || (STATE_RANK[a.state] ?? 0) - (STATE_RANK[b.state] ?? 0))
  const silenced: SilencedRow[] = [
    ...health.findings
      .filter((f): f is Finding & { mark: Mark } => f.state === 'silenced' && f.mark !== null)
      .map(f => ({ key: `${f.class}|${f.subject}`, class: f.class, subject: f.subject, title: f.class_title || f.title, severity: f.severity, activeNow: true, mark: f.mark })),
    ...health.silences.map(m => ({
      key: `${m.class}|${m.subject}`,
      class: m.class,
      subject: m.subject,
      title: titles.get(m.class) ?? m.class,
      severity: m.severity,
      activeNow: false,
      mark: m,
    })),
  ]
  return { attention, silenced }
}

// A mutation's answer is the whole HealthFindings without the catalog: keep the catalog the cache already has.
export const mergeAnswer = (previous: HealthFindings | undefined, next: HealthFindings): HealthFindings =>
  next.catalog || !previous?.catalog ? next : { ...next, catalog: previous.catalog }

// The severity rollup (stats.dashboard.severity, or a health.changed event) these answers imply.
export const severityOf = (h: Pick<HealthFindings, 'overall_status' | 'error_count' | 'warning_count' | 'unattended_error_count' | 'unattended_warning_count' | 'checked_at'>) => ({
  overall_status: h.overall_status,
  error_count: h.error_count,
  warning_count: h.warning_count,
  unattended_error_count: h.unattended_error_count,
  unattended_warning_count: h.unattended_warning_count,
  checked_at: h.checked_at,
})

export type BadgeTone = 'ok' | 'info' | 'warn' | 'danger' | 'unknown'

const count = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : null)

const countText = (errors: number | null, warnings: number | null) => {
  const parts: string[] = []
  if (errors) parts.push(`${errors} error${errors === 1 ? '' : 's'}`)
  if (warnings) parts.push(`${warnings} warning${warnings === 1 ? '' : 's'}`)
  return parts.join(' · ')
}

const statusText = (status: unknown) =>
  status === 'healthy' ? 'Healthy' : status === 'info' ? 'No issues' : status === 'warning' ? 'Warning' : status === 'error' ? 'Error' : C.badgeUnknown

// The top bar badge (§3, §11): what needs a person, from the unattended counts. Findings everyone has acknowledged or
// silenced leave the badge quiet but never green; a status the server could not determine stays unknown. A server
// that sends no unattended counts is read by its true counts.
export const badgeFor = (raw: Record<string, unknown> | undefined, stale: boolean): { tone: BadgeTone; label: string; title: string; alert: boolean } => {
  if (stale || !raw) return { tone: 'unknown', label: C.badgeUnknown, title: C.badgeStale, alert: false }
  const status = raw.overall_status
  const errors = count(raw.error_count)
  const warnings = count(raw.warning_count)
  const openErrors = count(raw.unattended_error_count) ?? errors
  const openWarnings = count(raw.unattended_warning_count) ?? warnings
  if (openErrors || openWarnings) {
    const label = countText(openErrors, openWarnings)
    return { tone: openErrors ? 'danger' : 'warn', label, title: C.badgeTitle(label), alert: Boolean(openErrors) }
  }
  if (errors || warnings) return { tone: 'info', label: C.badgeAllSeen, title: C.badgeAllSeenTitle(countText(errors, warnings)), alert: false }
  const tone: BadgeTone = status === 'healthy' ? 'ok' : status === 'info' ? 'info' : status === 'warning' ? 'warn' : status === 'error' ? 'danger' : 'unknown'
  const label = statusText(status)
  return { tone, label, title: C.badgeTitle(label), alert: status === 'error' }
}
