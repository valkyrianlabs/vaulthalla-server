import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  NOTE_MAX,
  SILENCE_CHOICES,
  badgeFor,
  controlsFor,
  mergeAnswer,
  noteOf,
  openRemedies,
  severityOf,
  silencePayload,
  splitFindings,
  stateText,
  type Finding,
  type HealthFindings,
  type Mark,
  type Remedy,
} from './model.ts'

const NOW = 1_800_000_000

const mark = (over: Partial<Mark> = {}): Mark => ({
  class: 'system.fuse.error_rate_high',
  subject: '',
  state: 'acknowledged',
  severity: 'error',
  set_by: 1,
  set_by_name: 'cooper',
  set_at: NOW - 300,
  expires_at: null,
  note: null,
  ...over,
})

const open = (href: string, label = 'Open the filesystem'): Remedy => ({ id: 'open', label, kind: 'open', href, command: null, payload: null, effect: null })

const finding = (over: Partial<Finding> = {}): Finding => ({
  class: 'system.fuse.error_rate_high',
  subject: '',
  card_id: 'fuse',
  severity: 'error',
  title: 'FUSE errors',
  class_title: 'FUSE error rate high',
  message: 'FUSE error rate is 4.2%',
  href: '/health/filesystem',
  metric_key: null,
  notifies: true,
  state: 'active',
  mark: null,
  remedies: [open('/health/filesystem')],
  ...over,
})

const health = (over: Partial<HealthFindings> = {}): HealthFindings => ({
  overall_status: 'error',
  error_count: 1,
  warning_count: 1,
  unattended_error_count: 1,
  unattended_warning_count: 0,
  checked_at: NOW,
  findings: [],
  silences: [],
  can_manage: true,
  ...over,
})

test('each state reads with who and when', () => {
  assert.equal(stateText(finding()), 'Not acknowledged')
  assert.match(stateText(finding({ state: 'acknowledged', mark: mark() }), NOW * 1000), /^Acknowledged by cooper 5 minutes ago$/)
  assert.match(
    stateText(finding({ state: 'silenced', mark: mark({ state: 'silenced', expires_at: NOW + 3600 }) })),
    /^Silenced by cooper until .+/,
  )
  assert.equal(stateText(finding({ state: 'silenced', mark: mark({ state: 'silenced' }) })), 'Silenced by cooper until turned back on')
  // A mark without a name still says someone did it.
  assert.equal(stateText(finding({ state: 'silenced', mark: mark({ state: 'silenced', set_by_name: '' }) })), 'Silenced by someone until turned back on')
})

test('controls follow the state and need can_manage', () => {
  const pick = (f: Finding, manage = true) => {
    const c = controlsFor(f, manage)
    return { acknowledge: c.acknowledge, silence: c.silence, turnBackOn: c.turnBackOn, remedies: c.remedies.length }
  }
  assert.deepEqual(pick(finding()), { acknowledge: true, silence: true, turnBackOn: false, remedies: 1 })
  assert.deepEqual(pick(finding({ state: 'acknowledged', mark: mark() })), { acknowledge: false, silence: true, turnBackOn: true, remedies: 1 })
  assert.deepEqual(pick(finding({ state: 'silenced', mark: mark({ state: 'silenced' }) })), { acknowledge: false, silence: false, turnBackOn: true, remedies: 1 })
  for (const state of ['active', 'acknowledged', 'silenced'] as const)
    assert.deepEqual(pick(finding({ state }), false), { acknowledge: false, silence: false, turnBackOn: false, remedies: 0 })
})

test('only open remedies with a console path become links', () => {
  const remedies: Remedy[] = [
    open('/cost#budget-alerts', 'Open cost alerts'),
    open('//evil.example/x'),
    open('https://evil.example/'),
    { ...open('/x'), href: null },
    { id: 'sync', label: 'Sync', kind: 'command', href: null, command: 'storage.vault.sync', payload: {}, effect: 'write' },
  ]
  assert.deepEqual(openRemedies(remedies).map(r => r.href), ['/cost#budget-alerts'])
})

test('silence lengths are an hour, a day, a week or until turned back on', () => {
  assert.deepEqual(
    SILENCE_CHOICES.map(c => [c.label, c.seconds]),
    [
      ['1 hour', 3600],
      ['24 hours', 86_400],
      ['7 days', 604_800],
      ['Until turned back on', null],
    ],
  )
  const f = finding()
  assert.deepEqual(silencePayload(f, 'hour', ''), { class: f.class, for_seconds: 3600 })
  assert.deepEqual(silencePayload(f, 'forever', '  noisy during the migration  '), { class: f.class, note: 'noisy during the migration' })
  assert.deepEqual(silencePayload({ class: 'c', subject: 'vault:2' }, 'week', ' '), { class: 'c', subject: 'vault:2', for_seconds: 604_800 })
})

test('a note is at most 500 bytes once trimmed, as the server counts it', () => {
  assert.equal(NOTE_MAX, 500)
  assert.equal(noteOf(` ${'a'.repeat(500)} `).tooLong, false)
  assert.equal(noteOf('a'.repeat(501)).tooLong, true)
  // Two bytes each in UTF-8.
  assert.equal(noteOf('é'.repeat(251)).tooLong, true)
  assert.deepEqual(noteOf('   '), { text: null, length: 0, tooLong: false })
})

test('needs attention keeps everything not silenced, worst and newest first; silenced lists both kinds', () => {
  const warning = finding({ class: 'w', severity: 'warning', title: 'W' })
  const seenError = finding({ class: 'e1', state: 'acknowledged', mark: mark({ class: 'e1' }) })
  const error = finding({ class: 'e2' })
  const quiet = finding({ class: 's', state: 'silenced', mark: mark({ class: 's', state: 'silenced' }), class_title: 'Quiet class' })
  const { attention, silenced } = splitFindings(
    health({
      findings: [warning, seenError, quiet, error],
      silences: [mark({ class: 'system.retention.overdue', state: 'silenced', severity: 'warning' }), mark({ class: 'unknown.class', state: 'silenced' })],
      catalog: [{ class: 'system.retention.overdue', card_id: 'retention', title: 'Retention overdue', max_severity: 'warning', notifies: true, remedies: [] }],
    }),
  )
  assert.deepEqual(attention.map(f => f.class), ['e2', 'e1', 'w'])
  assert.deepEqual(
    silenced.map(r => [r.class, r.title, r.activeNow, r.severity]),
    [
      ['s', 'Quiet class', true, 'error'],
      ['system.retention.overdue', 'Retention overdue', false, 'warning'],
      // A class the catalog doesn't name is shown by its code, never dropped.
      ['unknown.class', 'unknown.class', false, 'error'],
    ],
  )
})

test('a change answer keeps the cached catalog and implies the severity rollup', () => {
  const catalog = [{ class: 'c', card_id: 'x', title: 'C', max_severity: 'error' as const, notifies: true, remedies: [] }]
  const next = health({ unattended_error_count: 0 })
  assert.deepEqual(mergeAnswer(health({ catalog }), next).catalog, catalog)
  assert.equal(mergeAnswer(undefined, next), next)
  assert.deepEqual(severityOf(next), {
    overall_status: 'error',
    error_count: 1,
    warning_count: 1,
    unattended_error_count: 0,
    unattended_warning_count: 0,
    checked_at: NOW,
  })
})

test('the top bar badge counts what is unattended and never reads unknown or attended as healthy', () => {
  const sev = (over: Record<string, unknown>) => ({ ...severityOf(health()), ...over })
  assert.deepEqual(badgeFor(sev({}), false), { tone: 'danger', label: '1 error', title: 'System health: 1 error', alert: true })
  assert.equal(badgeFor(sev({ unattended_error_count: 0, unattended_warning_count: 1 }), false).tone, 'warn')
  const quiet = badgeFor(sev({ unattended_error_count: 0, unattended_warning_count: 0 }), false)
  assert.equal(quiet.tone, 'info')
  assert.equal(quiet.label, 'Nothing new')
  assert.match(quiet.title, /1 error · 1 warning, all acknowledged or silenced/)
  assert.equal(quiet.alert, false)
  // A server without unattended counts is read by its true counts.
  assert.equal(badgeFor({ overall_status: 'error', error_count: 2, warning_count: 0 }, false).label, '2 errors')
  assert.equal(badgeFor({ overall_status: 'healthy', error_count: 0, warning_count: 0 }, false).tone, 'ok')
  assert.equal(badgeFor({ overall_status: 'unavailable', error_count: 0, warning_count: 0 }, false).tone, 'unknown')
  assert.equal(badgeFor({ overall_status: 'healthy' }, true).tone, 'unknown')
  assert.equal(badgeFor(undefined, false).label, 'Health unknown')
})
