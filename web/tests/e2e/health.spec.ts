import { expect, test, type Page } from '@playwright/test'
import { authenticateAndSaveState, authStatePath, explicitSkipRequested } from './helpers/auth'
import { NOW, OFFLINE, count, scriptWs, type Answer, type Frame } from './helpers/scriptedWs'

// Health findings on the Overview (design/health/findings.md §11): each finding's state, Acknowledge / Silence / Turn
// back on for accounts that may manage them, the Silenced list, the top bar badge from the unattended counts, and the
// health.changed subscription. health.*, meta.hello and the severity rollup are scripted on the console socket
// (helpers/scriptedWs.ts); screenshots land in test-results/.
//
//     VAULTHALLA_E2E_OFFLINE=1 pnpm exec playwright test tests/e2e/health.spec.ts                  # no daemon

test.skip(explicitSkipRequested(), 'VAULTHALLA_E2E_SKIP set')
test.use({ ignoreHTTPSErrors: true, ...(OFFLINE ? {} : { storageState: authStatePath }) })
test.beforeAll(async ({ browser }) => {
  if (!OFFLINE) await authenticateAndSaveState(browser)
})

const VIEW = ['admin.stats.view']
const MANAGE = ['admin.stats.view', 'admin.stats.manage']

const remedy = (href: string, label: string) => ({ id: 'open', label, kind: 'open', href, command: null, payload: null, effect: null })
const mark = (cls: string, over: Record<string, unknown> = {}) => ({
  class: cls,
  subject: '',
  state: 'acknowledged',
  severity: 'error',
  set_by: 1,
  set_by_name: 'cooper',
  set_at: NOW - 600,
  expires_at: null,
  note: null,
  ...over,
})
const finding = (cls: string, over: Record<string, unknown> = {}) => ({
  class: cls,
  subject: '',
  card_id: 'fuse',
  severity: 'error',
  title: 'FUSE errors',
  class_title: 'FUSE error rate high',
  message: 'FUSE error rate is 4.2% over the last 5 minutes.',
  href: '/health/filesystem',
  metric_key: null,
  notifies: true,
  state: 'active',
  mark: null,
  remedies: [remedy('/health/filesystem', 'Open the filesystem')],
  ...over,
})

type State = { findings: Record<string, unknown>[]; silences: Record<string, unknown>[] }

const initial = (): State => ({
  findings: [
    finding('system.fuse.error_rate_high'),
    finding('system.db.pool_saturated', {
      card_id: 'db',
      title: 'Database pool',
      class_title: 'Database pool saturated',
      message: 'All 16 database connections are in use.',
      href: '/health/runtime#connections',
      state: 'acknowledged',
      mark: mark('system.db.pool_saturated', { note: 'Looking at it after the backup finishes.' }),
      remedies: [remedy('/health/runtime#connections', 'Open connections')],
    }),
    finding('system.pricing.warnings', {
      card_id: 'pricing',
      severity: 'warning',
      title: 'Cost warnings',
      class_title: 'Cost warnings',
      message: '2 budget warnings are open.',
      href: '/cost',
      state: 'silenced',
      mark: mark('system.pricing.warnings', { state: 'silenced', severity: 'warning', set_by_name: 'ana', expires_at: NOW + 86_400 }),
      remedies: [remedy('/cost#budget-alerts', 'Open cost alerts')],
    }),
  ],
  silences: [mark('system.retention.overdue', { state: 'silenced', severity: 'warning', set_at: NOW - 3 * 86_400, note: 'Retention runs weekly here.' })],
})

const catalog = [
  { class: 'system.retention.overdue', card_id: 'retention', title: 'Retention overdue', max_severity: 'warning', notifies: true, remedies: [] },
]

const answers = (state: State, canManage: boolean) => {
  const unattended = (sev: string) => state.findings.filter(f => f.state === 'active' && f.severity === sev).length
  const health = (withCatalog: boolean) => ({
    overall_status: 'error',
    error_count: state.findings.filter(f => f.severity === 'error').length,
    warning_count: state.findings.filter(f => f.severity === 'warning').length,
    unattended_error_count: unattended('error'),
    unattended_warning_count: unattended('warning'),
    checked_at: NOW,
    findings: state.findings,
    silences: state.silences,
    can_manage: canManage,
    ...(withCatalog ? { catalog } : {}),
  })
  const set = (cls: string, change: (f: Record<string, unknown>) => Record<string, unknown>) => {
    state.findings = state.findings.map(f => (f.class === cls ? change(f) : f))
  }
  return (frame: Frame): Answer | undefined => {
    const p = frame.payload ?? {}
    switch (frame.command) {
      case 'meta.hello':
        return {
          data: {
            server: { name: 'vaulthalla', version: '1.28.0' },
            protocol: { version: 3, min: 1, max: 3 },
            capabilities: ['health.findings', 'health.push'],
            commands: [],
            contract: { contract_version: 3, contract_hash: 'x', ws_hash: 'x', models_hash: 'x' },
          },
        }
      case 'health.subscribe':
        return { data: { revision: 1 } }
      case 'health.unsubscribe':
        return { data: { subscribed: false } }
      case 'health.findings.list':
        return { data: { health: health(true) } }
      case 'stats.dashboard.severity': {
        const { findings: _f, silences: _s, can_manage: _c, ...stats } = health(false)
        return { data: { stats } }
      }
      case 'stats.dashboard.overview':
        return { data: { stats: { overall_status: 'error', error_count: 2, warning_count: 1, checked_at: NOW, attention: [], sections: [], cards: [] } } }
      case 'health.finding.acknowledge':
        set(String(p.class), f => ({ ...f, state: 'acknowledged', mark: mark(String(p.class), { set_at: NOW }) }))
        return { data: { health: health(false) } }
      case 'health.finding.silence':
        set(String(p.class), f => ({
          ...f,
          state: 'silenced',
          mark: mark(String(p.class), { state: 'silenced', set_at: NOW, expires_at: p.for_seconds ? NOW + Number(p.for_seconds) : null, note: p.note ?? null }),
        }))
        return { data: { health: health(false) } }
      case 'health.finding.unsilence': {
        const before = state.silences.length
        state.silences = state.silences.filter(m => m.class !== p.class)
        if (state.silences.length === before) set(String(p.class), f => ({ ...f, state: 'active', mark: null }))
        return { data: { health: health(false) } }
      }
      default:
        return undefined
    }
  }
}

const OWNED = new Set(['meta.hello', 'health.subscribe', 'health.unsubscribe', 'health.findings.list', 'stats.dashboard.severity', 'stats.dashboard.overview', 'health.finding.acknowledge', 'health.finding.silence', 'health.finding.unsilence'])

const open = async (page: Page, role: string[], state = initial()) => {
  const sent = await scriptWs(page, c => OWNED.has(c), answers(state, role.includes('admin.stats.manage')), { superAdmin: role })
  await page.goto('/health')
  await expect(page.locator('#health-attention')).toBeVisible()
  return sent
}

const shoot = async (page: Page, name: string) => {
  for (const [label, width] of [
    ['1280', 1280],
    ['390', 390],
  ] as const) {
    await page.setViewportSize({ width, height: 900 })
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
    await page.screenshot({ path: test.info().outputPath(`${name}-${label}.png`), fullPage: true })
  }
  await page.setViewportSize({ width: 1280, height: 900 })
}

const row = (page: Page, cls: string) => page.locator(`[data-testid="health-finding"][data-class="${cls}"]`)
const silence = (page: Page, cls: string) => page.locator(`[data-testid="health-silence"][data-class="${cls}"]`)

test('states, controls and the Silenced list for an account that may manage findings', async ({ page }) => {
  const sent = await open(page, MANAGE)

  await expect(row(page, 'system.fuse.error_rate_high').getByTestId('health-finding-state')).toHaveText('Not acknowledged')
  await expect(row(page, 'system.db.pool_saturated').getByTestId('health-finding-state')).toHaveText(/^Acknowledged by cooper/)
  await expect(row(page, 'system.db.pool_saturated')).toContainText('Note: Looking at it after the backup finishes.')
  await expect(silence(page, 'system.pricing.warnings')).toContainText(/Silenced by ana until /)
  await expect(silence(page, 'system.pricing.warnings')).toContainText('Active now')
  await expect(silence(page, 'system.retention.overdue')).toContainText('Retention overdue')
  await expect(silence(page, 'system.retention.overdue')).toContainText('Not active now')
  await expect(silence(page, 'system.retention.overdue')).toContainText('Silenced by cooper until turned back on')
  // A silenced finding is not under Needs attention, and the true counts stay on the health page.
  await expect(row(page, 'system.pricing.warnings')).toHaveCount(0)
  await expect(page.locator('#health-attention')).toContainText('2 errors · 1 warning')

  const fuse = row(page, 'system.fuse.error_rate_high')
  await expect(fuse.getByRole('button', { name: 'Acknowledge' })).toBeVisible()
  await expect(fuse.getByRole('link', { name: 'Open the filesystem' })).toHaveAttribute('href', '/health/filesystem')
  await expect(row(page, 'system.db.pool_saturated').getByRole('button', { name: 'Acknowledge' })).toHaveCount(0)
  await shoot(page, 'health-findings')

  // The top bar badge counts only the unattended error.
  await expect(page.getByRole('link', { name: 'System health: 1 error' })).toBeVisible()
  await fuse.getByRole('button', { name: 'Acknowledge' }).click()
  await expect(fuse.getByTestId('health-finding-state')).toHaveText(/^Acknowledged by cooper/)
  expect(sent.find(f => f.command === 'health.finding.acknowledge')?.payload).toEqual({ class: 'system.fuse.error_rate_high' })
  await expect(page.getByRole('link', { name: /all acknowledged or silenced/ })).toBeVisible()

  await row(page, 'system.db.pool_saturated').getByRole('button', { name: 'Silence…' }).click()
  const dialog = page.getByTestId('health-silence-dialog')
  await expect(dialog.getByLabel('For how long')).toHaveValue('day')
  await dialog.getByLabel('For how long').selectOption({ label: '7 days' })
  await dialog.getByLabel('Note (optional)').fill('x'.repeat(501))
  await expect(dialog.getByRole('button', { name: 'Silence' })).toBeDisabled()
  await expect(dialog).toContainText('At most 500 characters (501 now).')
  await dialog.getByLabel('Note (optional)').fill('  Known: pool resized on Monday.  ')
  await dialog.getByRole('button', { name: 'Silence' }).click()
  await expect(dialog).toHaveCount(0)
  expect(sent.find(f => f.command === 'health.finding.silence')?.payload).toEqual({
    class: 'system.db.pool_saturated',
    for_seconds: 604_800,
    note: 'Known: pool resized on Monday.',
  })
  await expect(silence(page, 'system.db.pool_saturated')).toContainText('Note: Known: pool resized on Monday.')

  await silence(page, 'system.retention.overdue').getByRole('button', { name: 'Turn back on' }).click()
  await expect(silence(page, 'system.retention.overdue')).toHaveCount(0)
  expect(sent.find(f => f.command === 'health.finding.unsilence')?.payload).toEqual({ class: 'system.retention.overdue' })

  // Subscribed to health.changed, so nothing polls the findings or the severity.
  expect(count(sent, 'health.subscribe')).toBeGreaterThan(0)
})

test('an account that may only view sees the states and no controls', async ({ page }) => {
  const sent = await open(page, VIEW)
  await expect(row(page, 'system.db.pool_saturated').getByTestId('health-finding-state')).toHaveText(/^Acknowledged by cooper/)
  await expect(page.locator('#health-attention').getByRole('button')).toHaveCount(0)
  await expect(page.locator('#health-silenced').getByRole('button')).toHaveCount(0)
  await expect(page.locator('#health-attention').getByRole('link', { name: 'Open the filesystem' })).toHaveCount(0)
  // The finding itself still links to where it can be looked at.
  await expect(row(page, 'system.fuse.error_rate_high').getByRole('link').first()).toHaveAttribute('href', '/health/filesystem')
  expect(count(sent, 'health.finding.acknowledge') + count(sent, 'health.finding.silence')).toBe(0)
  await shoot(page, 'health-findings-view-only')
})
