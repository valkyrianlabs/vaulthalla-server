import { expect, test, type Page } from '@playwright/test'
import { authStatePath, authenticateAndSaveState, explicitSkipRequested } from './helpers/auth'

// Idle sign-out (#319). The console reports real user input with auth.activity (at most once a minute, no client
// timestamp) and never for background traffic; a session the server has ended reaches the sign-in page without a
// silent re-authentication.
//
// - offline (no daemon; every ws answer scripted):
//     VAULTHALLA_E2E_OFFLINE=1 pnpm exec playwright test tests/e2e/idle-logoff.spec.ts
// - against a real install configured with a short timeout (idle_timeout_minutes: 1, sweep_interval_seconds: 15),
//   for the server-side test at the bottom:
//     VAULTHALLA_E2E_IDLE_MINUTES=1 VAULTHALLA_E2E_BASE_URL=https://localhost VAULTHALLA_E2E_NO_WEB_SERVER=1 \
//       pnpm exec playwright test tests/e2e/idle-logoff.spec.ts

const OFFLINE = process.env.VAULTHALLA_E2E_OFFLINE === '1' || process.env.VAULTHALLA_E2E_OFFLINE === 'true'
const LIVE_IDLE_MINUTES = Number(process.env.VAULTHALLA_E2E_IDLE_MINUTES ?? 0)

test.skip(explicitSkipRequested(), 'VAULTHALLA_E2E_SKIP set')

type Frame = { command: string; payload: unknown; requestId: string }

const user = {
  id: 7,
  name: 'e2e-user',
  email: 'e2e@example.invalid',
  permissions: {},
  created_at: new Date().toISOString(),
  last_login: new Date().toISOString(),
  is_active: true,
  admin_role: { id: 2, name: 'user', permissions: [] },
  vault_roles: [],
}

const ok = (frame: Frame, data: unknown, extra: Record<string, unknown> = {}) =>
  JSON.stringify({ command: frame.command, requestId: frame.requestId, status: 'OK', data, ...extra })
const refused = (frame: Frame, error: string, status = 'ERROR') =>
  JSON.stringify({ command: frame.command, requestId: frame.requestId, status, error, data: { code: 'denied' } })

// A scripted daemon: auth.refresh signs in until `end()`; then the socket is closed, as the idle sweep does, and every
// refresh is refused. Records every frame the console sends.
const scriptedDaemon = async (page: Page) => {
  const sent: Frame[] = []
  let ended = false
  const sockets: { close: () => Promise<void> }[] = []
  const base = new URL(test.info().project.use.baseURL ?? 'http://127.0.0.1:3000')
  await page.context().addCookies([{ name: 'refresh', value: 'e2e-offline', url: base.origin }])
  await page.routeWebSocket(
    url => url.pathname === '/ws',
    ws => {
      sockets.push({ close: () => ws.close({ code: 1000, reason: 'idle' }) })
      ws.onMessage(message => {
        if (typeof message !== 'string') return
        const frame = JSON.parse(message) as Frame
        sent.push(frame)
        if (frame.command === 'auth.refresh')
          ws.send(ended ? refused(frame, 'Session ended after inactivity') : ok(frame, { user }, { token: 'e2e-token' }))
        else if (frame.command === 'auth.activity') ws.send(ended ? refused(frame, 'Unauthorized', 'UNAUTHORIZED') : ok(frame, null))
        else ws.send(refused(frame, 'Unknown command (offline e2e)'))
      })
    },
  )
  return {
    sent,
    count: (command: string) => sent.filter(f => f.command === command).length,
    end: async () => {
      ended = true
      for (const s of sockets) await s.close().catch(() => {})
    },
  }
}

test.describe('idle sign-out (console)', () => {
  test.skip(!OFFLINE, 'scripted ws: run with VAULTHALLA_E2E_OFFLINE=1')

  test('reports real input at most once a minute, and never for background traffic', async ({ page }) => {
    await page.clock.install()
    const daemon = await scriptedDaemon(page)
    await page.goto('/')
    await expect.poll(() => daemon.count('auth.refresh')).toBeGreaterThan(0)

    // Background only: refreshes and polling happen, but no input, so no activity report.
    await page.clock.fastForward('00:30')
    await page.waitForTimeout(500)
    expect(daemon.count('auth.activity')).toBe(0)

    // Input reports once; more input in the same minute doesn't.
    await page.mouse.move(200, 200)
    await page.keyboard.press('Shift')
    await page.mouse.wheel(0, 120)
    await expect.poll(() => daemon.count('auth.activity')).toBe(1)
    await page.mouse.move(300, 300)
    await page.waitForTimeout(300)
    expect(daemon.count('auth.activity')).toBe(1)
    const report = daemon.sent.find(f => f.command === 'auth.activity')
    expect(report?.payload ?? null).toBeNull() // the server stamps its own time; the console sends none

    // After the interval, the next input reports again.
    await page.clock.fastForward('01:01')
    await page.keyboard.press('Shift')
    await expect.poll(() => daemon.count('auth.activity')).toBe(2)
  })

  test('a session the server ended goes to sign-in, with no silent re-authentication', async ({ page }) => {
    const daemon = await scriptedDaemon(page)
    await page.goto('/')
    await expect.poll(() => daemon.count('auth.refresh')).toBeGreaterThan(0)
    await expect(page).not.toHaveURL(/\/login/)

    await daemon.end() // the idle sweep: refresh token revoked, socket closed
    await expect(page).toHaveURL(/\/login/, { timeout: 15_000 })
  })
})

test.describe.serial('idle sign-out (live daemon)', () => {
  test.skip(OFFLINE || LIVE_IDLE_MINUTES <= 0, "set VAULTHALLA_E2E_IDLE_MINUTES to the install's idle_timeout_minutes")
  const window = (LIVE_IDLE_MINUTES * 60 + 120) * 1000 // the timeout, a sweep and the console's own re-check

  const freshConsole = async (browser: import('@playwright/test').Browser) => {
    await authenticateAndSaveState(browser)
    const context = await browser.newContext({ ignoreHTTPSErrors: true, storageState: authStatePath })
    const page = await context.newPage()
    await page.goto('/')
    await expect(page).not.toHaveURL(/\/login/)
    return page
  }

  test('a console in use stays signed in past the timeout', async ({ browser }) => {
    test.setTimeout(window + 60_000)
    const page = await freshConsole(browser)
    const deadline = Date.now() + window
    while (Date.now() < deadline) {
      await page.mouse.move(100 + Math.random() * 200, 100 + Math.random() * 200)
      await page.waitForTimeout(20_000)
      await expect(page).not.toHaveURL(/\/login/)
    }
  })

  test('an idle console is signed out and stays signed out after a reload', async ({ browser }) => {
    test.setTimeout(window + 60_000)
    const page = await freshConsole(browser)
    await expect(page).toHaveURL(/\/login/, { timeout: window })
    await page.goto('/')
    await expect(page).toHaveURL(/\/login/)
  })
})
