import { expect, test, type Page, type CDPSession } from '@playwright/test'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { armStepUp, authenticateAndSaveState, authStatePath, explicitSkipRequested } from './helpers/auth'

// Console dogfood suite: drives the real console against a running daemon (local dev install or a lab host through
// nginx). Uses the provisioned E2E super admin (globalSetup). Creates its own folders/files/links and removes them.
//   VAULTHALLA_E2E_BASE_URL=https://localhost VAULTHALLA_E2E_NO_WEB_SERVER=1 pnpm exec playwright test tests/e2e/console.spec.ts
// Uploads go through the console's HTTP routes, so the base URL must be the reverse proxy (nginx/Caddy), not `next dev`.

test.skip(explicitSkipRequested(), 'VAULTHALLA_E2E_SKIP set')
test.use({ storageState: authStatePath, ignoreHTTPSErrors: true })
// Step-up dialogs (#359) are answered with the e2e account's password and TOTP code.
test.beforeEach(({ page }) => armStepUp(page))

test.beforeAll(async ({ browser }) => {
  await authenticateAndSaveState(browser)
})

const RUN = `e2e-${Date.now().toString(36)}`

const ROUTES = ['/files', '/shares', '/vaults', '/users', '/groups', '/roles', '/credentials', '/cost', '/s3-gateway', '/health', '/health/runtime', '/health/filesystem', '/health/storage', '/health/activity', '/notifications', '/settings', '/account']

// Collects page errors, console errors and failed requests (ignoring aborted prefetches).
const watch = (page: Page) => {
  const problems: string[] = []
  page.on('pageerror', error => problems.push(`pageerror: ${error.message}`))
  page.on('console', message => {
    if (message.type() === 'error') problems.push(`console.error: ${message.text().slice(0, 240)}`)
  })
  page.on('response', response => {
    if (response.status() >= 500) problems.push(`HTTP ${response.status()} ${response.url()}`)
  })
  return problems
}

const wsTraffic = (page: Page) => {
  const stats = { sentCommands: [] as string[], receivedBytes: 0 }
  page.on('websocket', ws => {
    // Only the console socket: not the dev server's HMR socket.
    if (!/\/ws$/.test(new URL(ws.url()).pathname)) return
    ws.on('framesent', frame => {
      if (typeof frame.payload !== 'string') return
      try {
        stats.sentCommands.push(JSON.parse(frame.payload).command)
      } catch {
        // binary or non-JSON frames are not commands
      }
    })
    ws.on('framereceived', frame => {
      stats.receivedBytes += typeof frame.payload === 'string' ? frame.payload.length : frame.payload.byteLength
    })
  })
  return stats
}

const gotoFiles = async (page: Page) => {
  await page.goto('/files')
  await page.waitForURL(/\/files\/\d+/)
  await expect(page.getByRole('listbox', { name: /contents of/i })).toBeVisible()
}

test.describe.serial('console', () => {
  test('every console route renders without errors, endless spinners or denied states for a super admin', async ({ page }) => {
    // Each route's own waits are bounded below; this only caps the whole sweep.
    test.setTimeout(ROUTES.length * 10_000)
    const problems = watch(page)
    for (const route of ROUTES) {
      const response = await page.goto(route)
      expect(response?.status(), route).toBeLessThan(400)
      await expect(page.getByRole('heading', { level: 1 }).first(), route).toBeVisible({ timeout: 15_000 })
      await expect(page.getByText(/you don.t have access to this/i), route).toHaveCount(0)
      await expect(page.getByRole('status', { name: /loading/i }), `${route} still loading`).toHaveCount(0, { timeout: 15_000 })
    }
    expect(problems).toEqual([])
  })

  test('old console URLs redirect to their new homes', async ({ page }) => {
    for (const [from, to] of [
      ['/fs', /\/files/],
      ['/dashboard', /\/health$/],
      ['/dashboard/trends', /\/health\/activity$/],
      ['/api-keys', /\/credentials$/],
      ['/pricing-budget', /\/cost$/],
      ['/operator-email', /\/notifications$/],
      ['/vaults/add', /\/vaults\/new$/],
    ] as const) {
      await page.goto(from)
      await expect(page, from).toHaveURL(to)
    }
  })

  test('middleware only checks for a refresh cookie; the session gate turns a bogus one away', async ({ playwright, browser, baseURL }) => {
    // #171: the middleware used to verify the cookie upstream on every page load (a password-hash verify in the
    // daemon). Now it only checks presence, and the websocket session gate (auth.refresh) decides validity.
    if (!baseURL) throw new Error('baseURL is not configured')
    // The runner applies this spec's storageState to request contexts too: start from an empty jar.
    const api = await playwright.request.newContext({ baseURL, ignoreHTTPSErrors: true, storageState: { cookies: [], origins: [] } })
    const pageLoad = { 'sec-fetch-dest': 'document' }
    const anonymous = await api.get('/users', { maxRedirects: 0, headers: pageLoad })
    expect(anonymous.status()).toBe(307)
    expect(anonymous.headers().location).toMatch(/\/login\?next=%2Fusers$/)
    const bogus = await api.get('/users', { maxRedirects: 0, headers: { ...pageLoad, cookie: 'refresh=not-a-session' } })
    expect(bogus.status()).toBe(200)
    await api.dispose()

    const stranger = await browser.newContext({ baseURL, ignoreHTTPSErrors: true, storageState: undefined })
    await stranger.addCookies([{ name: 'refresh', value: 'not-a-session', url: baseURL }])
    const page = await stranger.newPage()
    await page.goto('/files')
    await page.waitForURL(/\/login\?next=%2Ffiles/, { timeout: 15_000 })
    await stranger.close()
  })

  test('the websocket bootstrap stays small and pollers stop when you leave a page', async ({ page }) => {
    const traffic = wsTraffic(page)
    await gotoFiles(page)
    await page.waitForTimeout(2000)
    // Session refresh + vault list + one directory listing: a few KB, never the 85 KB dashboard overview.
    // Measure against a production build: React StrictMode doubles every request under `next dev`.
    expect(traffic.sentCommands).not.toContain('stats.dashboard.overview')
    expect(traffic.receivedBytes, 'ws bytes received while opening /files').toBeLessThan(20 * 1024)

    await page.goto('/health')
    await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible()
    await page.waitForTimeout(3000)
    await gotoFiles(page)
    traffic.sentCommands.length = 0
    await page.waitForTimeout(25_000)
    const statsCommands = traffic.sentCommands.filter(c => c.startsWith('stats.') && c !== 'stats.dashboard.severity')
    expect(statsCommands, 'stats polling after leaving /health').toEqual([])
  })

  test('files: create, upload, rename, move, copy, download and delete', async ({ page }) => {
    const problems = watch(page)
    await gotoFiles(page)
    const folder = `${RUN} folder`
    const dir = mkdtempSync(join(tmpdir(), 'vh-e2e-'))
    const names = [`${RUN}-a.txt`, `${RUN} b (ü #1 %20).txt`, `.${RUN}-dotfile`]
    for (const name of names) writeFileSync(join(dir, name), `hello ${name}\n`)

    await page.getByRole('button', { name: 'New folder' }).click()
    await page.getByRole('textbox', { name: 'Name', exact: true }).fill(folder)
    await page.getByRole('button', { name: 'Create' }).click()
    await expect(page.getByRole('option', { name: new RegExp(folder) })).toBeVisible()

    await page.locator('input[type=file][multiple]').setInputFiles(names.map(n => join(dir, n)))
    for (const name of names) await expect(page.getByRole('option', { name: new RegExp(name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) })).toBeVisible({ timeout: 30_000 })

    // Rename with F2.
    await page.getByRole('option', { name: new RegExp(`${RUN}-a\\.txt`) }).click()
    await page.keyboard.press('F2')
    await page.getByRole('textbox', { name: 'Name', exact: true }).fill(`${RUN}-renamed.txt`)
    await page.getByRole('button', { name: 'Rename' }).click()
    await expect(page.getByRole('option', { name: new RegExp(`${RUN}-renamed`) })).toBeVisible()

    // Download (preflighted; the app must stay put).
    const downloadPromise = page.waitForEvent('download')
    await page.getByRole('option', { name: new RegExp(`${RUN}-renamed`) }).click({ button: 'right' })
    await page.getByRole('menuitem', { name: 'Download' }).click()
    const download = await downloadPromise
    expect(download.suggestedFilename()).toBe(`${RUN}-renamed.txt`)
    await expect(page).toHaveURL(/\/files\//)

    // Copy into the folder, then move the original into it too.
    await page.getByRole('option', { name: new RegExp(`${RUN}-renamed`) }).click({ button: 'right' })
    await page.getByRole('menuitem', { name: 'Copy to…' }).click()
    await page.getByRole('dialog').getByRole('button', { name: folder }).click()
    await page.getByRole('button', { name: 'Copy here' }).click()
    await expect(page.getByRole('dialog')).toHaveCount(0)

    await page.getByRole('option', { name: new RegExp(`${RUN} b`) }).click({ button: 'right' })
    await page.getByRole('menuitem', { name: 'Move to…' }).click()
    await page.getByRole('dialog').getByRole('button', { name: folder }).click()
    await page.getByRole('button', { name: 'Move here' }).click()
    await expect(page.getByRole('option', { name: new RegExp(`${RUN} b`) })).toHaveCount(0)

    // Inside the folder: both arrived, and the URL carries the path (refresh/back work).
    await page.getByRole('option', { name: new RegExp(folder) }).dblclick()
    await expect(page).toHaveURL(new RegExp(encodeURIComponent(folder).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
    await expect(page.getByRole('option', { name: new RegExp(`${RUN}-renamed`) })).toBeVisible()
    await expect(page.getByRole('option', { name: new RegExp(`${RUN} b`) })).toBeVisible()
    await page.reload()
    await expect(page.getByRole('option', { name: new RegExp(`${RUN} b`) })).toBeVisible()
    await page.goBack()
    await expect(page.getByRole('option', { name: new RegExp(folder) })).toBeVisible()

    // Clean up: select everything this run created and delete through the confirmation.
    await page.getByRole('listbox').focus()
    for (const option of await page.getByRole('option').filter({ hasText: RUN }).all()) await option.click({ modifiers: ['Control'] })
    await page.keyboard.press('Delete')
    await page.getByRole('button', { name: 'Delete', exact: true }).click()
    await expect(page.getByRole('option').filter({ hasText: RUN })).toHaveCount(0, { timeout: 30_000 })
    expect(problems).toEqual([])
  })

  test('dropping several files and a folder uploads every item', async ({ page }) => {
    await gotoFiles(page)
    const dir = mkdtempSync(join(tmpdir(), 'vh-e2e-drop-'))
    const files = [1, 2, 3, 4, 5].map(i => {
      const file = join(dir, `${RUN}-drop-${i}.txt`)
      writeFileSync(file, `drop ${i}\n`)
      return file
    })
    const cdp: CDPSession = await page.context().newCDPSession(page)
    const box = await page.getByRole('listbox').boundingBox()
    const x = Math.round((box?.x ?? 400) + 200)
    const y = Math.round((box?.y ?? 300) + 60)
    const data = { items: [], files, dragOperationsMask: 1 }
    await cdp.send('Input.dispatchDragEvent', { type: 'dragEnter', x, y, data })
    await cdp.send('Input.dispatchDragEvent', { type: 'dragOver', x, y, data })
    await cdp.send('Input.dispatchDragEvent', { type: 'drop', x, y, data })
    await expect(page.getByRole('option').filter({ hasText: `${RUN}-drop-` })).toHaveCount(5, { timeout: 30_000 })

    await page.getByRole('listbox').focus()
    for (const option of await page.getByRole('option').filter({ hasText: `${RUN}-drop-` }).all()) await option.click({ modifiers: ['Control'] })
    await page.keyboard.press('Delete')
    await page.getByRole('button', { name: 'Delete', exact: true }).click()
    await expect(page.getByRole('option').filter({ hasText: `${RUN}-drop-` })).toHaveCount(0, { timeout: 30_000 })
  })

  test('share links: a recipient browses a folder link and can only upload through a dropbox link', async ({ page, browser }) => {
    await gotoFiles(page)
    const folder = `${RUN} shared`
    await page.getByRole('button', { name: 'New folder' }).click()
    await page.getByRole('textbox', { name: 'Name', exact: true }).fill(folder)
    await page.getByRole('button', { name: 'Create' }).click()
    const row = page.getByRole('option', { name: new RegExp(folder) })
    await expect(row).toBeVisible()

    await row.click({ button: 'right' })
    await page.getByRole('menuitem', { name: 'Share link…' }).click()
    await page.getByRole('button', { name: 'Create link' }).click()
    const browseUrl = ((await page.locator('code').first().textContent()) ?? '').trim()
    expect(browseUrl).toMatch(/\/share#vhs_/)
    await page.getByRole('button', { name: 'Create another' }).click()
    await page.getByRole('radio', { name: /upload dropbox/i }).click()
    await page.getByRole('button', { name: 'Create link' }).click()
    const dropUrl = ((await page.locator('code').first().textContent()) ?? '').trim()
    await page.keyboard.press('Escape')

    const recipient = await browser.newContext({ ignoreHTTPSErrors: true, storageState: undefined })
    const anon = await recipient.newPage()
    await anon.goto(browseUrl)
    await expect(anon.getByRole('listbox')).toBeVisible({ timeout: 15_000 })

    await anon.goto(dropUrl)
    await expect(anon.getByRole('heading', { name: /send files/i })).toBeVisible({ timeout: 15_000 })
    await expect(anon.getByRole('listbox')).toHaveCount(0)
    const dir = mkdtempSync(join(tmpdir(), 'vh-e2e-dropbox-'))
    writeFileSync(join(dir, `${RUN}-from-recipient.txt`), 'hi\n')
    await anon.locator('input[type=file]').setInputFiles(join(dir, `${RUN}-from-recipient.txt`))
    await expect(anon.getByText(/sent/)).toBeVisible({ timeout: 30_000 })
    await recipient.close()

    // The owner sees the recipient's upload; then revoke both links and remove the folder.
    await row.dblclick()
    await expect(page.getByRole('option', { name: new RegExp(`${RUN}-from-recipient`) })).toBeVisible({ timeout: 15_000 })
    await page.goto('/shares')
    for (const label of [folder, folder]) {
      const link = page.getByText(label, { exact: true }).first()
      if (!(await link.count())) break
      await page.getByRole('button', { name: 'Link actions' }).first().click()
      await page.getByRole('menuitem', { name: /revoke/i }).click()
      await page.getByRole('button', { name: 'Revoke', exact: true }).click()
    }
    await gotoFiles(page)
    await page.getByRole('option', { name: new RegExp(folder) }).click()
    await page.keyboard.press('Delete')
    await page.getByRole('button', { name: 'Delete', exact: true }).click()
    await expect(page.getByRole('option', { name: new RegExp(folder) })).toHaveCount(0, { timeout: 30_000 })
  })

  test('logging out leaves nothing behind', async ({ page }) => {
    await gotoFiles(page)
    await page.getByRole('button', { name: /account menu/i }).click()
    await page.getByRole('menuitem', { name: /log out/i }).click()
    await page.waitForURL(/\/login/)
    const keys = await page.evaluate(() => Object.keys(localStorage))
    expect(keys.filter(k => k.startsWith('vaulthalla-') && k !== 'vaulthalla-ui')).toEqual([])
    await page.goto('/files')
    await expect(page).toHaveURL(/\/login/)
  })
})
