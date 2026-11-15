import { expect, test, type Page } from '@playwright/test'
import { armStepUp, authenticateAndSaveState, authStatePath, explicitSkipRequested } from './helpers/auth'
import { NOW, OFFLINE, count, scriptWs, type Answer, type Frame } from './helpers/scriptedWs'

// Paired devices (Vaulthalla Desktop): the Devices pages, the "Pair a device" dialog's number matching, and the super
// admin's remote-connections switch. The device.* answers are scripted on the console socket (page.routeWebSocket), so
// the suite proves the console's own rules against any daemon: a wrong code is declined, a conflicting window is
// explained and never closed, the countdown follows the node's clock (server_time) and the port comes from
// device.pairing.open.
//
// Two ways to run it:
// - against a reverse-proxied install like console.spec.ts (every other command reaches the real daemon; the session
//   user is shown as a super admin by patching the auth.refresh answer, UI gating only):
//     VAULTHALLA_E2E_BASE_URL=https://localhost VAULTHALLA_E2E_NO_WEB_SERVER=1 pnpm exec playwright test tests/e2e/devices.spec.ts
// - offline, with no daemon at all (`pnpm dev:e2e` is started for you; every command is scripted, others refused):
//     VAULTHALLA_E2E_OFFLINE=1 pnpm exec playwright test tests/e2e/devices.spec.ts

test.skip(explicitSkipRequested(), 'VAULTHALLA_E2E_SKIP set')
test.use({ ignoreHTTPSErrors: true, ...(OFFLINE ? {} : { storageState: authStatePath }) })
// Step-up dialogs (#359) are answered with the e2e account's password and TOTP code.
test.beforeEach(({ page }) => armStepUp(page))

test.beforeAll(async ({ browser }) => {
  if (!OFFLINE) await authenticateAndSaveState(browser)
})

const hex = (seed: string) => seed.repeat(64).slice(0, 64)

const device = (over: Record<string, unknown> = {}) => ({
  id: 3,
  device_id: hex('3fa9c1d2'),
  user_id: 7,
  user_name: 'e2e-user',
  name: 'Studio Mac',
  platform: 'macOS',
  app_version: '1.0.0',
  previous_device_id: null,
  approved_by: 7,
  created_at: NOW - 86_400,
  last_seen_at: NOW - 120,
  last_ip: '192.168.1.42',
  revoked_at: null as number | null,
  revoked: false,
  paired_via: 'listener',
  ...over,
})

const pairingWindow = () => ({ owner_id: 7, opened_at: NOW, expires_at: Math.floor(Date.now() / 1000) + 600 })

// The node's clock, 8 minutes ahead of the browser's: a countdown by the browser's clock would show ~10:00, by the
// node's ~2:00. The listener port is deliberately not the default: the console must show what the daemon reports.
const SERVER_AHEAD_S = 480
const serverTime = () => Math.floor(Date.now() / 1000) + SERVER_AHEAD_S
const opened = () => ({ window: pairingWindow(), server_time: serverTime(), port: 40123, remote: false })
const pendingAnswer = (requests: unknown[]) => ({ window: pairingWindow(), requests, server_time: serverTime() })

const request = (over: Record<string, unknown> = {}) => ({
  request_id: '7f3a9c1d2e4b6a80',
  name: 'Kitchen Mac',
  platform: 'macOS',
  app_version: '1.0.2',
  source_ip: '192.168.1.57',
  device_id: hex('9c1d'),
  code_choices: ['019337', '482913', '760001'],
  approval_key_present: false,
  via: 'listener',
  created_at: NOW,
  expires_at: NOW + 300,
  ...over,
})

const listener = (over: Record<string, unknown> = {}) => ({
  enabled: true,
  remote: false,
  // Deliberately not the default port: the console must show what the daemon reports.
  port: 40123,
  listening: true,
  address: '127.0.0.1',
  error: null,
  server_spki_sha256: hex('ab12'),
  connections: 1,
  ...over,
})

// Scripts device.* (helpers/scriptedWs.ts): offline every other command is refused, online it reaches the daemon.
const scriptDevices = (page: Page, answer: (frame: Frame) => Answer | undefined, opts: { superAdmin?: boolean } = {}) =>
  scriptWs(page, command => command.startsWith('device.'), answer, opts)

test.describe.serial('devices', () => {
  test('your devices: list, rename and revoke', async ({ page }) => {
    let devices = [device(), device({ id: 4, device_id: hex('51e0'), name: 'Old MacBook', revoked: true, revoked_at: NOW - 3600 })]
    const sent = await scriptDevices(page, frame => {
      if (frame.command === 'device.list') return { data: { devices } }
      if (frame.command === 'device.rename') {
        devices = devices.map(d => (d.device_id === frame.payload?.device_id ? { ...d, name: String(frame.payload?.name) } : d))
        return { data: { device: devices.find(d => d.device_id === frame.payload?.device_id) } }
      }
      if (frame.command === 'device.revoke') {
        devices = devices.map(d => (d.device_id === frame.payload?.device_id ? { ...d, revoked: true, revoked_at: NOW } : d))
        return { data: { device: devices.find(d => d.device_id === frame.payload?.device_id) } }
      }
      return undefined
    })
    await page.goto('/devices')
    const row = page.getByRole('row', { name: /Studio Mac/ })
    await expect(row).toBeVisible()
    await expect(row).toContainText('macOS')
    await expect(row).toContainText('192.168.1.42')
    await expect(row.getByTestId('device-id')).toHaveText(hex('3fa9c1d2').slice(0, 12))
    // Revoked devices stay listed, behind a switch.
    await expect(page.getByRole('row', { name: /Old MacBook/ })).toHaveCount(0)
    await page.getByTestId('devices-show-revoked').check()
    await expect(page.getByRole('row', { name: /Old MacBook/ })).toContainText('Revoked')
    await page.getByTestId('devices-show-revoked').uncheck()
    expect(sent.find(f => f.command === 'device.list')?.payload ?? {}).not.toHaveProperty('all', true)

    await page.getByTestId('device-rename-3').click()
    const rename = page.getByTestId('device-rename-dialog')
    await rename.getByRole('textbox', { name: 'Name' }).fill('Studio Mac Pro')
    await rename.getByRole('button', { name: 'Rename' }).click()
    await expect(rename).toHaveCount(0)
    await expect(page.getByRole('row', { name: /Studio Mac Pro/ })).toBeVisible()
    expect(sent.find(f => f.command === 'device.rename')?.payload).toEqual({ device_id: hex('3fa9c1d2'), name: 'Studio Mac Pro' })

    await page.getByTestId('device-revoke-3').click()
    const confirmDialog = page.getByRole('dialog', { name: 'Revoke Studio Mac Pro?' })
    await expect(confirmDialog).toContainText('This Mac loses access immediately and must pair again')
    await confirmDialog.getByRole('button', { name: 'Revoke' }).click()
    await expect(page.getByRole('row', { name: /Studio Mac Pro/ })).toHaveCount(0)
    expect(sent.find(f => f.command === 'device.revoke')?.payload).toEqual({ device_id: hex('3fa9c1d2') })
    await expect(page.getByText('Show revoked (2)')).toBeVisible()
  })

  test('pairing: the code the Mac shows pairs it', async ({ page }) => {
    let requests = [request()]
    let paired = false
    const sent = await scriptDevices(page, frame => {
      if (frame.command === 'device.list') return { data: { devices: paired ? [device({ id: 9, name: 'Kitchen Mac' })] : [] } }
      if (frame.command === 'device.pairing.open') return { data: opened() }
      if (frame.command === 'device.pairing.pending') return { data: pendingAnswer(requests) }
      if (frame.command === 'device.pairing.approve') {
        if (frame.payload?.code !== '482913') return { error: 'that is not the code the device shows', code: 'invalid' }
        requests = []
        paired = true
        return { data: { device: device({ id: 9, name: 'Kitchen Mac', device_id: hex('9c1d') }) } }
      }
      if (frame.command === 'device.pairing.close') return { data: { closed: true } }
      return undefined
    })
    await page.goto('/devices')
    await expect(page.getByTestId('devices-empty')).toBeVisible()
    await page.getByTestId('pair-open').click()

    const dialog = page.getByTestId('pair-dialog')
    await expect(dialog.getByTestId('pair-instructions')).toContainText('In Vaulthalla Desktop, add this server and choose Pair.')
    await expect(dialog.getByTestId('pair-countdown')).toContainText(/\b[12]:\d\d\b/)
    await expect(dialog.getByTestId('pair-server-address')).toHaveText(/:40123$/)
    const card = dialog.getByTestId('pair-request')
    await expect(card).toContainText('Kitchen Mac')
    await expect(card).toContainText('192.168.1.57')
    await expect(card).toContainText('1.0.2')
    await expect(card.getByTestId('pair-code')).toHaveText(['019 337', '482 913', '760 001'])

    const listsBefore = count(sent, 'device.list')
    await card.getByRole('button', { name: '482 913' }).click()
    await expect(dialog.getByTestId('pair-success')).toContainText('Paired')
    expect(sent.find(f => f.command === 'device.pairing.approve')?.payload).toEqual({ request_id: '7f3a9c1d2e4b6a80', code: '482913' })
    await expect.poll(() => count(sent, 'device.list')).toBeGreaterThan(listsBefore)

    await dialog.getByRole('button', { name: 'Done' }).click()
    await expect(dialog).toHaveCount(0)
    await expect.poll(() => count(sent, 'device.pairing.close')).toBe(1)
    // Its own window only: never `any`.
    expect(sent.find(f => f.command === 'device.pairing.close')?.payload).toEqual({})
    await expect(page.getByRole('row', { name: /Kitchen Mac/ })).toBeVisible()
  })

  test('pairing: a wrong code declines the request', async ({ page }) => {
    let requests = [request()]
    const sent = await scriptDevices(page, frame => {
      if (frame.command === 'device.list') return { data: { devices: [device()] } }
      if (frame.command === 'device.pairing.open') return { data: opened() }
      if (frame.command === 'device.pairing.pending') return { data: pendingAnswer(requests) }
      if (frame.command === 'device.pairing.approve') {
        // The daemon denies the request on any wrong code.
        requests = []
        return {
          error: 'that is not the code the device shows: the request was denied (pair again from the device and compare the codes)',
          code: 'invalid',
        }
      }
      if (frame.command === 'device.pairing.close') return { data: { closed: true } }
      return undefined
    })
    await page.goto('/devices')
    await page.getByTestId('pair-open').click()
    const dialog = page.getByTestId('pair-dialog')
    await dialog.getByTestId('pair-request').getByRole('button', { name: '019 337' }).click()
    await expect(dialog.getByTestId('pair-notice')).toHaveText(
      'That code didn’t match, so the request was declined. Start pairing again on the Mac.',
    )
    await expect(dialog.getByTestId('pair-request')).toHaveCount(0)
    await expect(dialog.getByTestId('pair-waiting')).toBeVisible()
    await expect(dialog.getByTestId('pair-success')).toHaveCount(0)
    expect(sent.find(f => f.command === 'device.pairing.approve')?.payload).toEqual({ request_id: '7f3a9c1d2e4b6a80', code: '019337' })
    await page.keyboard.press('Escape')
    await expect.poll(() => count(sent, 'device.pairing.close')).toBe(1)
  })

  test('pairing: another user’s window is explained and left alone', async ({ page }) => {
    const sent = await scriptDevices(
      page,
      frame => {
        if (frame.command === 'device.list') return { data: { devices: [] } }
        if (frame.command === 'device.remote.status') return { data: { status: listener() } }
        if (frame.command === 'device.pairing.open')
          return { error: 'another user is pairing a device on this node until 14:32; try again then', code: 'conflict' }
        return undefined
      },
      // The dialog opened no window of its own here, so it has nothing to close.
      { superAdmin: true },
    )
    await page.goto('/devices')
    await page.getByTestId('pair-open').click()
    const dialog = page.getByTestId('pair-dialog')
    await expect(dialog.getByTestId('pair-conflict')).toContainText('Someone else is pairing a device')
    await expect(dialog.getByTestId('pair-conflict')).toContainText('until 14:32')
    await dialog.getByTestId('pair-retry').click()
    await expect.poll(() => count(sent, 'device.pairing.open')).toBe(2)
    await expect(dialog.getByTestId('pair-conflict')).toBeVisible()
    await dialog.getByRole('button', { name: 'Close' }).last().click()
    await expect(dialog).toHaveCount(0)
    await page.waitForTimeout(300)
    expect(count(sent, 'device.pairing.close')).toBe(0)
    expect(count(sent, 'device.pairing.pending')).toBe(0)
  })

  test('pairing: advertised endpoints are listed and linked to Desktop (device.endpoints)', async ({ page }) => {
    const spki = 'ab'.repeat(32)
    const sent = await scriptDevices(page, frame => {
      if (frame.command === 'device.list') return { data: { devices: [] } }
      if (frame.command === 'device.pairing.open')
        return {
          data: {
            ...opened(),
            remote: true,
            server_spki_sha256: spki,
            endpoints: {
              port: 40123,
              remote: true,
              listening: true,
              candidates: [
                { host: '10.0.0.11', port: 40123, kind: 'lan', source: 'interface', interface: 'enp3s0' },
                { host: 'fd00::11', port: 40123, kind: 'lan', source: 'interface', interface: 'enp3s0' },
                { host: 'device.example.com', port: 443, kind: 'passthrough', source: 'config' },
              ],
            },
          },
        }
      if (frame.command === 'device.pairing.pending') return { data: pendingAnswer([]) }
      if (frame.command === 'device.pairing.close') return { data: { closed: true } }
      return undefined
    })
    await page.goto('/devices')
    await page.getByTestId('pair-open').click()
    const dialog = page.getByTestId('pair-dialog')
    await expect(dialog.getByTestId('pair-endpoint')).toHaveText(['10.0.0.11:40123', '[fd00::11]:40123', 'device.example.com:443'])
    const href = await dialog.getByTestId('pair-open-desktop').getAttribute('href')
    expect(href).toBe(`vaulthalla://pair?spki=${spki}&endpoints=${encodeURIComponent('10.0.0.11:40123,[fd00::11]:40123,device.example.com:443')}`)
    await dialog.getByRole('button', { name: 'Close' }).last().click()
    await expect.poll(() => count(sent, 'device.pairing.close')).toBe(1)
  })

  test('pairing: an older server shows no endpoint list', async ({ page }) => {
    await scriptDevices(page, frame => {
      if (frame.command === 'device.list') return { data: { devices: [] } }
      if (frame.command === 'device.pairing.open') return { data: opened() }
      if (frame.command === 'device.pairing.pending') return { data: pendingAnswer([]) }
      if (frame.command === 'device.pairing.close') return { data: { closed: true } }
      return undefined
    })
    await page.goto('/devices')
    await page.getByTestId('pair-open').click()
    const dialog = page.getByTestId('pair-dialog')
    await expect(dialog.getByTestId('pair-waiting')).toBeVisible()
    await expect(dialog.getByTestId('pair-endpoints')).toHaveCount(0)
  })

  test('super admin: every device and the remote-connections switch', async ({ page }) => {
    let status = listener()
    const sent = await scriptDevices(
      page,
      frame => {
        if (frame.command === 'device.list')
          return {
            data: {
              devices:
                frame.payload?.all ?
                  [device(), device({ id: 5, device_id: hex('77aa'), user_id: 11, user_name: 'alice', name: 'Alice’s Mac' })]
                : [device()],
            },
          }
        if (frame.command === 'device.remote.status') return { data: { status } }
        if (frame.command === 'device.remote.enable') {
          status = listener({ remote: true, address: '0.0.0.0' })
          return { data: { status } }
        }
        if (frame.command === 'device.remote.disable') {
          status = listener()
          return { data: { status } }
        }
        return undefined
      },
      { superAdmin: true },
    )
    await page.goto('/devices')
    await page.getByRole('link', { name: 'All devices' }).click()
    await expect(page).toHaveURL(/\/devices\/all$/)

    const alice = page.getByRole('row', { name: /Alice’s Mac/ })
    await expect(alice).toContainText('alice')
    expect(sent.some(f => f.command === 'device.list' && f.payload?.all === true)).toBe(true)

    const remote = page.getByTestId('remote-connections')
    await expect(remote.getByTestId('remote-port')).toHaveText('40123')
    await expect(remote.getByTestId('remote-address')).toHaveText('127.0.0.1')
    await expect(remote.getByTestId('remote-state')).toContainText('Listening')
    await expect(remote).toContainText('Off: only this machine can pair and connect.')
    const toggle = remote.getByRole('switch', { name: 'Allow remote connections' })
    await expect(toggle).toHaveAttribute('aria-checked', 'false')

    await toggle.click()
    const allow = page.getByRole('dialog', { name: 'Allow remote connections?' })
    await expect(allow).toContainText('40123/tcp')
    await allow.getByRole('button', { name: 'Allow' }).click()
    await expect(toggle).toHaveAttribute('aria-checked', 'true')
    await expect(remote).toContainText('On: Macs on your network can pair and reconnect.')
    await expect(remote.getByTestId('remote-address')).toHaveText('0.0.0.0')
    expect(count(sent, 'device.remote.enable')).toBe(1)

    await toggle.click()
    await page.getByRole('dialog', { name: 'Turn off remote connections?' }).getByRole('button', { name: 'Turn off' }).click()
    await expect(toggle).toHaveAttribute('aria-checked', 'false')
    expect(count(sent, 'device.remote.disable')).toBe(1)
  })

  test('pairing: a web browser via the relay is labelled and read-only', async ({ page }) => {
    const browser = request({
      request_id: 'a1b2c3d4e5f60718',
      name: 'Firefox on a laptop',
      platform: 'web',
      app_version: '0.1.0',
      source_ip: '203.0.113.9',
      device_id: hex('beef'),
      via: 'relay',
    })
    let requests = [browser, request()]
    const sent = await scriptDevices(page, frame => {
      if (frame.command === 'device.list') return { data: { devices: [] } }
      if (frame.command === 'device.pairing.open') return { data: opened() }
      if (frame.command === 'device.pairing.pending') return { data: pendingAnswer(requests) }
      if (frame.command === 'device.pairing.approve') {
        requests = requests.filter(r => r.request_id !== frame.payload?.request_id)
        return { data: { device: device({ id: 12, name: 'Firefox on a laptop', platform: 'web', device_id: hex('beef'), paired_via: 'relay' }) } }
      }
      if (frame.command === 'device.pairing.close') return { data: { closed: true } }
      return undefined
    })
    await page.goto('/devices')
    await page.getByTestId('pair-open').click()
    const dialog = page.getByTestId('pair-dialog')
    const relayed = dialog.locator('[data-testid="pair-request"][data-request-id="a1b2c3d4e5f60718"]')
    await expect(relayed.getByTestId('pair-request-kind')).toHaveText('Web browser (relay)')
    await expect(relayed.getByTestId('pair-request-read-only')).toContainText('It will be read-only')
    await expect(dialog.getByTestId('pair-browser-hint')).toContainText("a web browser is paired from your account's web page")
    await expect(dialog).not.toContainText(/vaulthalla cloud/i)
    await expect(relayed).toContainText('Which code does the browser show?')
    await expect(relayed).toContainText('203.0.113.9')
    // A request from the listener keeps the Desktop wording.
    const desktop = dialog.locator('[data-testid="pair-request"][data-request-id="7f3a9c1d2e4b6a80"]')
    await expect(desktop.getByTestId('pair-request-kind')).toHaveText('macOS · Desktop 1.0.2')
    await expect(desktop.getByTestId('pair-request-read-only')).toHaveCount(0)
    await expect(desktop).toContainText('Which code does the Mac show?')

    await relayed.getByRole('button', { name: '482 913' }).click()
    await expect(dialog.getByTestId('pair-success')).toContainText('It is read-only and finishes connecting on its own.')
    expect(sent.find(f => f.command === 'device.pairing.approve')?.payload).toEqual({ request_id: 'a1b2c3d4e5f60718', code: '482913' })
  })

  test('devices: a browser paired via the relay is marked read-only and revokes like any device', async ({ page }) => {
    let devices = [device(), device({ id: 12, name: 'Firefox on a laptop', platform: 'web', app_version: '0.1.0', device_id: hex('beef'), paired_via: 'relay' })]
    const sent = await scriptDevices(page, frame => {
      if (frame.command === 'device.list') return { data: { devices } }
      if (frame.command === 'device.revoke') {
        devices = devices.map(d => (d.device_id === frame.payload?.device_id ? { ...d, revoked: true, revoked_at: NOW } : d))
        return { data: { device: devices.find(d => d.device_id === frame.payload?.device_id) } }
      }
      return undefined
    })
    await page.goto('/devices')
    const relayed = page.getByRole('row', { name: /Firefox on a laptop/ })
    await expect(relayed.getByTestId('device-read-only')).toHaveText('Read-only')
    await expect(relayed.getByTestId('device-platform')).toHaveText('Web browser (relay)')
    const mac = page.getByRole('row', { name: /Studio Mac/ })
    await expect(mac.getByTestId('device-read-only')).toHaveCount(0)
    await expect(mac.getByTestId('device-platform')).toHaveText('macOS')

    await page.getByTestId('device-revoke-12').click()
    const confirmDialog = page.getByRole('dialog', { name: 'Revoke Firefox on a laptop?' })
    await expect(confirmDialog).toContainText('This browser loses access immediately and must pair again')
    await confirmDialog.getByRole('button', { name: 'Revoke' }).click()
    await expect(relayed).toHaveCount(0)
    expect(sent.find(f => f.command === 'device.revoke')?.payload).toEqual({ device_id: hex('beef') })
  })

  test('the All devices tab is for super admins only', async ({ page }) => {
    test.skip(!OFFLINE, 'the live e2e account may be a super admin; offline the role is scripted')
    await scriptDevices(page, frame => (frame.command === 'device.list' ? { data: { devices: [device()] } } : undefined))
    await page.goto('/devices')
    await expect(page.getByRole('row', { name: /Studio Mac/ })).toBeVisible()
    await expect(page.getByRole('link', { name: 'All devices' })).toHaveCount(0)
    await page.goto('/devices/all')
    await expect(page.getByText('You don\'t have access to this')).toBeVisible()
  })
})
