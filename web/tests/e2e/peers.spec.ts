import { expect, test, type Page } from '@playwright/test'
import { armStepUp, authenticateAndSaveState, authStatePath, explicitSkipRequested } from './helpers/auth'
import { NOW, OFFLINE, count, scriptWs, type Answer, type Frame, type ScriptedRole } from './helpers/scriptedWs'

// Linked servers (/linked-servers; design/peers/link.md, experimental and off by default): the page only exists for a
// super admin on a server with peers.experimental on (peer.status), the list's health words, rename and unlink, Accept
// a link (the window, three codes, a wrong code declining, the device.trust step-up before approving) and Link a server
// (the address and key sent, the step-up, the code this server computed, the outcome, cancelling). peer.*,
// device.remote.status and auth.stepup.* are scripted on the console socket (helpers/scriptedWs.ts), so the suite proves
// the console's own rules against any daemon; a real two-server link is the `vhh drill peers` harness's job.
// Screenshots of each layout land in the test's output directory (test-results/).
//
//     VAULTHALLA_E2E_OFFLINE=1 pnpm exec playwright test tests/e2e/peers.spec.ts                  # no daemon
//     VAULTHALLA_E2E_BASE_URL=https://localhost VAULTHALLA_E2E_NO_WEB_SERVER=1 pnpm exec playwright test tests/e2e/peers.spec.ts

test.skip(explicitSkipRequested(), 'VAULTHALLA_E2E_SKIP set')
test.use({ ignoreHTTPSErrors: true, ...(OFFLINE ? {} : { storageState: authStatePath }) })
test.beforeEach(({ page }) => armStepUp(page))
test.beforeAll(async ({ browser }) => {
  if (!OFFLINE) await authenticateAndSaveState(browser)
})

const hex = (seed: string) => seed.repeat(64).slice(0, 64)

const health = (over: Record<string, unknown> = {}) => ({
  connected: false,
  since: null as number | null,
  dialed_by: null as string | null,
  address: null as string | null,
  rtt_ms: null as number | null,
  peer_protocol: null as number | null,
  peer_version: null as string | null,
  protocol_compatible: null as boolean | null,
  last_error: null as string | null,
  last_error_at: null as number | null,
  next_attempt_at: null as number | null,
  ...over,
})

const peer = (over: Record<string, unknown> = {}) => ({
  id: 3,
  node_id: 'node-b-4f1c9a2e7d',
  name: 'vps',
  spki_sha256: hex('ab12'),
  next_spki_sha256: null,
  attest_public_keys: [],
  wrap_public_key: 'AAAA',
  endpoints: [{ host: '10.0.0.20', port: 36972, kind: 'lan' }],
  sharing: 'identities',
  approved_by: 7,
  compared_by: 'person',
  peer_protocol: 1,
  product_version: '1.27.0',
  linked_at: NOW - 3 * 86_400,
  last_seen_at: NOW - 30,
  revoked_at: null as number | null,
  revoked: false,
  health: health({ connected: true, since: NOW - 3600, dialed_by: 'peer', address: '10.0.0.20', rtt_ms: 4, peer_protocol: 1, peer_version: '1.27.0', protocol_compatible: true }),
  ...over,
})

const windowOf = () => ({ owner_id: 7, opened_at: NOW, expires_at: Math.floor(Date.now() / 1000) + 600 })
const opened = (over: Record<string, unknown> = {}) => ({
  window: windowOf(),
  server_time: Math.floor(Date.now() / 1000),
  node_id: 'node-this-0011',
  name: 'studio',
  spki_sha256: hex('cd34'),
  endpoints: {
    port: 40123,
    remote: true,
    listening: true,
    generated_at: NOW,
    candidates: [
      { host: '10.0.0.11', port: 40123, kind: 'lan' },
      { host: 'fd00::11', port: 40123, kind: 'lan' },
    ],
  },
  ...over,
})

const request = (over: Record<string, unknown> = {}) => ({
  request_id: 'r-7f3a9c1d',
  node_id: 'node-a-9c1d2e4b',
  name: 'mac-mini',
  product_version: '1.27.0',
  peer_protocol: 1,
  spki_sha256: hex('9c1d'),
  source_ip: '10.0.0.30',
  code_choices: ['760001', '227515', '019337'],
  created_at: NOW,
  expires_at: NOW + 300,
  ...over,
})

const attempt = (over: Record<string, unknown> = {}) => ({
  link_id: 'l-1',
  state: 'connecting',
  code: null as string | null,
  peer: null as unknown,
  peer_id: null as number | null,
  expect_spki: null as string | null,
  address: '10.0.0.5:40123',
  error: null as string | null,
  created_at: NOW,
  updated_at: NOW,
  ...over,
})

const listener = () => ({
  enabled: true,
  remote: true,
  port: 40123,
  listening: true,
  address: '0.0.0.0',
  error: null,
  server_spki_sha256: hex('cd34'),
  connections: 0,
})

const stepUpFor = (target: string): Answer => ({
  error: 'confirm it is you first',
  code: 'step_up_required',
  errorData: { family: 'device.trust', target, methods: ['password'], max_age_seconds: 300 },
})

const owns = (command: string) => command.startsWith('peer.') || command.startsWith('auth.stepup.') || command === 'device.remote.status'

// The test's own answers first; then peer.status (on unless a test says otherwise), the listener's status and a
// scripted step-up (password only) that always succeeds.
const scriptPeers = (page: Page, answer: (frame: Frame) => Answer | undefined, { role = true as ScriptedRole, enabled = true } = {}) =>
  scriptWs(
    page,
    owns,
    frame => {
      const own = answer(frame)
      if (own) return own
      if (frame.command === 'peer.status') return { data: { enabled } }
      if (frame.command === 'device.remote.status') return { data: { status: listener() } }
      if (frame.command === 'auth.stepup.begin') {
        const target = String(frame.payload?.target ?? '')
        return { data: { stepup_id: 'su-1', family: 'device.trust', target, methods: ['password'] } }
      }
      if (frame.command === 'auth.stepup.finish') return { data: { family: 'device.trust', target: null, expires_at: NOW + 300, uses: 1 } }
      return undefined
    },
    { superAdmin: role },
  )

const confirmStepUp = async (page: Page) => {
  const stepUp = page.getByTestId('stepup-dialog')
  await expect(stepUp).toContainText('Link this server with another server')
  // Online, armStepUp answers it with the e2e account; offline it is filled here.
  if (OFFLINE) {
    await stepUp.getByTestId('stepup-password').fill('scripted-password')
    await stepUp.getByTestId('stepup-submit').click()
  }
  await expect(stepUp).toHaveCount(0)
}

const shoot = async (page: Page, name: string) => {
  for (const [label, size] of [
    ['desktop', { width: 1280, height: 900 }],
    ['narrow', { width: 390, height: 844 }],
  ] as const) {
    await page.setViewportSize(size)
    await page.waitForTimeout(200)
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), `${label}: no sideways scrolling`).toBe(true)
    await page.screenshot({ path: test.info().outputPath(`${name}-${label}.png`), fullPage: true })
  }
  await page.setViewportSize({ width: 1280, height: 900 })
}

const peerCommands = (sent: Frame[]) => sent.filter(f => f.command.startsWith('peer.') && f.command !== 'peer.status').map(f => f.command)

test.describe.serial('linked servers', () => {
  test('switched off: no nav entry, and the URL says only that it is not available', async ({ page }) => {
    const sent = await scriptPeers(page, () => undefined, { enabled: false })
    await page.goto('/linked-servers')
    const off = page.getByTestId('peers-unavailable')
    await expect(off).toHaveText(/Linked servers aren’t available on this server/)
    await expect(page.locator('main')).not.toContainText(/experimental|peers\.experimental|config\.yaml/i)
    await expect(page.getByRole('link', { name: 'Linked servers' })).toHaveCount(0)
    expect(count(sent, 'peer.status')).toBeGreaterThan(0)
    expect(peerCommands(sent)).toEqual([])
  })

  test('not a super admin: denied, and nothing is asked', async ({ page }) => {
    const sent = await scriptPeers(page, () => undefined, { role: false })
    await page.goto('/linked-servers')
    await expect(page.getByText('You don\'t have access to this')).toBeVisible()
    await expect(page.getByRole('link', { name: 'Linked servers' })).toHaveCount(0)
    expect(sent.filter(f => f.command.startsWith('peer.'))).toEqual([])
  })

  test('list: health in words, rename and unlink', async ({ page }) => {
    let peers = [
      peer(),
      peer({
        id: 4,
        node_id: 'node-c-77aa01',
        name: 'office',
        spki_sha256: hex('77aa'),
        compared_by: 'desktop',
        health: health({ last_error: 'connection refused', next_attempt_at: NOW + 60 }),
      }),
      peer({ id: 2, node_id: 'node-d-old', name: 'old-box', spki_sha256: hex('5150'), revoked: true, revoked_at: NOW - 86_400 }),
    ]
    const sent = await scriptPeers(page, frame => {
      if (frame.command === 'peer.list') return { data: { peers } }
      if (frame.command === 'peer.rename') {
        peers = peers.map(p => (String(p.id) === frame.payload?.peer ? { ...p, name: String(frame.payload?.name) } : p))
        return { data: { peer: peers.find(p => String(p.id) === frame.payload?.peer) } }
      }
      if (frame.command === 'peer.unlink') {
        peers = peers.map(p => (String(p.id) === frame.payload?.peer ? { ...p, revoked: true, revoked_at: NOW } : p))
        return { data: { peer: peers.find(p => String(p.id) === frame.payload?.peer) } }
      }
      return undefined
    })
    await page.goto('/linked-servers')
    await expect(page.getByRole('heading', { level: 1 })).toContainText('Linked servers')
    await expect(page.getByTestId('peers-experimental')).toHaveText('Experimental')
    await expect(page.getByTestId('peers-purpose')).toHaveText(/vault mirroring will use in a later release; today it carries nothing else/)
    await expect(page.getByRole('link', { name: 'Linked servers' }).first()).toBeVisible()
    expect(sent.find(f => f.command === 'peer.list')?.payload).toEqual({ all: true })

    const vps = page.getByRole('row', { name: /vps/ })
    await expect(vps.getByTestId('peer-health-label')).toHaveText('Connected')
    await expect(vps.getByTestId('peer-health-facts')).toHaveText(/^since .+ · it dialled · 4 ms · Vaulthalla 1\.27\.0$/)
    await expect(vps.getByTestId('peer-node')).toHaveText('node-b-4f1c9')
    await expect(vps.getByTestId('peer-key')).toHaveText('ab12 ab12 ab12 ab12')
    await expect(vps.getByTestId('peer-compared-by')).toHaveText('A person')
    const office = page.getByRole('row', { name: /office/ })
    await expect(office.getByTestId('peer-health-label')).toHaveText('Not connected')
    await expect(office.getByTestId('peer-health-facts')).toContainText('connection refused · next try ')
    await expect(office.getByTestId('peer-compared-by')).toHaveText('Desktop')
    // Unlinked rows stay listed behind a switch.
    await expect(page.getByRole('row', { name: /old-box/ })).toHaveCount(0)
    await page.getByTestId('peers-show-unlinked').check()
    await expect(page.getByRole('row', { name: /old-box/ }).getByTestId('peer-health-label')).toHaveText('Unlinked')
    await page.getByTestId('peers-show-unlinked').uncheck()
    await shoot(page, 'peers-list')

    await page.getByTestId('peer-rename-3').click()
    const rename = page.getByTestId('peer-rename-dialog')
    await rename.getByRole('textbox', { name: 'Name' }).fill('vps-frankfurt')
    await rename.getByRole('button', { name: 'Rename' }).click()
    await expect(rename).toHaveCount(0)
    expect(sent.find(f => f.command === 'peer.rename')?.payload).toEqual({ peer: '3', name: 'vps-frankfurt' })
    await expect(page.getByRole('row', { name: /vps-frankfurt/ })).toBeVisible()

    await page.getByTestId('peer-unlink-3').click()
    const ask = page.getByRole('dialog', { name: 'Unlink vps-frankfurt?' })
    await expect(ask).toContainText('keeps nothing it can use to reconnect')
    await expect(ask).toContainText('Linking them again takes a new pairing with a new code')
    await expect(ask).toContainText('No files, vaults or accounts change on either server')
    await ask.getByRole('button', { name: 'Unlink' }).click()
    await expect(page.getByRole('row', { name: /vps-frankfurt/ })).toHaveCount(0)
    expect(sent.find(f => f.command === 'peer.unlink')?.payload).toEqual({ peer: '3' })
    await expect(page.getByText('Show unlinked (2)')).toBeVisible()
  })

  test('a refusal shows the server’s words and its code', async ({ page }) => {
    await scriptPeers(page, frame => {
      if (frame.command === 'peer.list') return { data: { peers: [peer()] } }
      if (frame.command === 'peer.unlink') return { error: 'only a person, or a fully trusted device connected directly, may unlink servers', code: 'peer_forbidden' }
      return undefined
    })
    await page.goto('/linked-servers')
    await page.getByTestId('peer-unlink-3').click()
    await page.getByRole('dialog', { name: 'Unlink vps?' }).getByRole('button', { name: 'Unlink' }).click()
    await expect(page.getByTestId('peer-error')).toContainText('only a person, or a fully trusted device connected directly, may unlink servers')
    await expect(page.getByTestId('peer-error-code')).toHaveText('(peer_forbidden)')
  })

  test('accept a link: this server’s key and addresses, a wrong code declines, the right one links after a step-up', async ({ page }) => {
    let requests = [request({ request_id: 'r-wrong', name: 'stranger' })]
    let stepped = false
    let linked = false
    const sent = await scriptPeers(page, frame => {
      if (frame.command === 'peer.list') return { data: { peers: linked ? [peer({ id: 9, name: 'mac-mini', compared_by: 'person' })] : [] } }
      if (frame.command === 'peer.pairing.open') return { data: opened() }
      if (frame.command === 'peer.pairing.pending') return { data: { window: windowOf(), requests, server_time: Math.floor(Date.now() / 1000) } }
      if (frame.command === 'peer.pairing.approve') {
        if (frame.payload?.request_id === 'r-wrong') {
          requests = [request()]
          return { error: 'that is not the code the other server shows: the request was denied', code: 'invalid' }
        }
        if (!stepped) return stepUpFor('peer.pairing.approve:r-7f3a9c1d:' + hex('9c1d') + ':0011')
        requests = []
        linked = true
        return { data: { peer: peer({ id: 9, name: 'mac-mini', health: undefined }) } }
      }
      if (frame.command === 'auth.stepup.finish') stepped = true
      if (frame.command === 'peer.pairing.close') return { data: { closed: true } }
      return undefined
    })
    await page.goto('/linked-servers')
    await expect(page.getByTestId('peer-health')).toHaveCount(0)
    await page.getByTestId('peers-accept-open').click()
    const dialog = page.getByTestId('peer-accept-dialog')
    await expect(dialog.getByTestId('peer-accept-name')).toHaveText('studio')
    await expect(dialog.getByTestId('peer-accept-key')).toHaveText(hex('cd34').match(/.{4}/g)!.join(' '))
    await expect(dialog.getByTestId('peer-accept-endpoint')).toHaveText(['10.0.0.11:40123', '[fd00::11]:40123'])
    await expect(dialog.getByTestId('peer-accept-countdown')).toContainText(/\b(9|10):\d\d\b/)
    await expect(dialog.getByTestId('peer-accept-steps')).toContainText('a wrong code declines the request')

    const stranger = dialog.getByTestId('peer-request')
    await expect(stranger.getByTestId('peer-request-name')).toHaveText('stranger')
    await stranger.getByRole('button', { name: '760 001' }).click()
    await expect(dialog.getByTestId('peer-accept-notice')).toHaveText(
      'That code didn’t match, so the request was declined. Start the link again on the other server.',
    )

    const card = dialog.getByTestId('peer-request')
    await expect(card.getByTestId('peer-request-name')).toHaveText('mac-mini')
    await expect(card).toContainText('from 10.0.0.30')
    await expect(card).toContainText('Vaulthalla 1.27.0')
    await expect(card.getByTestId('peer-request-key')).toHaveText(hex('9c1d').match(/.{4}/g)!.join(' '))
    await expect(card.getByTestId('peer-request-code')).toHaveText(['760 001', '227 515', '019 337'])
    await shoot(page, 'peers-accept')
    await card.getByRole('button', { name: '227 515' }).click()
    await confirmStepUp(page)
    await expect(dialog.getByTestId('peer-accept-linked')).toContainText('mac-mini is now linked with this server')
    expect(sent.filter(f => f.command === 'peer.pairing.approve').map(f => f.payload)).toEqual([
      { request_id: 'r-wrong', code: '760001' },
      { request_id: 'r-7f3a9c1d', code: '227515' },
      { request_id: 'r-7f3a9c1d', code: '227515' }, // refused once for the step-up, then resent
    ])
    expect(sent.find(f => f.command === 'auth.stepup.begin')?.payload).toMatchObject({ family: 'device.trust' })
    await dialog.getByRole('button', { name: 'Done' }).click()
    await expect(dialog).toHaveCount(0)
    await expect(page.getByRole('row', { name: /mac-mini/ })).toBeVisible()
    // The server closed the window when it approved: nothing left to close.
    await page.waitForTimeout(300)
    expect(count(sent, 'peer.pairing.close')).toBe(0)
  })

  test('accept a link: closing the dialog closes its window; another window is explained and left alone', async ({ page }) => {
    let conflict = false
    const sent = await scriptPeers(page, frame => {
      if (frame.command === 'peer.list') return { data: { peers: [] } }
      if (frame.command === 'peer.pairing.open')
        return conflict ? { error: 'another pairing window is open on this node until 14:32', code: 'conflict' } : { data: opened({ endpoints: { ...opened().endpoints, remote: false } }) }
      if (frame.command === 'peer.pairing.pending') return { data: { window: windowOf(), requests: [], server_time: Math.floor(Date.now() / 1000) } }
      if (frame.command === 'peer.pairing.close') return { data: { closed: true } }
      return undefined
    })
    await page.goto('/linked-servers')
    await page.getByTestId('peers-accept-open').click()
    const dialog = page.getByTestId('peer-accept-dialog')
    await expect(dialog.getByTestId('peer-accept-waiting')).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(dialog).toHaveCount(0)
    await expect.poll(() => count(sent, 'peer.pairing.close')).toBe(1)

    conflict = true
    await page.getByTestId('peers-accept-open').click()
    await expect(dialog.getByTestId('peer-accept-conflict')).toContainText('Another pairing window is open')
    await expect(dialog.getByTestId('peer-error')).toContainText('until 14:32')
    await expect(dialog.getByTestId('peer-error-code')).toHaveText('(conflict)')
    await dialog.getByRole('button', { name: 'Close' }).last().click()
    await page.waitForTimeout(300)
    expect(count(sent, 'peer.pairing.close')).toBe(1)
  })

  test('link a server: the address, port and key are sent after a step-up, the code is shown, then the outcome', async ({ page }) => {
    let stepped = false
    let polls = 0
    const sent = await scriptPeers(page, frame => {
      if (frame.command === 'peer.list') return { data: { peers: [] } }
      if (frame.command === 'peer.link.start') {
        if (!stepped) return stepUpFor('peer.link.start:' + hex('9c1d') + ':10.0.0.5:40123')
        return { data: { link: attempt({ expect_spki: hex('9c1d') }) } }
      }
      if (frame.command === 'auth.stepup.finish') stepped = true
      if (frame.command === 'peer.link.status') {
        polls += 1
        const card = { node_id: 'node-b-4f1c9a2e7d', name: 'vps', product_version: '1.27.0', spki_sha256: hex('9c1d') }
        if (polls < 3) return { data: { link: attempt({ state: 'awaiting_approval', code: '227515', peer: card, updated_at: NOW + 1 }) } }
        return { data: { link: attempt({ state: 'linked', code: '227515', peer: card, peer_id: 5, updated_at: NOW + 2 }) } }
      }
      return undefined
    })
    await page.goto('/linked-servers')
    await page.getByTestId('peers-link-open').click()
    const dialog = page.getByTestId('peer-link-dialog')
    // The port defaults to this server's own device listener port, as `vh peer link <host>` does.
    await expect(dialog.getByTestId('peer-link-port')).toHaveValue('40123')
    await dialog.getByTestId('peer-link-start').click()
    await expect(dialog).toContainText('Enter the other server’s address.')
    await dialog.getByTestId('peer-link-address').fill('10.0.0.5')
    await dialog.getByTestId('peer-link-key').fill('9c1d')
    await dialog.getByTestId('peer-link-start').click()
    await expect(dialog).toContainText('A key is 64 hex digits; this has 4.')
    expect(count(sent, 'peer.link.start')).toBe(0)
    await dialog.getByTestId('peer-link-key').fill(hex('9C1D').match(/.{2}/g)!.join(':'))
    await shoot(page, 'peers-link-form')
    await dialog.getByTestId('peer-link-start').click()
    await confirmStepUp(page)

    await expect(dialog.getByTestId('peer-link-code')).toHaveText('227 515')
    await expect(dialog).toContainText('On vps, click this code on this server’s request.')
    await expect(dialog.getByTestId('peer-link-peer-key')).toHaveText(hex('9c1d').match(/.{4}/g)!.join(' '))
    await shoot(page, 'peers-link-code')
    await expect(dialog.getByTestId('peer-link-state')).toHaveText('Linked', { timeout: 10_000 })
    await expect(dialog.getByTestId('peer-link-outcome')).toHaveText('Linked with vps. The two connect on their own.')
    expect(sent.filter(f => f.command === 'peer.link.start').map(f => f.payload)).toEqual([
      { endpoints: [{ host: '10.0.0.5', port: 40123 }], expect_spki: hex('9c1d') },
      { endpoints: [{ host: '10.0.0.5', port: 40123 }], expect_spki: hex('9c1d') },
    ])
    expect(sent.find(f => f.command === 'peer.link.status')?.payload).toEqual({ link_id: 'l-1' })
    await dialog.getByRole('button', { name: 'Done' }).click()
    await page.waitForTimeout(300)
    expect(count(sent, 'peer.link.cancel')).toBe(0)
  })

  test('link a server: a failure keeps its reason, and closing a running attempt cancels it', async ({ page }) => {
    let failing = true
    const sent = await scriptPeers(page, frame => {
      if (frame.command === 'peer.list') return { data: { peers: [] } }
      if (frame.command === 'peer.link.start') return { data: { link: attempt() } }
      if (frame.command === 'peer.link.status')
        return failing ?
            { data: { link: attempt({ state: 'failed', error: 'no window for linking a server is open on this server', updated_at: NOW + 1 }) } }
          : { data: { link: attempt({ state: 'connecting', updated_at: NOW + 1 }) } }
      if (frame.command === 'peer.link.cancel') return { data: { link: attempt({ state: 'cancelled', updated_at: NOW + 2 }) } }
      return undefined
    })
    await page.goto('/linked-servers')
    await page.getByTestId('peers-link-open').click()
    const dialog = page.getByTestId('peer-link-dialog')
    await dialog.getByTestId('peer-link-address').fill('[fd00::5]:9')
    await dialog.getByTestId('peer-link-start').click()
    await expect(dialog.getByTestId('peer-link-outcome')).toHaveText('Couldn’t link: no window for linking a server is open on this server')
    expect(sent.find(f => f.command === 'peer.link.start')?.payload).toEqual({ endpoints: [{ host: 'fd00::5', port: 9 }] })

    failing = false
    await dialog.getByTestId('peer-link-again').click()
    await dialog.getByTestId('peer-link-address').fill('vps.example.com')
    await dialog.getByTestId('peer-link-start').click()
    await expect(dialog.getByTestId('peer-link-state')).toHaveText('Connecting')
    await page.keyboard.press('Escape')
    await expect(dialog).toHaveCount(0)
    await expect.poll(() => count(sent, 'peer.link.cancel')).toBe(1)
    expect(sent.find(f => f.command === 'peer.link.cancel')?.payload).toEqual({ link_id: 'l-1' })
  })
})
