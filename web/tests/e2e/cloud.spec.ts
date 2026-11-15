import { expect, test, type Page } from '@playwright/test'
import { armStepUp, authenticateAndSaveState, authStatePath, explicitSkipRequested } from './helpers/auth'
import { NOW, OFFLINE, count, scriptWs, type Answer, type Frame, type ScriptedRole } from './helpers/scriptedWs'

// The server's cloud page (/managed-storage): managed storage (design/cloud/managed-remotes.md, "The console page") and
// the cloud relay's switch (design/cloud/relay.md, "The switch"). meta.hello, cloud.* and auth.stepup.* are scripted on
// the console socket (helpers/scriptedWs.ts), so the suite proves the console's own rules without a linked server: what
// each state reads as, who sees which control, the payloads the controls send, the step-up before the relay goes on.
// Screenshots of each layout land in the test's output directory (test-results/) for review.
//
//     VAULTHALLA_E2E_OFFLINE=1 pnpm exec playwright test tests/e2e/cloud.spec.ts                  # no daemon
//     VAULTHALLA_E2E_BASE_URL=https://localhost VAULTHALLA_E2E_NO_WEB_SERVER=1 pnpm exec playwright test tests/e2e/cloud.spec.ts

test.skip(explicitSkipRequested(), 'VAULTHALLA_E2E_SKIP set')
test.use({ ignoreHTTPSErrors: true, ...(OFFLINE ? {} : { storageState: authStatePath }) })
test.beforeEach(({ page }) => armStepUp(page))
test.beforeAll(async ({ browser }) => {
  if (!OFFLINE) await authenticateAndSaveState(browser)
})

const GIB = 1024 ** 3

const hello = (relay = true) => ({
  server: { name: 'vaulthalla', version: '1.22.0' },
  protocol: { version: 3, min: 1, max: 3 },
  capabilities: ['cloud.storage.managed_remotes', 'cloud.account_key', ...(relay ? ['cloud.relay'] : [])],
  commands: [],
  contract: { contract_version: 3, contract_hash: 'x', ws_hash: 'x', models_hash: 'x' },
})

const vault = (over: Record<string, unknown> = {}) => ({
  vault_id: 1,
  vault_name: 'Photos',
  vault_uid: '01jbz5c0000000000000000000',
  storage: 'managed',
  switch: 'on',
  state: 'active',
  reason: null,
  summary: 'Backed up',
  local_bytes: 12 * GIB,
  access: 'full',
  key_state: 'active',
  key_access: 'full',
  retention_days: 30,
  retention_sent: 30,
  retention_pending: false,
  recovery: 'ready',
  progress: null,
  lost: null,
  last_error: null,
  active_at: NOW - 86_400,
  moved_at: null,
  ejected_at: null,
  ended_at: null,
  ...over,
})

const storage = (over: Record<string, unknown> = {}) => ({
  linked: true,
  account_key: 'pinned',
  available: true,
  entitlement: 'active',
  plan: 'Standard 1 TB',
  quota_bytes: 1024 * GIB,
  used_bytes: 312 * GIB,
  usage_day: '2026-11-14',
  storage_access: 'full',
  cause: null,
  managed_local_bytes: 40 * GIB,
  new_vaults: true,
  offer_open: true,
  offered: [
    vault({ vault_id: 4, vault_name: 'Old projects', switch: 'offered', state: 'off', storage: 'local', summary: 'Offered', local_bytes: 3 * GIB }),
    vault({ vault_id: 5, vault_name: 'Scans', switch: 'offered', state: 'off', storage: 'local', summary: 'Offered', local_bytes: 512 * 1024 ** 2 }),
  ],
  vaults: [
    vault(),
    vault({
      vault_id: 2,
      vault_name: 'Music library with a rather long name that has to wrap or truncate on a phone',
      state: 'attaching',
      summary: 'Uploading 40 %',
      progress: { bytes_done: 40 * GIB, bytes_total: 100 * GIB },
    }),
    vault({ vault_id: 3, vault_name: 'Taxes', storage: 'local', switch: 'off', state: 'off', summary: 'Stays on this server', access: null }),
    vault({ vault_id: 6, vault_name: 'Shared drive', storage: 'own', switch: null, state: 'active', summary: 'Uses its own storage' }),
  ],
  billing: null,
  ejection: null,
  fetched_at: NOW - 300,
  fetch_error: null,
  ended: null as { since: number; converts_at: number; confirmed_by: string | null } | null,
  next_step: null,
  ...over,
})

const relay = (over: Record<string, unknown> = {}) => ({
  state: 'off' as string,
  enabled: false,
  enabled_by: null as string | null,
  enabled_at: null as number | null,
  relay_url: null,
  connected_since: null as number | null,
  renew_by: null,
  last_ticket_at: null,
  next_attempt_at: null as number | null,
  last_error: null as string | null,
  streams: 0,
  streams_accepted: 0,
  streams_refused: 0,
  ...over,
})

const owns = (command: string) => command === 'meta.hello' || command.startsWith('cloud.') || command.startsWith('auth.stepup.')

const scriptCloud = (page: Page, answer: (frame: Frame) => Answer | undefined, role: ScriptedRole = true) =>
  scriptWs(page, owns, answer, { superAdmin: role })

const shoot = async (page: Page, name: string) => {
  for (const [label, size] of [
    ['desktop', { width: 1280, height: 900 }],
    ['narrow', { width: 390, height: 844 }],
  ] as const) {
    await page.setViewportSize(size)
    await page.waitForTimeout(200)
    // No sideways scrolling at either width, and no control running past its panel's edge.
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
    const overflowing = await page.evaluate(() =>
      [...document.querySelectorAll('section.panel')].flatMap(panel => {
        const edge = panel.getBoundingClientRect().right
        return [...panel.querySelectorAll('button, [role="switch"], [role="meter"]')]
          .filter(el => el.getBoundingClientRect().right > edge + 0.5)
          .map(el => el.textContent?.trim() || el.getAttribute('aria-label') || el.tagName)
      }),
    )
    expect(overflowing, `${label}: controls past their panel's edge`).toEqual([])
    await page.screenshot({ path: test.info().outputPath(`${name}-${label}.png`), fullPage: true })
  }
  await page.setViewportSize({ width: 1280, height: 900 })
}

test.describe.serial('cloud page', () => {
  test('managed storage: plan, usage, default, offer, each vault’s switch', async ({ page }) => {
    let status = storage()
    const sent = await scriptCloud(page, frame => {
      if (frame.command === 'meta.hello') return { data: hello() }
      if (frame.command === 'cloud.storage.status') return { data: status }
      if (frame.command === 'cloud.relay.status') return { data: relay() }
      if (frame.command === 'cloud.storage.new_vaults') {
        status = { ...status, new_vaults: frame.payload?.enabled === true }
        return { data: { new_vaults: status.new_vaults } }
      }
      if (frame.command === 'cloud.storage.offer.accept') {
        const ids = status.offered.map(v => v.vault_id)
        status = { ...status, offered: [], offer_open: false, vaults: [...status.vaults, ...status.offered.map(v => ({ ...v, switch: 'on', state: 'registered', summary: 'Waiting for its first file' }))] }
        return { data: { vaults: ids, offer_open: false } }
      }
      if (frame.command === 'cloud.storage.switch') {
        const id = frame.payload?.vault_id
        status = { ...status, vaults: status.vaults.map(v => (v.vault_id === id ? { ...v, switch: frame.payload?.enabled ? 'on' : 'off', state: frame.payload?.enabled ? 'registered' : 'detaching' } : v)) }
        return { data: status.vaults.find(v => v.vault_id === id) }
      }
      return undefined
    })
    await page.goto('/managed-storage')
    const page$ = page.getByTestId('managed-storage')
    await expect(page$).toContainText('Your plan (Standard 1 TB) is active.')
    await expect(page$).toContainText('Account usage as of 2026-11-14')
    await expect(page$).toContainText('Held on this server in managed vaults')
    await expect(page.locator('#managed-storage-offer')).toContainText('2 existing vaults can use managed storage')
    await expect(page.locator('#managed-storage-offer')).toContainText('Old projects')
    // Keys, endpoints, bucket names and providers are never shown.
    await expect(page.locator('main')).not.toContainText(/backblaze|b2|endpoint|bucket name|access key/i)
    const own = page.getByTestId('managed-storage-vault-6')
    await expect(own).toContainText('Own storage')
    await expect(own.getByRole('switch')).toHaveCount(0)
    await expect(page.getByTestId('managed-storage-vault-2').getByRole('meter')).toBeVisible()
    await shoot(page, 'managed-storage')

    await page.getByRole('switch', { name: 'Use managed storage for new vaults' }).click()
    await expect.poll(() => sent.find(f => f.command === 'cloud.storage.new_vaults')?.payload).toEqual({ enabled: false })
    await expect(page.getByRole('switch', { name: 'Use managed storage for new vaults' })).toHaveAttribute('aria-checked', 'false')

    // A local vault goes on without a confirmation.
    await page.getByTestId('managed-storage-vault-3').getByRole('switch').click()
    await expect.poll(() => sent.find(f => f.command === 'cloud.storage.switch')?.payload).toEqual({ vault_id: 3, enabled: true, confirm: null })

    // A vault with a bucket goes off only with its name typed.
    await page.getByTestId('managed-storage-vault-1').getByRole('switch').click()
    const off = page.getByRole('dialog', { name: 'Make this vault local again?' })
    await expect(off.getByRole('button', { name: 'Make local' })).toBeDisabled()
    await off.getByRole('textbox', { name: 'Type Photos to confirm' }).fill('Photos')
    await off.getByRole('button', { name: 'Make local' }).click()
    await expect.poll(() => sent.filter(f => f.command === 'cloud.storage.switch').at(-1)?.payload).toEqual({ vault_id: 1, enabled: false, confirm: 'Photos' })

    await page.locator('#managed-storage-offer').getByRole('button', { name: 'Use for all' }).click()
    await expect.poll(() => sent.find(f => f.command === 'cloud.storage.offer.accept')?.payload).toEqual({ vault_ids: null })
    await expect(page.locator('#managed-storage-offer')).toHaveCount(0)
    await expect(page.getByTestId('managed-storage-vault-4')).toContainText('Old projects')
  })

  test('managed storage: the offer can be declined, and an ended plan is explained', async ({ page }) => {
    let status = storage({ entitlement: 'ended', ended: { since: NOW - 3600, converts_at: NOW + 20 * 3600, confirmed_by: null } })
    const sent = await scriptCloud(page, frame => {
      if (frame.command === 'meta.hello') return { data: hello() }
      if (frame.command === 'cloud.storage.status') return { data: status }
      if (frame.command === 'cloud.relay.status') return { data: relay() }
      if (frame.command === 'cloud.storage.offer.decline') {
        status = { ...status, offered: [], offer_open: false }
        return { data: { vaults: [4, 5], offer_open: false } }
      }
      if (frame.command === 'cloud.storage.ended.confirm') {
        status = { ...status, ended: { ...status.ended!, confirmed_by: 'e2e-user' } }
        return { data: { confirmed: true, since: NOW, vaults: 2 } }
      }
      return undefined
    })
    await page.goto('/managed-storage')
    await expect(page.getByTestId('managed-storage')).toContainText('Your plan has ended.')
    await expect(page.getByText(/Managed vaults are kept attached without access until/)).toBeVisible()
    await shoot(page, 'managed-storage-ended')
    await page.getByRole('button', { name: 'Make them local now' }).click()
    await expect.poll(() => count(sent, 'cloud.storage.ended.confirm')).toBe(1)
    await expect(page.getByRole('button', { name: 'Make them local now' })).toHaveCount(0)

    await page.locator('#managed-storage-offer').getByRole('button', { name: 'Keep them local' }).click()
    await expect.poll(() => sent.find(f => f.command === 'cloud.storage.offer.decline')?.payload).toEqual({ vault_ids: null })
    await expect(page.locator('#managed-storage-offer')).toHaveCount(0)
  })

  test('relay: switched on after a step-up, connected, then off', async ({ page }) => {
    let status = relay()
    let stepUpDone = false
    const sent = await scriptCloud(page, frame => {
      if (frame.command === 'meta.hello') return { data: hello() }
      if (frame.command === 'cloud.storage.status') return { data: storage() }
      if (frame.command === 'cloud.relay.status') {
        // The service connects between the switch and the next read.
        if (status.state === 'connecting') status = { ...status, state: 'connected', connected_since: NOW, streams: 1, streams_accepted: 3, streams_refused: 1 }
        return { data: status }
      }
      if (frame.command === 'cloud.relay.enable') {
        if (!stepUpDone)
          return {
            error: 'confirm it is you first',
            code: 'step_up_required',
            errorData: { family: 'device.trust', target: 'cloud.relay.enable', methods: ['password'], max_age_seconds: 300 },
          }
        status = relay({ state: 'connecting', enabled: true, enabled_by: 'e2e-user', enabled_at: NOW })
        return { data: status }
      }
      if (frame.command === 'auth.stepup.begin')
        return { data: { stepup_id: 'su-1', family: 'device.trust', target: 'cloud.relay.enable', methods: ['password'] } }
      if (frame.command === 'auth.stepup.finish') {
        stepUpDone = true
        return { data: { family: 'device.trust', target: 'cloud.relay.enable', expires_at: NOW + 300, uses: 1 } }
      }
      if (frame.command === 'cloud.relay.disable') {
        status = relay()
        return { data: status }
      }
      return undefined
    })
    await page.goto('/managed-storage')
    const panel = page.getByTestId('cloud-relay')
    await expect(panel.getByTestId('cloud-relay-state')).toHaveText('Off')
    await expect(panel).toContainText('this server opens one outbound connection to the relay your account provides')
    await expect(panel).toContainText("The relay passes encrypted bytes it can't read")
    await expect(panel).toContainText('must also have switched the relay on for this server')
    await expect(page.locator('main')).not.toContainText(/vaulthalla cloud|vaulthalla\.cloud/i)
    await expect(panel).not.toContainText(/blind/i)
    await shoot(page, 'relay-off')

    const toggle = panel.getByRole('switch', { name: 'Allow web browsers through the relay' })
    await toggle.click()
    const ask = page.getByRole('dialog', { name: 'Switch the relay on?' })
    await expect(ask).toContainText('read-only')
    await ask.getByRole('button', { name: 'Switch on' }).click()

    if (OFFLINE) {
      // The step-up the console uses for device trust: password only here (scripted); online armStepUp answers it.
      const stepUp = page.getByTestId('stepup-dialog')
      await expect(stepUp).toContainText('Trust a device')
      await stepUp.getByTestId('stepup-password').fill('scripted-password')
      await stepUp.getByTestId('stepup-submit').click()
    }
    await expect(toggle).toHaveAttribute('aria-checked', 'true')
    expect(sent.find(f => f.command === 'auth.stepup.begin')?.payload).toEqual({ family: 'device.trust', target: 'cloud.relay.enable' })
    expect(sent.find(f => f.command === 'auth.stepup.finish')?.payload).toMatchObject({ stepup_id: 'su-1', method: 'password' })
    expect(count(sent, 'cloud.relay.enable')).toBe(2) // refused once for the step-up, then resent

    await expect(panel.getByTestId('cloud-relay-switched-by')).toContainText('Switched on by e2e-user on ')
    // Connecting polls every 5 s until the service reports the connection.
    await expect(panel.getByTestId('cloud-relay-state')).toHaveText('Connected', { timeout: 15_000 })
    await expect(panel.getByTestId('cloud-relay-detail')).toContainText('Connected since ')
    await expect(panel.getByTestId('cloud-relay-streams')).toHaveText('1 open · 3 accepted · 1 refused')
    await shoot(page, 'relay-connected')

    await toggle.click()
    const offAsk = page.getByRole('dialog', { name: 'Switch the relay off?' })
    await expect(offAsk).toContainText('Paired browsers stay paired')
    await offAsk.getByRole('button', { name: 'Switch off' }).click()
    await expect(toggle).toHaveAttribute('aria-checked', 'false')
    await expect(panel.getByTestId('cloud-relay-state')).toHaveText('Off')
    expect(count(sent, 'cloud.relay.disable')).toBe(1)
  })

  test('relay: waiting, stopped with its last error and Try again, listener off', async ({ page }) => {
    let status = relay({ state: 'waiting', enabled: true, enabled_by: 'ada', enabled_at: NOW - 7200, next_attempt_at: NOW + 240, last_error: 'relay_disabled: the account holder switched the relay off' })
    const sent = await scriptCloud(page, frame => {
      if (frame.command === 'meta.hello') return { data: hello() }
      if (frame.command === 'cloud.storage.status') return { data: storage() }
      if (frame.command === 'cloud.relay.status') return { data: status }
      if (frame.command === 'cloud.relay.enable') {
        status = { ...status, state: 'connecting', last_error: null }
        return { data: status }
      }
      return undefined
    })
    await page.goto('/managed-storage')
    const panel = page.getByTestId('cloud-relay')
    await expect(panel.getByTestId('cloud-relay-state')).toHaveText('Waiting')
    await expect(panel.getByTestId('cloud-relay-detail')).toContainText('This server asks again every 5 minutes. Next attempt')
    await expect(panel.getByTestId('cloud-relay-error')).toHaveText('Last error: relay_disabled: the account holder switched the relay off')
    await expect(panel.getByTestId('cloud-relay-switched-by')).toContainText('Switched on by ada on ')
    await expect(panel.getByTestId('cloud-relay-retry')).toHaveCount(0)
    await shoot(page, 'relay-waiting')

    status = relay({ state: 'stopped', enabled: true, enabled_by: 'ada', enabled_at: NOW - 7200, last_error: 'ticket refused: 401 unknown installation' })
    await page.reload()
    await expect(panel.getByTestId('cloud-relay-state')).toHaveText('Stopped')
    await expect(panel.getByTestId('cloud-relay-error')).toContainText('401 unknown installation')
    await shoot(page, 'relay-stopped')
    await panel.getByTestId('cloud-relay-retry').click()
    await expect(panel.getByTestId('cloud-relay-state')).toHaveText('Connecting')
    // Already on: the server tries again without a step-up.
    expect(count(sent, 'cloud.relay.enable')).toBe(1)
    expect(count(sent, 'auth.stepup.begin')).toBe(0)

    status = relay({ state: 'listener_off', enabled: true, enabled_by: 'ada', enabled_at: NOW - 7200 })
    await page.reload()
    await expect(panel.getByTestId('cloud-relay-state')).toHaveText('Device listener off')
    await expect(panel.getByTestId('cloud-relay-detail')).toContainText('device_server.enabled')
  })

  test('relay: a server that isn’t linked can’t switch it on', async ({ page }) => {
    await scriptCloud(page, frame => {
      if (frame.command === 'meta.hello') return { data: hello() }
      if (frame.command === 'cloud.storage.status')
        return { data: storage({ linked: false, account_key: 'unlinked', available: false, entitlement: null, plan: null, offered: [], vaults: [] }) }
      if (frame.command === 'cloud.relay.status') return { data: relay({ state: 'not_linked' }) }
      return undefined
    })
    await page.goto('/managed-storage')
    await expect(page.getByText('This server isn’t linked to an account.')).toBeVisible()
    const panel = page.getByTestId('cloud-relay')
    await expect(panel.getByTestId('cloud-relay-state')).toHaveText('Not linked')
    await expect(panel.getByRole('switch', { name: 'Allow web browsers through the relay' })).toBeDisabled()
    await shoot(page, 'relay-not-linked')
  })

  test('the admin cloud View permission sees the state, never a control', async ({ page }) => {
    test.skip(!OFFLINE, 'the live e2e account may be a super admin; offline the role is scripted')
    await scriptCloud(
      page,
      frame => {
        if (frame.command === 'meta.hello') return { data: hello() }
        if (frame.command === 'cloud.storage.status') return { data: storage() }
        if (frame.command === 'cloud.relay.status') return { data: relay({ state: 'connected', enabled: true, enabled_by: 'ada', enabled_at: NOW, connected_since: NOW }) }
        return undefined
      },
      ['admin.cloud.view'],
    )
    await page.goto('/managed-storage')
    await expect(page.getByTestId('managed-storage')).toContainText('Your plan (Standard 1 TB) is active.')
    await expect(page.getByTestId('managed-storage').getByRole('switch')).toHaveCount(0)
    await expect(page.getByRole('button', { name: 'Manage billing' })).toHaveCount(0)
    const panel = page.getByTestId('cloud-relay')
    await expect(panel.getByTestId('cloud-relay-state')).toHaveText('Connected')
    await expect(panel.getByRole('switch')).toHaveCount(0)
    await expect(panel).toContainText('Only a super admin can switch the relay.')
    // The nav item is there for a viewer of a linked server.
    await expect(page.getByRole('link', { name: 'Managed storage' }).first()).toBeVisible()
  })

  test('no relay panel without the cloud.relay capability, and none for other users', async ({ page }) => {
    const sent = await scriptCloud(page, frame => {
      if (frame.command === 'meta.hello') return { data: hello(false) }
      if (frame.command === 'cloud.storage.status') return { data: storage() }
      return undefined
    })
    await page.goto('/managed-storage')
    await expect(page.getByTestId('managed-storage')).toBeVisible()
    await expect(page.getByTestId('cloud-relay')).toHaveCount(0)
    expect(count(sent, 'cloud.relay.status')).toBe(0)
  })

  test('a user without the cloud View permission sees neither', async ({ page }) => {
    test.skip(!OFFLINE, 'the live e2e account may be a super admin; offline the role is scripted')
    const sent = await scriptCloud(page, frame => (frame.command === 'meta.hello' ? { data: hello() } : undefined), false)
    await page.goto('/managed-storage')
    await expect(page.getByText('This server isn’t linked to an account.')).toBeVisible()
    await expect(page.getByTestId('cloud-relay')).toHaveCount(0)
    expect(sent.filter(f => f.command.startsWith('cloud.')).length).toBe(0)
  })
})
