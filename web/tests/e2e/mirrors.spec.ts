import { expect, test, type Page } from '@playwright/test'
import { armStepUp, authenticateAndSaveState, authStatePath, explicitSkipRequested } from './helpers/auth'
import { NOW, OFFLINE, count, scriptWs, type Answer, type Frame, type ScriptedRole } from './helpers/scriptedWs'

// Mirrored vaults (/linked-servers/mirrors; design/peers/mirror.md, experimental like linked servers): the area only
// exists for a super admin on a server with peers.experimental on; the list's states and reasons in words, offers
// (accept, decline), mirroring a vault (the keys step-up), a vault's page with its advice and only the actions its role
// and state allow (resync, switch with the no-access choice, detach with its preview and typed name, versions, ending
// a mirror with the copy choice) and held changes (retry, discard). mirror.*, peer.*, storage.vault.list and
// auth.stepup.* are scripted on the console socket (helpers/scriptedWs.ts), so the suite proves the console's own
// rules; a real two-server mirror is the `vhh drill` harness's job. Screenshots land in test-results/.
//
//     VAULTHALLA_E2E_OFFLINE=1 pnpm exec playwright test tests/e2e/mirrors.spec.ts                  # no daemon

test.skip(explicitSkipRequested(), 'VAULTHALLA_E2E_SKIP set')
test.use({ ignoreHTTPSErrors: true, ...(OFFLINE ? {} : { storageState: authStatePath }) })
test.beforeEach(({ page }) => armStepUp(page))
test.beforeAll(async ({ browser }) => {
  if (!OFFLINE) await authenticateAndSaveState(browser)
})

const health = (connected: boolean) => ({
  connected,
  since: connected ? NOW - 3600 : null,
  dialed_by: connected ? 'peer' : null,
  address: null,
  rtt_ms: connected ? 4 : null,
  peer_protocol: 1,
  peer_version: '1.27.0',
  protocol_compatible: true,
  last_error: connected ? null : 'connection refused',
  last_error_at: connected ? null : NOW - 60,
  next_attempt_at: connected ? null : NOW + 60,
})

const peer = (id: number, name: string, connected = true) => ({
  id,
  node_id: `node-${name}-0011`,
  name,
  spki_sha256: 'ab'.repeat(32),
  next_spki_sha256: null,
  attest_public_keys: [],
  wrap_public_key: 'AAAA',
  endpoints: [],
  sharing: 'identities',
  approved_by: 7,
  compared_by: 'person',
  peer_protocol: 1,
  product_version: '1.27.0',
  linked_at: NOW - 86_400,
  last_seen_at: NOW,
  revoked_at: null,
  revoked: false,
  health: health(connected),
})

const PEERS = [peer(3, 'vps'), peer(4, 'office', false)]
const ref = (p: { id: number; name: string; node_id: string }) => ({ id: p.id, node_id: p.node_id, name: p.name, revoked: false })

const mirrored = (over: Record<string, unknown> = {}) => ({
  vault_id: 5,
  vault_name: 'Projects',
  role: 'mirror',
  peer: ref(PEERS[0]),
  term: 2,
  last_seq: 40,
  state: 'live',
  grant: { role_name: 'Editor', files: 0, directories: 0, sync: 0, roles: 0, granted_by_node: 'node-vps', granted_at: NOW - 3600 },
  acked: { term: 2, seq: 38 },
  created_at: NOW - 86_400,
  start: null,
  detached: null,
  rekey_recommended: false,
  deleting: null,
  stop_reason: null,
  ...over,
})

const offer = (over: Record<string, unknown> = {}) => ({
  id: 12,
  offer_uid: 'o-12',
  side: 'mirror',
  peer_id: 3,
  vault_uid: 'u-12',
  vault_id: null,
  core_vault_id: 9,
  term: 1,
  name: 'Photos',
  description: 'Family photos',
  quota: 0,
  size_bytes: 3 * 1024 ** 3,
  file_count: 1200,
  history: true,
  owner: { node: 'node-vps', id: 2, name: 'alice' },
  role: { role_name: 'Viewer', files: 0, directories: 0, sync: 0, roles: 0 },
  state: 'pending',
  step: 'offered',
  told: true,
  remove_copy: false,
  copy: null,
  reason: null,
  detail: null,
  attempts: 0,
  last_error: null,
  created_at: NOW - 600,
  updated_at: NOW - 600,
  expires_at: NOW + 86_400,
  finished_at: null,
  ...over,
})

const heldChange = (over: Record<string, unknown> = {}) => ({
  id: 7,
  vault_id: 5,
  kind: 'held',
  op: 'write',
  entry_uid: 'e-1',
  path: '/plans/budget.xlsx',
  name: 'budget.xlsx',
  copy_name: null,
  person: { node: 'node-this', id: 9 },
  reason_code: 'mirror_denied',
  reason: 'the core refused it: this account may not overwrite files in /plans',
  state: 'open',
  created_at: NOW - 900,
  resolved_at: null,
  ...over,
})

const preview = (over: Record<string, unknown> = {}) => ({
  vault_id: 5,
  vault_name: 'Projects',
  role: 'mirror',
  state: 'diverged',
  stop_reason: 'mirror_digest_mismatch',
  peer: ref(PEERS[0]),
  link_up: true,
  first_copy: { finished: true, entries_copied: 400, entries_total: 400 },
  applied: { term: 2, seq: 40 },
  confirmed: { term: 2, seq: 38 },
  digest_matched: false,
  pending_changes: 2,
  held_changes: 1,
  missing_count: 2,
  missing: [
    { file_id: 1, uid: 'f1', path: '/video/raw-01.mov', size_bytes: 2 * 1024 ** 3, state: 'missing', last_error: null },
    { file_id: 2, uid: 'f2', path: '/video/raw-02.mov', size_bytes: 1024 ** 3, state: 'failed', last_error: 'timeout' },
  ],
  owner_id: 7,
  ...over,
})

const stepUpFor = (family: string, target: string): Answer => ({
  error: 'confirm it is you first',
  code: 'step_up_required',
  errorData: { family, target, methods: ['password'], max_age_seconds: 300 },
})

const owns = (command: string) =>
  command.startsWith('peer.') || command.startsWith('mirror.') || command.startsWith('auth.stepup.') || command === 'storage.vault.list' || command === 'auth.users.list'

const scriptMirrors = (page: Page, answer: (frame: Frame) => Answer | undefined, { role = true as ScriptedRole, enabled = true } = {}) =>
  scriptWs(
    page,
    owns,
    frame => {
      const own = answer(frame)
      if (own) return own
      if (frame.command === 'peer.status') return { data: { enabled } }
      if (frame.command === 'peer.list') return { data: { peers: PEERS } }
      if (frame.command === 'mirror.pending') return { data: { offers: [] } }
      if (frame.command === 'mirror.held.list') return { data: { held: [] } }
      if (frame.command === 'auth.users.list') return { data: { users: [] } }
      if (frame.command === 'storage.vault.list') return { data: { vaults: [{ id: 1, name: 'Home' }, { id: 5, name: 'Projects' }, { id: 6, name: 'Archive' }] } }
      if (frame.command === 'auth.stepup.begin') {
        const target = String(frame.payload?.target ?? '')
        return { data: { stepup_id: 'su-1', family: frame.payload?.family ?? 'keys', target, methods: ['password'] } }
      }
      if (frame.command === 'auth.stepup.finish') return { data: { family: 'keys', target: null, expires_at: NOW + 300, uses: 1 } }
      return undefined
    },
    { superAdmin: role },
  )

const confirmStepUp = async (page: Page, action: string) => {
  const stepUp = page.getByTestId('stepup-dialog')
  await expect(stepUp).toContainText(action)
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
    await page.waitForTimeout(250)
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), `${label}: no sideways scrolling`).toBe(true)
    await page.screenshot({ path: test.info().outputPath(`${name}-${label}.png`), fullPage: true })
  }
  await page.setViewportSize({ width: 1280, height: 900 })
}

const mirrorCommands = (sent: Frame[]) => sent.filter(f => f.command.startsWith('mirror.')).map(f => f.command)

test.describe.serial('mirrored vaults', () => {
  test('switched off: the URL says only that linked servers aren’t available, and nothing is asked', async ({ page }) => {
    const sent = await scriptMirrors(page, () => undefined, { enabled: false })
    await page.goto('/linked-servers/mirrors')
    await expect(page.getByTestId('peers-unavailable')).toHaveText(/Linked servers aren’t available on this server/)
    await expect(page.locator('main')).not.toContainText(/experimental|config\.yaml/i)
    expect(mirrorCommands(sent)).toEqual([])
  })

  test('not a super admin: denied, and nothing is asked', async ({ page }) => {
    const sent = await scriptMirrors(page, () => undefined, { role: false })
    await page.goto('/linked-servers/mirrors/5')
    await expect(page.getByText('You don\'t have access to this')).toBeVisible()
    expect(mirrorCommands(sent)).toEqual([])
  })

  test('a mirror command answering that linked servers are off shows the same state', async ({ page }) => {
    await scriptMirrors(page, frame =>
      frame.command === 'mirror.list' ? { error: 'linked servers are experimental and off on this server', code: 'peers_experimental' } : undefined,
    )
    await page.goto('/linked-servers/mirrors')
    await expect(page.getByTestId('peers-unavailable')).toBeVisible()
  })

  test('list: tabs, each state with its reason in words, held counts, offers accepted and declined', async ({ page }) => {
    let offers = [offer(), offer({ id: 13, name: 'Scans', peer_id: 4, history: false, role: null, description: '' })]
    const vaults = [
      mirrored(),
      mirrored({ vault_id: 6, vault_name: 'Archive', role: 'core', peer: ref(PEERS[1]), acked: { term: 2, seq: 30 } }),
      mirrored({ vault_id: 8, vault_name: 'Design', state: 'diverged', stop_reason: 'mirror_digest_mismatch' }),
      mirrored({ vault_id: 10, vault_name: 'Legal', state: 'paused', stop_reason: 'mirror_core_deleting', deleting: { deleting: true, purge_after: NOW + 7 * 86_400, copy: 'leave' } }),
      mirrored({ vault_id: 11, vault_name: 'Old', role: 'orphaned', state: 'stopped', stop_reason: 'mirror_orphaned' }),
      mirrored({ vault_id: 0, vault_name: '', role: 'starting', state: null, term: null, last_seq: null, acked: null, start: offer({ id: 20, name: 'Music', side: 'core', state: 'offered', peer_id: 3 }) }),
    ]
    const sent = await scriptMirrors(page, frame => {
      if (frame.command === 'mirror.list') return { data: { vaults } }
      if (frame.command === 'mirror.pending') return { data: { offers } }
      if (frame.command === 'mirror.held.list') return { data: { held: [heldChange(), heldChange({ id: 8 }), heldChange({ id: 9, vault_id: 8, state: 'discarded' })] } }
      if (frame.command === 'mirror.accept') {
        const o = offers.find(x => x.id === frame.payload?.offer)!
        offers = offers.filter(x => x !== o)
        return { data: { offer: { ...o, state: 'accepted' } } }
      }
      if (frame.command === 'mirror.decline') {
        const o = offers.find(x => x.id === frame.payload?.offer)!
        offers = offers.filter(x => x !== o)
        return { data: { offer: { ...o, state: 'declined' } } }
      }
      return undefined
    })
    await page.goto('/linked-servers')
    await page.getByRole('link', { name: 'Mirrored vaults' }).click()
    await expect(page).toHaveURL(/\/linked-servers\/mirrors$/)
    await expect(page.getByRole('link', { name: 'Mirrored vaults' })).toHaveAttribute('aria-current', 'page')

    const row = (name: string) => page.getByRole('row', { name: new RegExp(name) })
    await expect(row('Projects').getByTestId('mirror-status-label')).toHaveText('Live')
    await expect(row('Projects').getByTestId('mirror-held-count')).toHaveText('2 held')
    await expect(row('Archive').getByTestId('mirror-role')).toHaveText('Core')
    await expect(row('Archive').getByTestId('mirror-status-label')).toHaveText('Live, link down')
    await expect(row('Design').getByTestId('mirror-status-sentence')).toContainText('stopped matching the core’s')
    await expect(row('Design').getByTestId('mirror-held-count')).toHaveText('None')
    await expect(row('Legal').getByTestId('mirror-status-label')).toHaveText('Core is deleting it')
    await expect(row('Legal').getByTestId('mirror-status-sentence')).toContainText('then it is kept as an orphaned copy')
    await expect(row('Old').getByTestId('mirror-role')).toHaveText('Orphaned copy')
    await expect(row('Music').getByTestId('mirror-status-label')).toHaveText('Waiting for an answer')
    await expect(page.getByTestId('mirror-offer')).toHaveCount(2)
    await expect(page.getByTestId('mirror-offers')).toContainText('from vps')
    await expect(page.getByTestId('mirror-offers')).toContainText('Access here: role “Viewer”')
    await shoot(page, 'mirrors-list')

    await page.getByTestId('mirror-offer-accept-12').click()
    const ask = page.getByRole('dialog', { name: 'Accept “Photos”?' })
    await expect(ask).toContainText('receives its keys')
    await ask.getByRole('button', { name: 'Accept' }).click()
    await expect(page.getByTestId('mirror-offer')).toHaveCount(1)
    expect(sent.find(f => f.command === 'mirror.accept')?.payload).toEqual({ offer: 12 })

    await page.getByTestId('mirror-offer-decline-13').click()
    await page.getByRole('dialog', { name: 'Decline “Scans”?' }).getByRole('button', { name: 'Decline' }).click()
    await expect(page.getByTestId('mirror-offers')).toHaveCount(0)
    expect(sent.find(f => f.command === 'mirror.decline')?.payload).toEqual({ offer: 13 })

    // A start with no vault here yet is cancelled from the list, by its offer.
    await page.getByTestId('mirror-cancel-start-20').click()
    await page.getByRole('dialog', { name: 'Cancel the start of “Music”?' }).getByRole('button', { name: 'Cancel the start' }).click()
    await expect.poll(() => sent.find(f => f.command === 'mirror.cancel')?.payload).toEqual({ offer: 20 })
  })

  test('mirror a vault: the vault and the server are sent after the keys step-up', async ({ page }) => {
    let stepped = false
    const sent = await scriptMirrors(page, frame => {
      if (frame.command === 'mirror.list') return { data: { vaults: [mirrored()] } }
      if (frame.command === 'mirror.add') {
        if (!stepped) return stepUpFor('keys', 'mirror.add:6')
        return { data: { offer: offer({ id: 21, side: 'core', name: 'Archive', peer_id: 3, state: 'offered' }) } }
      }
      if (frame.command === 'auth.stepup.finish') stepped = true
      return undefined
    })
    await page.goto('/linked-servers/mirrors')
    await page.getByTestId('mirror-add-open').click()
    const dialog = page.getByTestId('mirror-add-dialog')
    // Projects (vault 5) is mirrored already: not offered again.
    await expect(dialog.getByTestId('mirror-add-vault').locator('option')).toHaveText(['Choose…', 'Home', 'Archive'])
    await expect(dialog.getByTestId('mirror-add-submit')).toBeDisabled()
    await dialog.getByTestId('mirror-add-vault').selectOption('6')
    await dialog.getByTestId('mirror-add-peer').selectOption('3')
    await shoot(page, 'mirrors-add')
    await dialog.getByTestId('mirror-add-submit').click()
    await confirmStepUp(page, 'Give a linked server this vault’s keys')
    await expect(dialog).toHaveCount(0)
    expect(sent.filter(f => f.command === 'mirror.add').map(f => f.payload)).toEqual([
      { vault_id: 6, peer: '3' },
      { vault_id: 6, peer: '3' },
    ])
  })

  test('link settings: each is sent and what the server set is shown', async ({ page }) => {
    const sent = await scriptMirrors(page, frame => {
      if (frame.command === 'mirror.list') return { data: { vaults: [] } }
      if (frame.command === 'mirror.accept_all.set' || frame.command === 'mirror.keep_removed.set')
        return { data: { peer: { id: 3, node_id: 'node-vps-0011', name: 'vps' }, enabled: frame.payload?.enabled, set_by: 7, set_at: NOW } }
      return undefined
    })
    await page.goto('/linked-servers/mirrors')
    await expect(page.getByText('No mirrored vaults')).toBeVisible()
    await page.getByTestId('mirror-settings-open-3').click()
    const dialog = page.getByTestId('mirror-settings-dialog')
    await dialog.getByTestId('mirror-accept-all').getByRole('radio', { name: 'On' }).click()
    await expect(dialog.getByTestId('mirror-accept-all-now')).toContainText('On · set')
    await dialog.getByTestId('mirror-keep-removed').getByRole('radio', { name: 'Off' }).click()
    await expect(dialog.getByTestId('mirror-keep-removed-now')).toContainText('Off · set')
    expect(sent.find(f => f.command === 'mirror.accept_all.set')?.payload).toEqual({ peer: '3', enabled: true })
    expect(sent.find(f => f.command === 'mirror.keep_removed.set')?.payload).toEqual({ peer: '3', enabled: false })
  })

  test('a diverged mirror: the reason, the advice, resync, held changes, versions and detach with its preview', async ({ page }) => {
    let row = mirrored({ state: 'diverged', stop_reason: 'mirror_digest_mismatch' })
    let held = [heldChange(), heldChange({ id: 8, kind: 'conflict', op: 'write', copy_name: 'notes (conflict).md', path: '/notes.md' })]
    const sent = await scriptMirrors(page, frame => {
      if (frame.command === 'mirror.get') return { data: { vault: row } }
      if (frame.command === 'mirror.detach.preview') return { data: { preview: preview() } }
      if (frame.command === 'mirror.held.list') return { data: { held } }
      if (frame.command === 'mirror.held.discard') {
        held = held.filter(h => h.id !== frame.payload?.id)
        return { data: { held: { ...heldChange(), state: 'discarded' } } }
      }
      if (frame.command === 'mirror.resync') {
        row = mirrored({ state: 'live' })
        return { data: { vault_id: 5, state: 'live', copy_finished: false, term: 3, held: 1, entries: 400 } }
      }
      if (frame.command === 'mirror.versions.set')
        return { data: { versions: { enabled: true, keep_last: frame.payload?.keep_last ?? 10, max_age_days: 30, quota_bytes: 0, set_by: 7, set_at: NOW } } }
      if (frame.command === 'mirror.detach') return { data: { detached: { vault_id: 5, owner_id: 7, missing: 2, pending_kept: 2, pending_held: 0, core_told: 'when_reachable' } } }
      return undefined
    })
    await page.goto('/linked-servers/mirrors/5')
    await expect(page.getByTestId('mirror-detail-name')).toHaveText('Projects')
    await expect(page.getByTestId('mirror-status-label')).toHaveText('Diverged')
    await expect(page.getByTestId('mirror-status-sentence')).toContainText('The copy here stopped matching the core’s, so it stopped following it and is read-only.')
    await expect(page.getByTestId('mirror-advice')).toContainText('Resync it to start over from the core’s files')
    await expect(page.getByTestId('mirror-advice')).toContainText('2 changes made here were refused by the core')
    await expect(page.getByTestId('mirror-pending')).toHaveText('2')
    // Only what a diverged mirror allows: no switch (not live), no cancel (a completed mirror leaves by detaching).
    await expect(page.getByTestId('mirror-actions').getByRole('button')).toHaveText(['Resync…', 'Detach…', 'Versions…'])
    await expect(page.getByTestId('mirror-held-reason').first()).toContainText('may not overwrite files in /plans')
    await expect(page.getByTestId('mirror-held')).toContainText('Conflict copy kept as “notes (conflict).md”')
    // Retry needs the vault live here.
    await expect(page.getByTestId('mirror-held-retry-7')).toBeDisabled()
    await shoot(page, 'mirrors-detail-diverged')

    await page.getByTestId('mirror-held-discard-8').click()
    const discard = page.getByRole('dialog', { name: 'Discard this held change?' })
    await expect(discard).toContainText('The conflict copy itself stays in the vault')
    await discard.getByRole('button', { name: 'Discard' }).click()
    await expect(page.getByTestId('mirror-held-path')).toHaveCount(1)
    expect(sent.find(f => f.command === 'mirror.held.discard')?.payload).toEqual({ id: 8 })

    await page.getByTestId('mirror-action-versions').click()
    const versions = page.getByTestId('mirror-versions-dialog')
    await versions.getByRole('switch').click()
    await versions.getByLabel('Versions per file').fill('3')
    await versions.getByTestId('mirror-versions-save').click()
    await expect(versions.getByTestId('mirror-versions-now')).toHaveText('On: 3 versions per file, 30 days, no limit.')
    expect(sent.find(f => f.command === 'mirror.versions.set')?.payload).toEqual({ vault_id: 5, enabled: true, keep_last: 3, max_age_days: null, quota_bytes: null })
    await versions.getByRole('button', { name: 'Close' }).last().click()

    await page.getByTestId('mirror-action-detach').click()
    const detach = page.getByTestId('mirror-detach-dialog')
    await expect(detach.getByTestId('mirror-detach-missing')).toContainText('2 files’ contents aren’t here')
    await expect(detach.getByTestId('mirror-detach-missing')).toContainText('/video/raw-01.mov')
    await expect(detach.getByTestId('mirror-detach-pending')).toContainText('2 changes made here and not yet confirmed become ordinary changes')
    await expect(detach.getByTestId('mirror-detach-confirm')).toBeDisabled()
    await shoot(page, 'mirrors-detach')
    await detach.getByTestId('mirror-detach-typed').fill('Projects')
    await detach.getByTestId('mirror-detach-confirm').click()
    await expect(detach).toHaveCount(0)
    expect(sent.find(f => f.command === 'mirror.detach')?.payload).toEqual({ vault_id: 5, owner: null, confirm_name: 'Projects' })

    await page.getByTestId('mirror-action-resync').click()
    const resync = page.getByRole('dialog', { name: 'Resync “Projects”?' })
    await expect(resync).toContainText('kept as held changes')
    await resync.getByRole('button', { name: 'Resync' }).click()
    await expect(page.getByTestId('mirror-status-label')).toHaveText('Live')
    expect(sent.find(f => f.command === 'mirror.resync')?.payload).toEqual({ vault_id: 5 })
  })

  test('a core: switch refused for no access, then sent with accept_no_access; ending asks about the copy', async ({ page }) => {
    let stepped = false
    const row = mirrored({ vault_id: 6, vault_name: 'Archive', role: 'core', grant: null })
    const sent = await scriptMirrors(page, frame => {
      if (frame.command === 'mirror.get') return { data: { vault: row } }
      if (frame.command === 'mirror.switch') {
        if (!frame.payload?.accept_no_access)
          return { error: 'vps gives this server no role on the vault: its people could not read it there', code: 'mirror_switch_no_role' }
        return {
          data: {
            vault_id: 6, switch_id: 's-1', outcome: 'switched', role: null, role_term: 3, side: 'core', phase: 'switched', term: 3, seq: 41,
            digest: null, entries: 400, told: true, asked_on: 'core', asked_by: null, reason: null, detail: {}, deadline: NOW + 60,
            created_at: NOW, ended_at: NOW, peer_role: null, peer_access: 'none',
          },
        }
      }
      if (frame.command === 'mirror.cancel') {
        if (!stepped) return stepUpFor('data.destroy', 'mirror.cancel:6')
        return { data: { side: 'core', vault_id: 6, removed: false, remove_copy: true, offer: null } }
      }
      if (frame.command === 'auth.stepup.finish') stepped = true
      return undefined
    })
    await page.goto('/linked-servers/mirrors/6')
    await expect(page.getByTestId('mirror-actions').getByRole('button')).toHaveText(['Switch the core…', 'End the mirror…'])
    expect(count(sent, 'mirror.detach.preview')).toBe(0)

    await page.getByTestId('mirror-action-switch').click()
    const sw = page.getByTestId('mirror-switch-dialog')
    await expect(sw).toContainText('vps becomes the vault’s core and this server keeps a copy')
    await sw.getByTestId('mirror-switch-confirm').click()
    await expect(sw.getByTestId('mirror-switch-no-role')).toContainText('its people could not read it there')
    await expect(sw.getByTestId('mirror-switch-confirm')).toBeDisabled()
    await shoot(page, 'mirrors-switch-no-role')
    await sw.getByTestId('mirror-switch-accept-no-access').check()
    await sw.getByTestId('mirror-switch-confirm').click()
    await expect(sw.getByTestId('mirror-switch-access')).toHaveText('This server keeps no access until a role is set for it.')
    expect(sent.filter(f => f.command === 'mirror.switch').map(f => f.payload)).toEqual([{ vault_id: 6 }, { vault_id: 6, accept_no_access: true }])
    await sw.getByRole('button', { name: 'Done' }).click()

    await page.getByTestId('mirror-action-cancel').click()
    const end = page.getByTestId('mirror-end-dialog')
    await expect(end.getByTestId('mirror-end-copy-leave')).toBeChecked()
    await end.getByTestId('mirror-end-copy-remove').check()
    await end.getByTestId('mirror-end-confirm').click()
    await confirmStepUp(page, 'End a vault’s mirror')
    await expect(end).toHaveCount(0)
    expect(sent.filter(f => f.command === 'mirror.cancel').at(-1)?.payload).toEqual({ vault_id: 6, remove_copy: true })
  })

  test('the first copy shows its progress, and a refusal its words and code', async ({ page }) => {
    await scriptMirrors(page, frame => {
      if (frame.command === 'mirror.get') return { data: { vault: mirrored({ state: 'live' }) } }
      if (frame.command === 'mirror.detach.preview')
        return { data: { preview: preview({ state: 'live', stop_reason: null, digest_matched: null, missing_count: 0, missing: [], first_copy: { finished: false, entries_copied: 120, entries_total: 400 } }) } }
      if (frame.command === 'mirror.switch') return { error: 'the first copy is not finished', code: 'mirror_first_copy' }
      return undefined
    })
    await page.goto('/linked-servers/mirrors/5')
    await expect(page.getByTestId('mirror-status-label')).toHaveText('First copy')
    await expect(page.getByTestId('mirror-first-copy')).toContainText('120 of 400 entries')
    await expect(page.getByRole('meter')).toHaveAttribute('aria-valuenow', '30')
    await page.getByTestId('mirror-action-switch').click()
    await page.getByTestId('mirror-switch-confirm').click()
    await expect(page.getByTestId('peer-error')).toContainText('the first copy is not finished')
    await expect(page.getByTestId('peer-error-code')).toHaveText('(mirror_first_copy)')
  })
})
