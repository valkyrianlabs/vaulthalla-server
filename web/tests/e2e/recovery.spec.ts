import { expect, test, type Page } from '@playwright/test'
import { authStatePath, authenticateAndSaveState, explicitSkipRequested } from './helpers/auth'

// File recovery UI: history sheet, restore preview, vault Recovery panel and the provider-versioning cost disclosure.
// The recovery.* / vault.recovery.* answers are scripted on the console socket (page.routeWebSocket), so the suite
// proves the console's own rules (acknowledgements, typed RESTORE, honest unknown costs) against any daemon; every
// other command reaches the real one. Run against a reverse-proxied install like console.spec.ts:
//   VAULTHALLA_E2E_BASE_URL=https://localhost VAULTHALLA_E2E_NO_WEB_SERVER=1 pnpm exec playwright test tests/e2e/recovery.spec.ts

test.skip(explicitSkipRequested(), 'VAULTHALLA_E2E_SKIP set')
test.use({ storageState: authStatePath, ignoreHTTPSErrors: true })

test.beforeAll(async ({ browser }) => {
  await authenticateAndSaveState(browser)
})

const RUN = `e2e-rec-${Date.now().toString(36)}`

type Frame = { command: string; payload: Record<string, unknown>; requestId: string }
type Answer = { data?: unknown; error?: string; code?: string }

const NOW = new Date().toISOString().replace(/\.\d+Z$/, 'Z')
const HOUR_AGO = new Date(Date.now() - 3600_000).toISOString().replace(/\.\d+Z$/, 'Z')

const point = (over: Record<string, unknown> = {}) => ({
  id: 'lv-1',
  backend: 'local_version',
  vault_id: 1,
  path: '/x',
  original_entry_id: null,
  kind: 'file',
  name: null,
  created_at: HOUR_AGO,
  valid_from: HOUR_AGO,
  valid_until: NOW,
  size_bytes: 1234,
  content_hash: null,
  encryption: { encrypted: true, key_version: 1, key_available: true, key_current: true },
  retention: { policy: 'keep_last:10', expires_at: null, note: null },
  estimated_monthly_cost: null,
  is_current: false,
  is_delete_marker: false,
  origin: null,
  reason: 'overwrite',
  upstream_state: 'none',
  storage_class: null,
  file_count: null,
  restorable: true,
  unavailable_reason: null,
  ...over,
})

const plan = (over: Record<string, unknown> = {}) => ({
  id: 42,
  vault_id: 1,
  token: 'plan-token-42',
  source_label: 'Local version lv-1',
  point_in_time: false,
  at: null,
  atomic: false,
  consistency_note: 'Reconstructed per object.',
  destination: null,
  prune: false,
  items: [
    {
      source_id: 'lv-1',
      source_path: '/x',
      destination_path: '/x',
      action: 'overwrite',
      size_bytes: 1234,
      destination_source_id: null,
      method: 'local_copy',
      notes: [],
    },
  ],
  creates: 0,
  overwrites: 1,
  skips: 0,
  conflicts: 0,
  removals: 0,
  unavailable: 0,
  estimate: {
    get_requests: 0,
    head_requests: 0,
    put_requests: 0,
    copy_requests: 0,
    list_requests: 0,
    download_bytes: 0,
    upload_bytes: 0,
    cost: null,
    unpriced_reason: null,
  },
  warnings: [],
  blockers: [],
  created_at: NOW,
  expires_at: new Date(Date.now() + 30 * 60_000).toISOString(),
  state: 'planned',
  ...over,
})

const figure = (amount: string | null, basis = 'illustrative') => ({
  expected: amount ? { amount, currency: 'USD' } : null,
  low: amount ? { amount, currency: 'USD' } : null,
  high: amount ? { amount, currency: 'USD' } : null,
  basis,
  reason: amount ? null : 'no catalog profile',
})

const report = (priced: boolean) => ({
  phase: 'pre_activation',
  vault_id: 1,
  priced,
  unpriced_reason: priced ? null : 'No price catalog profile for this region and storage class',
  provider: 'aws',
  bucket: 'e2e-bucket',
  region: 'us-east-1',
  storage_class: 'STANDARD',
  currency: priced ? 'USD' : null,
  catalog: { version: '1', source: 'price-bot', verified: true, stale: false, age_seconds: 3600, note: null },
  confidence: priced ? 'low' : 'none',
  confidence_reasons: ['No measured write activity yet'],
  observation: {
    window_days: 0,
    first_day: null,
    last_day: null,
    sufficient: false,
    put_requests: 0,
    copy_requests: 0,
    delete_requests: 0,
    get_requests: 0,
    list_requests: 0,
    first_put_objects: 0,
    overwrite_objects: 0,
    deleted_objects: 0,
    overwritten_bytes: 0,
    deleted_bytes: 0,
    uploaded_bytes: 0,
    overwritten_bytes_per_day: '0',
  },
  current: { objects: 10, bytes: 10_000_000, monthly_storage: priced ? { amount: '0.23', currency: 'USD' } : null },
  history: {
    known_noncurrent_versions: 0,
    known_noncurrent_bytes: 0,
    delete_markers: 0,
    unknown_size_versions: 0,
    unaccounted_history: false,
    inventoried_at: null,
  },
  pre_activation_monthly: figure(priced ? '1.25' : null),
  current_month_to_date: figure(null),
  current_month_projected: figure(null),
  projected_monthly: figure(priced ? '1.25' : null),
  accumulation: [1, 2, 3].map(month => ({
    month,
    noncurrent_bytes: month * 1_000_000,
    monthly_cost: figure(priced ? '0.10' : null),
  })),
  scenarios: ['30d', '90d', '365d', 'indefinite'].map(retention => ({
    retention,
    steady_noncurrent_bytes: 1_000_000,
    monthly_cost: figure(priced ? '0.50' : null),
    notes: [],
  })),
  recovery_per_gb: figure(priced ? '0.09' : null, 'scenario'),
  recovery_per_object: figure(priced ? '0.000005' : null, 'scenario'),
  unmodeled: ['Free tier', 'Taxes'],
  assumptions: [{ kind: 'illustrative', text: '5% of current bytes overwritten per month' }],
  retention: '90d',
  alert: { threshold: null, exceeded: false },
  computed_at: NOW,
})

const status = (mode = 'off') => ({
  vault_id: 1,
  mode,
  snapshot_quota_bytes: null,
  cost_alert_monthly: null,
  local_versioning: { enabled: false, keep_last: null, max_age_days: null, quota_bytes: null },
  provider: {
    supported: true,
    unsupported_reason: '',
    provider: 'aws',
    bucket: 'e2e-bucket',
    region: 'us-east-1',
    storage_class: 'STANDARD',
    bucket_state: 'managed',
    status: mode === 'provider_versioning' ? 'enabled' : 'unversioned',
    enabled_by_vaulthalla: mode === 'provider_versioning',
    enabled_at: null,
    settles_at: null,
    checked_at: NOW,
    settled: true,
    object_lock: false,
    mfa_delete: false,
    retention_mode: 'unset',
    retention_days: null,
    foreign_noncurrent_rules: [],
    effective_noncurrent_days: null,
    warnings: [],
  },
  snapshots: { count: 0, stored_bytes: 0, plaintext_bytes: 0 },
  versions: { count: 0, stored_bytes: 0, plaintext_bytes: 0 },
  backlog: { pending_versions: 0, pending_bytes: 0, oldest_pending_at: null, failing: 0, last_error: null },
  retained_key_versions: [],
  warnings: [],
})

// Scripts recovery answers on the console socket and records what the console sent. `storage.vault.get` answers are
// patched to an S3 vault so the provider-versioning controls render whatever the test vault is.
const scriptRecovery = async (page: Page, answer: (frame: Frame) => Answer | undefined) => {
  const sent: Frame[] = []
  const vaultReads = new Set<string>()
  await page.routeWebSocket(
    url => url.pathname === '/ws',
    ws => {
      const server = ws.connectToServer()
      ws.onMessage(message => {
        if (typeof message === 'string') {
          let frame: Frame | null = null
          try {
            frame = JSON.parse(message)
          } catch {
            frame = null
          }
          if (frame?.command === 'storage.vault.get') vaultReads.add(frame.requestId)
          if (frame && /^(recovery\.|vault\.recovery\.)/.test(frame.command)) {
            sent.push(frame)
            const a = answer(frame) ?? { error: 'not scripted', code: 'invalid' }
            ws.send(
              JSON.stringify(
                a.error ?
                  {
                    command: frame.command,
                    requestId: frame.requestId,
                    status: 'ERROR',
                    error: a.error,
                    data: { code: a.code },
                  }
                : { command: frame.command, requestId: frame.requestId, status: 'OK', data: a.data },
              ),
            )
            return
          }
        }
        server.send(message)
      })
      server.onMessage(message => {
        if (typeof message === 'string' && vaultReads.size) {
          try {
            const frame = JSON.parse(message)
            if (vaultReads.has(frame.requestId) && frame.data?.vault) {
              vaultReads.delete(frame.requestId)
              frame.data.vault.type = 's3'
              frame.data.vault.bucket = frame.data.vault.bucket || 'e2e-bucket'
              message = JSON.stringify(frame)
            }
          } catch {
            // not JSON: pass through
          }
        }
        ws.send(message)
      })
    },
  )
  return sent
}

const gotoFiles = async (page: Page) => {
  await page.goto('/files')
  await page.waitForURL(/\/files\/\d+/)
  await expect(page.getByRole('listbox', { name: /contents of/i })).toBeVisible()
  return Number(/\/files\/(\d+)/.exec(page.url())?.[1])
}

const withFolder = async (page: Page, name: string) => {
  await page.getByRole('button', { name: 'New folder' }).click()
  await page.getByRole('textbox', { name: 'Name', exact: true }).fill(name)
  await page.getByRole('button', { name: 'Create' }).click()
  await expect(page.getByRole('option', { name: new RegExp(name) })).toBeVisible()
}

const removeFolder = async (page: Page, name: string) => {
  await page.keyboard.press('Escape')
  await page.getByRole('option', { name: new RegExp(name) }).click({ button: 'right' })
  await page.getByRole('menuitem', { name: 'Delete' }).click()
  await page.getByRole('button', { name: 'Delete' }).last().click()
  await expect(page.getByRole('option', { name: new RegExp(name) })).toHaveCount(0)
}

const openHistory = async (page: Page, name: string) => {
  await page.getByRole('option', { name: new RegExp(name) }).click({ button: 'right' })
  await page.getByRole('menuitem', { name: 'Recovery history…' }).click()
  const sheet = page.getByTestId('recovery-history')
  await expect(sheet).toBeVisible()
  return sheet
}

test.describe.serial('recovery', () => {
  test('the history sheet opens and lists recovery points by backend', async ({ page }) => {
    const sent = await scriptRecovery(page, frame => {
      if (frame.command === 'recovery.list')
        return {
          data: {
            points: [
              point({
                id: 'snap-7',
                backend: 'local_snapshot',
                kind: 'directory',
                name: 'before cleanup',
                file_count: 3,
                retention: { policy: 'snapshot', expires_at: null, note: null },
              }),
              point({ id: 'lv-1' }),
              point({ id: 'lv-2', upstream_state: 'pending' }),
            ],
          },
        }
      if (frame.command === 'vault.recovery.status') return { data: { status: status('local_snapshots') } }
      return undefined
    })
    await gotoFiles(page)
    const folder = `${RUN} history`
    await withFolder(page, folder)
    const sheet = await openHistory(page, folder)
    await expect(sheet.getByTestId('recovery-group-local_snapshot')).toContainText('before cleanup')
    await expect(sheet.getByTestId('recovery-group-local_version').getByTestId('recovery-point')).toHaveCount(2)
    await expect(sheet.getByText('Pending upload')).toBeVisible()
    await expect(sheet.getByTestId('recovery-point-in-time')).toBeVisible()
    expect(sent.some(f => f.command === 'recovery.list' && f.payload.path === `/${folder}`)).toBe(true)
    await removeFolder(page, folder)
  })

  test('restoring over existing files needs RESTORE typed and sends the plan token', async ({ page }) => {
    const sent = await scriptRecovery(page, frame => {
      if (frame.command === 'recovery.list') return { data: { points: [point()] } }
      if (frame.command === 'vault.recovery.status') return { data: { status: status('off') } }
      if (frame.command === 'recovery.plan') return { data: { plan: plan() } }
      if (frame.command === 'recovery.restore')
        return {
          data: {
            result: {
              plan_id: 42,
              state: 'done',
              items: [{ destination_path: '/x', outcome: 'restored', error: null }],
              restored: 1,
              skipped: 0,
              conflicts: 0,
              failed: 0,
              removed: 0,
              unavailable: 0,
            },
          },
        }
      return undefined
    })
    await gotoFiles(page)
    const folder = `${RUN} restore`
    await withFolder(page, folder)
    const sheet = await openHistory(page, folder)
    await sheet.getByTestId('recovery-restore-open').first().click()
    await sheet.getByTestId('recovery-plan').click()

    const preview = page.getByTestId('restore-preview')
    await expect(preview).toBeVisible()
    await expect(preview.getByTestId('restore-consistency')).toContainText('not an atomic snapshot')
    await expect(preview.getByTestId('restore-items')).toContainText('Overwrite')
    await preview.getByTestId('restore-confirm').click()

    const confirmDialog = page.getByRole('dialog', { name: 'Overwrite current files?' })
    await expect(confirmDialog).toBeVisible()
    const go = confirmDialog.getByRole('button', { name: 'Restore' })
    await expect(go).toBeDisabled()
    await confirmDialog.getByRole('textbox', { name: 'Type RESTORE to confirm' }).fill('restore')
    await expect(go).toBeDisabled()
    await confirmDialog.getByRole('textbox', { name: 'Type RESTORE to confirm' }).fill('RESTORE')
    await go.click()

    await expect(preview.getByTestId('restore-result')).toBeVisible()
    const restore = sent.find(f => f.command === 'recovery.restore')
    expect(restore?.payload).toMatchObject({ plan_id: 42, token: 'plan-token-42' })
    expect(restore?.payload.accept_unverified).toBeUndefined()
    await preview.getByRole('button', { name: 'Done' }).click()
    await removeFolder(page, folder)
  })

  test('the cost disclosure blocks enabling provider versioning until acknowledged', async ({ page }) => {
    const sent = await scriptRecovery(page, frame => {
      if (frame.command === 'vault.recovery.status') return { data: { status: status('off') } }
      if (frame.command === 'vault.recovery.disclosure')
        return {
          data: {
            disclosure: {
              report: report(true),
              consequences: ['Versioning on AWS can only be suspended once enabled.'],
              required_acknowledgements: ['recovery_versioning_disclosure'],
              token: 'disc-token',
              expires_at: new Date(Date.now() + 600_000).toISOString(),
            },
          },
        }
      if (frame.command === 'vault.recovery.update') return { data: { status: status('provider_versioning') } }
      return undefined
    })
    const vaultId = await gotoFiles(page)
    await page.goto(`/vaults/${vaultId}/settings`)
    const panel = page.getByTestId('recovery-panel')
    await expect(panel).toBeVisible()
    await panel.getByTestId('recovery-mode-provider_versioning').check()
    await expect(panel.getByTestId('recovery-mode-apply')).toBeDisabled() // no retention chosen yet
    await panel.getByTestId('recovery-retention').selectOption('90d')
    await panel.getByTestId('recovery-mode-apply').click()

    const dialog = page.getByTestId('recovery-disclosure')
    await expect(dialog).toBeVisible()
    await expect(dialog.getByText('Provider Versioning — Estimated Monthly Cost')).toBeVisible()
    await expect(dialog.getByTestId('disclosure-headline')).toContainText('$1.25')
    const enable = dialog.getByTestId('disclosure-enable')
    await expect(enable).toBeDisabled()
    expect(sent.some(f => f.command === 'vault.recovery.update')).toBe(false)
    await dialog.getByTestId('disclosure-ack-recovery_versioning_disclosure').check()
    await expect(enable).toBeEnabled()
    await enable.click()
    await expect(dialog).toHaveCount(0)

    const update = sent.find(f => f.command === 'vault.recovery.update')
    expect(update?.payload).toMatchObject({
      mode: 'provider_versioning',
      provider_retention: '90d',
      disclosure_token: 'disc-token',
    })
    expect(update?.payload.accept_unpriced).toBeUndefined()
  })

  test('unpriced costs need their own acknowledgement and never show $0.00', async ({ page }) => {
    const sent = await scriptRecovery(page, frame => {
      if (frame.command === 'vault.recovery.status') return { data: { status: status('off') } }
      if (frame.command === 'vault.recovery.disclosure')
        return {
          data: {
            disclosure: {
              report: report(false),
              consequences: [],
              required_acknowledgements: ['recovery_versioning_disclosure', 'recovery_versioning_unpriced'],
              token: 'disc-unpriced',
              expires_at: new Date(Date.now() + 600_000).toISOString(),
            },
          },
        }
      if (frame.command === 'vault.recovery.update') return { data: { status: status('provider_versioning') } }
      return undefined
    })
    const vaultId = await gotoFiles(page)
    await page.goto(`/vaults/${vaultId}/settings`)
    const panel = page.getByTestId('recovery-panel')
    await panel.getByTestId('recovery-mode-provider_versioning').check()
    await panel.getByTestId('recovery-retention').selectOption('30d')
    await panel.getByTestId('recovery-mode-apply').click()

    const dialog = page.getByTestId('recovery-disclosure')
    await expect(dialog.getByTestId('disclosure-unpriced')).toContainText('Costs cannot be estimated')
    await expect(dialog).not.toContainText('$0.00')
    const enable = dialog.getByTestId('disclosure-enable')
    await dialog.getByTestId('disclosure-ack-recovery_versioning_disclosure').check()
    await expect(enable).toBeDisabled()
    await dialog.getByTestId('disclosure-ack-recovery_versioning_unpriced').check()
    await expect(enable).toBeEnabled()
    await enable.click()
    await expect(dialog).toHaveCount(0)

    const update = sent.find(f => f.command === 'vault.recovery.update')
    expect(update?.payload).toMatchObject({ disclosure_token: 'disc-unpriced', accept_unpriced: true })
  })
})
