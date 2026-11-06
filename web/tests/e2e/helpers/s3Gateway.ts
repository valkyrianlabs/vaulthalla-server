import { expect, type Page } from '@playwright/test'
import { armStepUp } from './auth'

export function uniqueE2EName(prefix: string) {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`
}

export async function gotoS3Gateway(page: Page) {
  await page.goto('/s3-gateway')
  await expect(page.getByTestId('s3-gateway-section-service')).toBeVisible()
}

// The page is tabbed (Keys, Buckets, Budgets, Client setup); credential details open in a side sheet.
export async function openTab(page: Page, name: 'Keys' | 'Buckets' | 'Budgets' | 'Client setup') {
  await closeSheet(page)
  await page.getByRole('tab', { name, exact: true }).click()
}

async function closeSheet(page: Page) {
  const dialog = page.getByRole('dialog')
  if (await dialog.count()) {
    await page.keyboard.press('Escape')
    await expect(dialog).toHaveCount(0)
  }
}

export async function ensureVaultAvailable(page: Page) {
  const vaultName = uniqueE2EName('pw-vault-seed')
  await createLocalBucket(page, vaultName)
  await expect(page.getByTestId('s3-gateway-bucket-routing-note')).toBeVisible()
  return vaultName
}

export async function createCredential(
  page: Page,
  name: string,
  scope: 'user_access' | 'vault_allowlist' | 'global' = 'user_access',
  vaultName?: string,
  enforceLocalBudget = false,
) {
  await openTab(page, 'Keys')
  await page.getByTestId('s3-gateway-open-create-credential').click()
  await expect(page.getByTestId('s3-gateway-create-credential-modal')).toBeVisible()
  await page.getByTestId('s3-gateway-credential-name-input').fill(name)
  await page.getByTestId(`s3-gateway-credential-scope-${scope}`).click()
  if (scope !== 'user_access') {
    const roleSelect = page.getByTestId('s3-gateway-create-default-role-select')
    await roleSelect.selectOption({ label: 'reader' }).catch(async () => {
      await selectFirstNonEmptyOption(roleSelect)
    })
  }
  if (scope === 'vault_allowlist') {
    const vaultList = page.getByTestId('s3-gateway-create-selected-vaults')
    if (vaultName) {
      await vaultList.getByRole('checkbox', { name: vaultName }).check()
    } else {
      await vaultList.getByRole('checkbox').first().check()
    }
  }
  if (enforceLocalBudget) {
    await page.getByTestId('s3-gateway-create-enforce-local-budget').check()
  }
  await page.getByTestId('s3-gateway-submit-create-credential').click()
  await expect(page.getByTestId('s3-gateway-secret-panel')).toBeVisible()
  await expect(page.getByTestId('s3-gateway-credential-name').filter({ hasText: name })).toBeVisible()
}

async function optionValueByText(select: ReturnType<Page['getByTestId']>, text: string) {
  const option = select.locator('option').filter({ hasText: text }).first()
  await expect(option).toHaveCount(1)
  const value = await option.getAttribute('value')
  if (!value) throw new Error(`No selectable option found for ${text}`)
  return value
}

async function selectFirstNonEmptyOption(select: ReturnType<Page['getByTestId']>) {
  const options = select.locator('option')
  const count = await options.count()
  for (let index = 0; index < count; index += 1) {
    const value = await options.nth(index).getAttribute('value')
    if (value) {
      await select.selectOption(value)
      return value
    }
  }
  throw new Error('No selectable option found.')
}

export async function assignVaultRole(page: Page, vaultName: string, roleName = 'reader') {
  const vaultSelect = page.getByTestId('s3-gateway-role-assign-vault-select')
  await vaultSelect.selectOption(await optionValueByText(vaultSelect, vaultName))
  await page.getByTestId('s3-gateway-role-assign-role-select').selectOption({ label: roleName })
  await page.getByTestId('s3-gateway-role-assign-submit').click()
  await expect(page.getByTestId('s3-gateway-role-assignment-row').filter({ hasText: vaultName })).toBeVisible()
}

export async function setDefaultVaultRole(page: Page, roleName = 'reader') {
  const roleSelect = page.getByTestId('s3-gateway-default-role-select')
  await roleSelect.selectOption({ label: roleName })
  await page.getByTestId('s3-gateway-default-role-save').click()
  await expect(roleSelect).toHaveValue(/.+/)
}

export async function addSelectedVault(page: Page, vaultName: string) {
  const vaultSelect = page.getByTestId('s3-gateway-selected-vault-add-select')
  await vaultSelect.selectOption(await optionValueByText(vaultSelect, vaultName))
  await page.getByTestId('s3-gateway-selected-vault-add-submit').click()
  await expect(page.getByTestId('s3-gateway-selected-vaults-panel')).toContainText(vaultName)
}

export async function addDefaultCredentialOverride(page: Page, glob = '/shared/**') {
  await page.getByTestId('s3-gateway-default-override-permission-select').selectOption('vault.fs.files.download')
  await page.getByTestId('s3-gateway-default-override-glob-input').fill(glob)
  await page.getByTestId('s3-gateway-default-override-effect-select').selectOption('deny')
  await page.getByTestId('s3-gateway-default-override-add-submit').click()
  await expect(page.getByTestId('s3-gateway-section-credential-roles')).toContainText(glob)
}

export async function addCredentialOverride(page: Page, vaultName: string, glob = '/private/**') {
  const vaultSelect = page.getByTestId('s3-gateway-override-vault-select')
  await vaultSelect.selectOption(await optionValueByText(vaultSelect, vaultName))
  await page.getByTestId('s3-gateway-override-permission-select').selectOption('vault.fs.files.download')
  await page.getByTestId('s3-gateway-override-glob-input').fill(glob)
  await page.getByTestId('s3-gateway-override-effect-select').selectOption('deny')
  await page.getByTestId('s3-gateway-override-add-submit').click()
  await expect(page.getByTestId('s3-gateway-section-credential-roles')).toContainText(glob)
}

export async function removeCredentialOverride(page: Page, glob = '/private/**') {
  const row = page.locator('tbody tr').filter({ hasText: glob }).first()
  await expect(row).toBeVisible()
  await row.getByRole('button', { name: /remove/i }).click()
  await expect(row).toBeHidden()
}

export async function revokeVaultRole(page: Page, vaultName: string) {
  const row = page.getByTestId('s3-gateway-role-assignment-row').filter({ hasText: vaultName }).first()
  await expect(row).toBeVisible()
  await row.getByRole('button', { name: /revoke/i }).click()
  await expect(row).toBeHidden()
}

export async function hideSecret(page: Page) {
  await page.getByTestId('s3-gateway-hide-secret').click()
  await expect(page.getByTestId('s3-gateway-secret-panel')).toBeHidden()
}

export async function selectCredential(page: Page, name: string) {
  await openTab(page, 'Keys')
  const cell = page.getByTestId('s3-gateway-credential-name').filter({ hasText: name }).first()
  await expect(cell).toBeVisible()
  await cell.click()
  await expect(page.getByTestId('s3-gateway-section-credential-roles')).toBeVisible()
}

// Every vault this suite creates, so afterAll can delete them (each run used to leave five behind).
export const createdVaults: string[] = []

export async function createLocalBucket(page: Page, name: string) {
  createdVaults.push(name)
  await openTab(page, 'Buckets')
  await page.getByTestId('s3-gateway-open-local-bucket').click()
  await page.getByTestId('s3-gateway-local-bucket-name-input').fill(name)
  await page.getByTestId('s3-gateway-create-local-bucket').click()
  await expect(page.getByTestId('s3-gateway-bucket-name').filter({ hasText: name })).toBeVisible()
}

export async function saveKeyBudget(page: Page, amount: string, waitForPolicy = true) {
  await page.getByTestId('s3-gateway-key-budget-input').fill(amount)
  await page.getByTestId('s3-gateway-key-budget-save').click()
  if (waitForPolicy) {
    await expect(page.getByTestId('s3-gateway-key-budget-disable')).toBeEnabled()
  }
}

export async function saveKeyVaultBudget(page: Page, amount: string, vaultName?: string) {
  const vaultSelect = page.getByTestId('s3-gateway-key-vault-budget-vault-select')
  const optionCount = await vaultSelect.locator('option').count()
  if (optionCount < 2) throw new Error('S3 Gateway E2E requires at least one vault for key/vault budget tests.')
  if (vaultName) {
    await vaultSelect.selectOption({ label: vaultName })
  } else {
    const value = await vaultSelect.locator('option').nth(1).getAttribute('value')
    if (!value) throw new Error('First key/vault budget option has no vault id.')
    await vaultSelect.selectOption(value)
  }
  await page.getByTestId('s3-gateway-key-vault-budget-input').fill(amount)
  await page.getByTestId('s3-gateway-key-vault-budget-save').click()
  await expect(page.getByTestId('s3-gateway-key-vault-budget-disable')).toBeEnabled()
}

// Deletes a vault through the console: Vaults → the vault → Settings → Delete vault → Delete now (typed confirmation).
// Deleting a vault is a data.destroy step-up (#359): the dialog is answered with the e2e account's password and code.
export async function deleteVault(page: Page, name: string) {
  await armStepUp(page)
  await page.goto('/vaults')
  // The row link's name also carries the vault's description.
  await page.getByRole('link').filter({ hasText: name }).first().click()
  await page.waitForURL(/\/vaults\/\d+$/)
  await page.goto(`${new URL(page.url()).pathname}/settings`)
  await page.getByRole('button', { name: 'Delete vault' }).click()
  // The delete dialog (features/vaults/DeleteVaultDialog.tsx): Delete now, then the typed confirmation.
  const dialog = page.getByTestId('vault-delete-dialog')
  await dialog.getByTestId('vault-delete-now').click()
  await dialog.getByLabel(`Type “${name}” to confirm`).fill(name)
  await dialog.getByTestId('vault-delete-now-confirm').click()
  await page.waitForURL(/\/vaults$/)
}

// Price budget policies this run saved. Saving or disabling a policy raises a "S3 price budget policy <id> was
// saved|disabled." alert that nothing else acknowledges, so the suite acknowledges its own in afterAll.
export const createdBudgetPolicyIds = new Set<number>()

// Records the id of every budget policy the console saves on this page (the policy.upsert responses on /ws).
export function trackBudgetPolicies(page: Page) {
  page.on('websocket', ws => {
    if (!/\/ws$/.test(new URL(ws.url()).pathname)) return
    ws.on('framereceived', frame => {
      if (typeof frame.payload !== 'string' || !frame.payload.includes('budget.policy.upsert.response')) return
      try {
        const message = JSON.parse(frame.payload) as { status?: string; data?: { policy?: { id?: unknown } } }
        const id = message.data?.policy?.id
        if (message.status === 'OK' && typeof id === 'number') createdBudgetPolicyIds.add(id)
      } catch {
        // not a JSON command response
      }
    })
  })
}

// Acknowledges, through the cost page's alert list, the open alerts raised for the given budget policies.
export async function acknowledgeBudgetAlerts(page: Page, policyIds: Iterable<number>) {
  const ids = [...policyIds]
  if (!ids.length) return
  await page.goto('/cost')
  const section = page.locator('#budget-alerts')
  await expect(section.getByRole('table').or(section.getByText('No open budget alerts.'))).toBeVisible()
  for (const id of ids) {
    const rows = section
      .getByRole('row')
      .filter({ hasText: new RegExp(`S3 price budget policy ${id} was (saved|disabled)\\.`) })
    for (let open = await rows.count(); open > 0; open = await rows.count()) {
      await rows.first().getByTestId('budget-alert-ack').click()
      await expect(rows).toHaveCount(open - 1)
    }
  }
}
