import { expect, test } from '@playwright/test'
import { armStepUp, authenticateAndSaveState, authStatePath, explicitSkipRequested } from './helpers/auth'
import {
  acknowledgeBudgetAlerts,
  addDefaultCredentialOverride,
  addCredentialOverride,
  addSelectedVault,
  assignVaultRole,
  createCredential,
  createLocalBucket,
  createdBudgetPolicyIds,
  createdVaults,
  deleteVault,
  ensureVaultAvailable,
  gotoS3Gateway,
  hideSecret,
  openTab,
  removeCredentialOverride,
  revokeVaultRole,
  saveKeyBudget,
  saveKeyVaultBudget,
  selectCredential,
  setDefaultVaultRole,
  trackBudgetPolicies,
  uniqueE2EName,
} from './helpers/s3Gateway'

test.describe.configure({ mode: 'serial' })
test.skip(explicitSkipRequested(), 'VAULTHALLA_E2E_SKIP requested')
test.use({ storageState: authStatePath })
// Step-up dialogs (#359) are answered with the e2e account's password and TOTP code.
test.beforeEach(({ page }) => armStepUp(page))

let userAccessCredential = ''
let vaultAllowCredential = ''

test.beforeAll(async ({ browser }) => {
  await authenticateAndSaveState(browser, authStatePath)
})

test.beforeEach(({ page }) => trackBudgetPolicies(page))

test.afterAll(async ({ browser }) => {
  // Each vault deletion is its own data.destroy step-up (single use), so each spends a TOTP step: up to 30 s apiece.
  test.setTimeout(60_000 + createdVaults.length * 45_000)
  const context = await browser.newContext({ storageState: authStatePath, ignoreHTTPSErrors: true })
  const page = await context.newPage()
  // Acknowledge the budget alerts this run raised (before deleting vaults: a vault's alerts go with it), so they
  // don't pile up in the bell across runs.
  await acknowledgeBudgetAlerts(page, createdBudgetPolicyIds)
  createdBudgetPolicyIds.clear()
  for (const name of createdVaults.splice(0)) await deleteVault(page, name)
  await context.close()
})

async function ensureUserCredential(page: Parameters<typeof gotoS3Gateway>[0]) {
  if (!userAccessCredential) {
    userAccessCredential = uniqueE2EName('pw-user-access')
    await createCredential(page, userAccessCredential)
    await hideSecret(page)
  }
  await selectCredential(page, userAccessCredential)
}

test('admin can navigate to S3 Gateway page', async ({ page }) => {
  await gotoS3Gateway(page)
  await expect(page.getByTestId('s3-gateway-section-service')).toBeVisible()
  await expect(page.getByTestId('s3-gateway-section-credentials')).toBeVisible()
  await openTab(page, 'Buckets')
  await expect(page.getByTestId('s3-gateway-section-bucket-bindings-routing')).toBeVisible()
  await expect(page.getByTestId('s3-gateway-bucket-routing-note')).toContainText(/do not grant access/i)
  await openTab(page, 'Budgets')
  await expect(page.getByTestId('s3-gateway-section-budget-overview')).toBeVisible()
  await openTab(page, 'Client setup')
  await expect(page.getByTestId('s3-gateway-section-client-setup')).toBeVisible()
})

test('admin can create a user_access credential and hide the secret', async ({ page }) => {
  await gotoS3Gateway(page)
  userAccessCredential = uniqueE2EName('pw-user-access')
  await createCredential(page, userAccessCredential)
  await expect(page.getByTestId('s3-gateway-secret-panel')).toContainText(/secret access key/i)
  await hideSecret(page)
  await expect(page.getByTestId('s3-gateway-credential-name').filter({ hasText: userAccessCredential })).toBeVisible()
})

test('user_access hides gateway vault role policy controls', async ({ page }) => {
  await gotoS3Gateway(page)
  await ensureUserCredential(page)
  await expect(page.getByTestId('s3-gateway-user-access-policy-note')).toBeVisible()
  await expect(page.getByTestId('s3-gateway-default-role-select')).toHaveCount(0)
  await expect(page.getByTestId('s3-gateway-selected-vaults-panel')).toHaveCount(0)
  await expect(page.getByTestId('s3-gateway-role-assign-vault-select')).toHaveCount(0)
})

test('admin manages vault_allowlist default role, selected vaults, and overrides', async ({ page }) => {
  await gotoS3Gateway(page)
  const vaultName = await ensureVaultAvailable(page)
  const extraVaultName = await ensureVaultAvailable(page)
  vaultAllowCredential = uniqueE2EName('pw-vault-allow')
  await createCredential(page, vaultAllowCredential, 'vault_allowlist', vaultName)
  await hideSecret(page)
  await selectCredential(page, vaultAllowCredential)

  await expect(page.getByTestId('s3-gateway-scope-editor-scope-select')).toHaveValue('vault_allowlist')
  await expect(page.getByTestId('s3-gateway-default-role-select')).toBeVisible()
  await expect(page.getByTestId('s3-gateway-selected-vaults-panel')).toBeVisible()
  await expect(page.getByTestId('s3-gateway-selected-vaults-panel')).toContainText(vaultName)
  await setDefaultVaultRole(page, 'reader')
  await addSelectedVault(page, extraVaultName)
  await page.getByTestId('s3-gateway-scope-save').click()
  await expect(page.getByTestId('s3-gateway-scope-save-status')).toHaveText('Saved')

  await assignVaultRole(page, vaultName, 'reader')
  await addDefaultCredentialOverride(page)
  await addCredentialOverride(page, vaultName)
  await removeCredentialOverride(page)
  await revokeVaultRole(page, vaultName)
})

test('global scope shows default role policy and hides selected vaults', async ({ page }) => {
  await gotoS3Gateway(page)
  await ensureVaultAvailable(page)
  const credentialName = uniqueE2EName('pw-global')
  await createCredential(page, credentialName, 'global')
  await hideSecret(page)
  await selectCredential(page, credentialName)

  await expect(page.getByTestId('s3-gateway-scope-editor-scope-select')).toHaveValue('global')
  await expect(page.getByTestId('s3-gateway-default-role-select')).toBeVisible()
  await expect(page.getByTestId('s3-gateway-selected-vaults-panel')).toHaveCount(0)
  await setDefaultVaultRole(page, 'reader')
  await page.getByTestId('s3-gateway-scope-save').click()
  await expect(page.getByTestId('s3-gateway-scope-save-status')).toHaveText('Saved')
})

test('credential create modal uses relational principal selector', async ({ page }) => {
  await gotoS3Gateway(page)
  await page.getByTestId('s3-gateway-open-create-credential').click()
  await expect(page.getByTestId('s3-gateway-create-credential-modal')).toBeVisible()
  const selector = page.getByTestId('s3-gateway-credential-principal-select')
  await expect(selector).toBeVisible()
  await expect(page.getByTestId('s3-gateway-create-credential-modal').locator('input[name="principal_user_id"]')).toHaveCount(0)
  await page.getByRole('button', { name: /^close$/i }).click()
})

test('admin can create a local gateway bucket', async ({ page }) => {
  await gotoS3Gateway(page)
  await createLocalBucket(page, uniqueE2EName('pw-local-bucket'))
})

test('admin can set a per-key budget', async ({ page }) => {
  await gotoS3Gateway(page)
  await ensureUserCredential(page)
  await saveKeyBudget(page, '0.25')
})

test('admin can set a per-key/vault budget', async ({ page }) => {
  await gotoS3Gateway(page)
  const vaultName = await ensureVaultAvailable(page)
  await ensureUserCredential(page)
  await saveKeyVaultBudget(page, '0.15', vaultName)
})

test('admin can create and update local budget enforcement on a credential', async ({ page }) => {
  await gotoS3Gateway(page)
  const credentialName = uniqueE2EName('pw-local-budget')
  await createCredential(page, credentialName, 'user_access', undefined, true)
  await hideSecret(page)
  await selectCredential(page, credentialName)
  await expect(page.getByTestId('s3-gateway-scope-enforce-local-budget')).toBeChecked()

  await page.getByTestId('s3-gateway-scope-enforce-local-budget').uncheck()
  await page.getByTestId('s3-gateway-scope-save').click()
  await expect(page.getByTestId('s3-gateway-scope-save-status')).toHaveText('Saved')
  await page.reload()
  await expect(page.getByTestId('s3-gateway-section-service')).toBeVisible()
  await selectCredential(page, credentialName)
  await expect(page.getByTestId('s3-gateway-scope-enforce-local-budget')).not.toBeChecked()
})

test('admin can disable a key budget policy', async ({ page }) => {
  await gotoS3Gateway(page)
  await ensureUserCredential(page)
  await saveKeyBudget(page, '0.37')
  await expect(page.getByTestId('s3-gateway-key-budget-disable')).toBeEnabled()
  await page.getByTestId('s3-gateway-key-budget-disable').click()
  // Disabling a budget is destructive, so it asks first (#150).
  await page.getByRole('button', { name: 'Disable budget' }).click()
  await expect(page.getByTestId('s3-gateway-key-budget-disable')).toBeDisabled()
})

test('budget panel scopes policy controls to the selected credential and shows ledger source column', async ({ page }) => {
  await gotoS3Gateway(page)
  const first = uniqueE2EName('pw-budget-filter-a')
  const second = uniqueE2EName('pw-budget-filter-b')
  await createCredential(page, first)
  await hideSecret(page)
  await createCredential(page, second)
  await hideSecret(page)

  await selectCredential(page, first)
  await saveKeyBudget(page, '0.41')
  await expect(page.getByTestId('s3-gateway-key-budget-disable')).toBeEnabled()

  await selectCredential(page, second)
  await expect(page.getByTestId('s3-gateway-key-budget-disable')).toBeDisabled()
  await expect(page.getByTestId('s3-gateway-section-budgets').getByText('Source')).toBeVisible()
})

test('invalid budget value reports a visible error', async ({ page }) => {
  await gotoS3Gateway(page)
  await ensureUserCredential(page)
  await saveKeyBudget(page, 'not-a-number', false)
  await expect(page.locator('body')).toContainText(/invalid|unable|error/i)
})
