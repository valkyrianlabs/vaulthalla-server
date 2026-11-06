import { expect, test, type Browser, type Page } from '@playwright/test'
import { existsSync } from 'node:fs'
import { mkdir } from 'node:fs/promises'
import { dirname } from 'node:path'
import { saveEnrolledTotp, totpCode, totpStep, withTotpCode } from './totp'

// One file per worker: spec files run in parallel workers and each signs in from beforeAll; a shared file was
// overwritten while other workers were loading it, leaving their tests on the login page.
export const authStatePath = `test-results/.auth/state-${process.env.TEST_PARALLEL_INDEX ?? '0'}.json`

export function explicitSkipRequested() {
  return process.env.VAULTHALLA_E2E_SKIP === '1' ||
    process.env.VAULTHALLA_E2E_SKIP === 'true'
}

export function e2eCredentials() {
  const user = process.env.VAULTHALLA_E2E_USER
  const password = process.env.VAULTHALLA_E2E_PASSWORD
  if (!user || !password) {
    throw new Error(
      'Missing E2E credentials. Run tools/e2e/provision_e2e_user.sh or set VAULTHALLA_E2E_USER and VAULTHALLA_E2E_PASSWORD. Set VAULTHALLA_E2E_SKIP=1 only to skip explicitly.',
    )
  }
  return { user, password }
}

// The account's authenticator app (#357: the MFA policy `admins`, the default, makes every admin sign in with a second
// factor). The e2e account's is enrolled once at provisioning (tools/e2e/enroll_totp.py, before any worker signs in;
// globalSetup passes VAULTHALLA_E2E_TOTP_FILE); an account a spec creates enrolls through the console at its first
// sign-in and keeps its factor in test-results/.auth. Either file is private run state, shared by the workers.
export function totpFileFor(user: string) {
  const provisioned = process.env.VAULTHALLA_E2E_TOTP_FILE
  if (provisioned && user === process.env.VAULTHALLA_E2E_USER) return provisioned
  return `test-results/.auth/totp-${user.replace(/[^A-Za-z0-9_-]/g, '_')}.json`
}

const leaveLogin = (page: Page) => page.waitForURL(url => !url.pathname.endsWith('/login'), { timeout: 30_000 })

// After the password: signed in (no second factor), or the second step (a code, or a first enrollment).
async function afterPassword(page: Page) {
  return Promise.race([
    leaveLogin(page).then(() => 'signed_in' as const),
    page.getByTestId('mfa-step').waitFor({ timeout: 30_000 }).then(() => 'mfa' as const),
  ])
}

// First sign-in of an account a spec created: an authenticator app, kept for its next sign-ins.
async function enrollThroughConsole(page: Page, user: string) {
  await page.getByTestId('mfa-choose-totp').click()
  const secret = await page.getByTestId('mfa-totp-secret').getAttribute('data-secret')
  if (!secret) throw new Error('no TOTP secret on the enrollment page')
  const at = totpStep()
  await page.getByTestId('mfa-totp-code').fill(totpCode(secret, at))
  await page.getByTestId('mfa-totp-confirm').click()
  await saveEnrolledTotp(totpFileFor(user), secret, at)
  await page.getByTestId('mfa-recovery-saved').check()
  await page.getByTestId('mfa-recovery-ack').click()
  await page.getByTestId('mfa-enrollment-continue').click()
  await leaveLogin(page)
}

// Step-up (#359): a sensitive command (deleting a vault, changing accounts, secrets, settings once the sign-in is older
// than auth.mfa.step_up_ttl_seconds) opens the Step-up dialog. This answers it the way a person with an authenticator
// app does: the password and a fresh code, then the console resends the command once.
export async function confirmStepUp(page: Page, account = e2eCredentials()) {
  allowForTotpQueue()
  const dialog = page.getByTestId('stepup-dialog')
  await expect(dialog.getByTestId('stepup-password')).toBeVisible()
  await expect(dialog.getByTestId('stepup-submit')).toBeEnabled()
  await dialog.getByTestId('stepup-password').fill(account.password)
  const confirm = async () => {
    await dialog.getByTestId('stepup-submit').click()
    await expect(dialog).toHaveCount(0, { timeout: 15_000 })
  }
  if (await dialog.getByTestId('stepup-code').count()) {
    await withTotpCode(totpFileFor(account.user), async code => {
      await dialog.getByTestId('stepup-code').fill(code)
      await confirm()
    })
  } else {
    await confirm()
  }
}

// Answers every Step-up dialog on this page as it appears, whatever the spec was doing (Playwright locator handler).
const armedPages = new WeakSet<Page>()
// Without an account (an offline run of scripted specs, VAULTHALLA_E2E_OFFLINE) there is nothing to confirm with.
export async function armStepUp(page: Page, account?: { user: string; password: string }) {
  const who = account ?? (process.env.VAULTHALLA_E2E_USER && process.env.VAULTHALLA_E2E_PASSWORD ? e2eCredentials() : null)
  if (!who || armedPages.has(page)) return
  armedPages.add(page)
  await page.addLocatorHandler(page.getByTestId('stepup-dialog'), () => confirmStepUp(page, who))
}

// The console's sign-in form (labelled fields; the session cookie is HttpOnly, the access token lives in memory),
// then the second factor when the account has or needs one.
export async function signIn(page: Page, user: string, password: string) {
  await page.goto('/login')
  await expect(page.getByRole('heading', { name: /sign in to vaulthalla/i })).toBeVisible()
  const submitPassword = async () => {
    await page.getByLabel('Username').fill(user)
    await page.getByLabel('Password').fill(password)
    await page.getByRole('button', { name: /^sign in$/i }).click()
  }
  const factor = totpFileFor(user)
  if (existsSync(factor)) {
    // An account with an authenticator: the password and the code in one turn of the factor's lock (helpers/totp.ts),
    // so the pending sign-in never sits waiting for other workers' steps.
    allowForTotpQueue()
    await withTotpCode(factor, async code => {
      await submitPassword()
      if ((await afterPassword(page)) === 'signed_in') return
      if (await page.getByTestId('mfa-choose-totp').isVisible()) {
        throw new Error(`${user} has no second factor, but ${factor} holds one: provision a fresh account`)
      }
      await page.getByTestId('mfa-code').fill(code)
      await page.getByTestId('mfa-submit-code').click()
      await leaveLogin(page)
    })
    return
  }
  await submitPassword()
  if ((await afterPassword(page)) === 'mfa') await enrollThroughConsole(page, user)
}

export async function loginThroughUi(page: Page) {
  const { user, password } = e2eCredentials()
  await signIn(page, user, password)
}

// Every worker signs the e2e account in from its beforeAll with the same factor, and the daemon takes one TOTP step
// per 30 s after the first three (helpers/totp.ts): a worker may wait its turn for a minute or more.
const TOTP_QUEUE_MS = 300_000
function allowForTotpQueue() {
  try {
    if (test.info().timeout > 0) test.setTimeout(test.info().timeout + TOTP_QUEUE_MS)
  } catch {
    // outside a test or hook (a script): no timeout to extend
  }
}

export async function authenticateAndSaveState(browser: Browser, storageStatePath = authStatePath) {
  allowForTotpQueue()
  await mkdir(dirname(storageStatePath), { recursive: true })
  const base = new URL(process.env.VAULTHALLA_E2E_BASE_URL ?? 'http://127.0.0.1:3000')
  const local = ['localhost', '127.0.0.1', '::1'].includes(base.hostname)
  const context = await browser.newContext({ storageState: undefined, ignoreHTTPSErrors: local })
  const page = await context.newPage()
  try {
    await loginThroughUi(page)
    await context.storageState({ path: storageStatePath })
  } finally {
    await context.close()
  }
}
