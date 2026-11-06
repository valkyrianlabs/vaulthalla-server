import { expect, type Browser, type Page } from '@playwright/test'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname } from 'node:path'
import { nextTotpStep, totpCode, totpStep } from './totp'

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

// The authenticator-app secret the e2e account enrolled (#357), per account: the MFA policy (`admins`, the default)
// makes an admin enroll a factor at its first sign-in and asks for it at every later one.
const totpSecretPath = (user: string) => `test-results/.auth/totp-${user.replace(/[^A-Za-z0-9_-]/g, '_')}.json`

async function finishSecondFactor(page: Page, user: string) {
  const step = page.getByTestId('mfa-step')
  const outcome = await Promise.race([
    page.waitForURL(url => !url.pathname.endsWith('/login'), { timeout: 15_000 }).then(() => 'signed_in' as const),
    step.waitFor({ timeout: 15_000 }).then(() => 'mfa' as const),
  ])
  if (outcome === 'signed_in') return
  if (await page.getByTestId('mfa-choose-totp').isVisible()) {
    // First run: an authenticator app, its secret kept for the next sign-ins of this account.
    await page.getByTestId('mfa-choose-totp').click()
    const secret = await page.getByTestId('mfa-totp-secret').getAttribute('data-secret')
    if (!secret) throw new Error('no TOTP secret on the enrollment page')
    const at = totpStep()
    await page.getByTestId('mfa-totp-code').fill(totpCode(secret, at))
    await page.getByTestId('mfa-totp-confirm').click()
    await mkdir(dirname(totpSecretPath(user)), { recursive: true })
    await writeFile(totpSecretPath(user), JSON.stringify({ secret, step: at }), { mode: 0o600 })
    await page.getByTestId('mfa-recovery-saved').check()
    await page.getByTestId('mfa-recovery-ack').click()
    await page.getByTestId('mfa-enrollment-continue').click()
  } else {
    const saved = JSON.parse(await readFile(totpSecretPath(user), 'utf8')) as { secret: string; step: number }
    // A step is accepted once: never reuse the one the last sign-in spent (other workers share the file).
    const step = saved.step >= totpStep() ? await nextTotpStep(saved.step) : totpStep()
    await writeFile(totpSecretPath(user), JSON.stringify({ secret: saved.secret, step }), { mode: 0o600 })
    await page.getByTestId('mfa-code').fill(totpCode(saved.secret, step))
    await page.getByTestId('mfa-submit-code').click()
  }
  await page.waitForURL(url => !url.pathname.endsWith('/login'), { timeout: 15_000 })
}

// The console's sign-in form (labelled fields; the session cookie is HttpOnly, the access token lives in memory),
// then the second factor when the account has or needs one.
export async function signIn(page: Page, user: string, password: string) {
  await page.goto('/login')
  await expect(page.getByRole('heading', { name: /sign in to vaulthalla/i })).toBeVisible()
  await page.getByLabel('Username').fill(user)
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: /^sign in$/i }).click()
  await finishSecondFactor(page, user)
}

export async function loginThroughUi(page: Page) {
  const { user, password } = e2eCredentials()
  await signIn(page, user, password)
}

export async function authenticateAndSaveState(browser: Browser, storageStatePath = authStatePath) {
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
