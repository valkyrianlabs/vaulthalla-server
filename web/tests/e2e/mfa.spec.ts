import { expect, test, type CDPSession, type Page } from '@playwright/test'
import { execFileSync } from 'node:child_process'
import { nextTotpStep, totpCode, totpStep } from './helpers/totp'

// Pending-MFA sign-in and guided enrollment (#357) against a real daemon, with Chrome's virtual authenticator
// (CDP WebAuthn.addVirtualAuthenticator: ctap2, internal, resident key, user verification) standing in for Touch ID,
// 1Password or a security key, and TOTP codes computed here with node:crypto.
//
// The daemon needs an admin it can create accounts with and a passkey relying party for the page's origin:
//   auth.webauthn: {rp_id: localhost, origins: ["http://localhost:3000"]} in its config.yaml,
//   the console at http://localhost:3000 (WebAuthn refuses IP addresses: not 127.0.0.1) talking to the daemon at
//   ws://localhost:<port> (same host as the page, so the refresh cookie is the page's),
//   VAULTHALLA_E2E_MFA_VH: a command that runs `vh` as the super admin of that daemon (accounts are made with
//   `vh user create <name> --role admin`, which prints the generated password).
// e.g. VAULTHALLA_E2E_MFA_VH=/tmp/vhi_mfa/vh-admin VAULTHALLA_E2E_BASE_URL=http://localhost:3000 \
//      NEXT_PUBLIC_VAULTHALLA_WS_ORIGIN=ws://localhost:<port> VAULTHALLA_E2E_SKIP=1 pnpm exec playwright test tests/e2e/mfa.spec.ts

const VH = process.env.VAULTHALLA_E2E_MFA_VH

test.skip(!VH, 'needs VAULTHALLA_E2E_MFA_VH and a daemon with auth.webauthn for this origin (see the header)')
test.describe.configure({ mode: 'serial' })

let counter = 0
const newAdmin = () => {
  const name = `e2e_mfa_${Date.now().toString(36)}_${++counter}`
  const out = execFileSync(VH as string, ['user', 'create', name, '--role', 'admin'], { encoding: 'utf8' })
  const password = /^Password: (.+)$/m.exec(out)?.[1]
  if (!password) throw new Error('vh user create printed no password')
  return { name, password }
}

const authenticator = async (page: Page, options: { isUserVerified?: boolean } = {}) => {
  const cdp = await page.context().newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: options.isUserVerified ?? true,
      automaticPresenceSimulation: true,
    },
  })
  return { cdp, authenticatorId }
}

const setUserVerified = (a: { cdp: CDPSession; authenticatorId: string }, isUserVerified: boolean) =>
  a.cdp.send('WebAuthn.setUserVerified', { authenticatorId: a.authenticatorId, isUserVerified })

const password = async (page: Page, name: string, secret: string) => {
  await page.goto('/login')
  await page.getByLabel('Username').fill(name)
  await page.getByLabel('Password').fill(secret)
  await page.getByRole('button', { name: /^sign in$/i }).click()
  await expect(page.getByTestId('mfa-step')).toBeVisible()
}

// A fresh browser state on the same page (and the same virtual authenticator): sign-out without the console.
const signOut = async (page: Page) => {
  await page.context().clearCookies()
  await page.goto('/login')
  await expect(page.getByRole('heading', { name: /sign in to vaulthalla/i })).toBeVisible()
}

const saveRecoveryCodes = async (page: Page) => {
  await expect(page.getByTestId('mfa-recovery-code')).toHaveCount(10)
  const codes = await page.getByTestId('mfa-recovery-code').allTextContents()
  for (const c of codes) expect(c).toMatch(/^[0-9A-Z]{5}-[0-9A-Z]{5}$/)
  await expect(page.getByTestId('mfa-recovery-ack')).toBeDisabled()
  await page.getByTestId('mfa-recovery-saved').check()
  await page.getByTestId('mfa-recovery-ack').click()
  return codes
}

const signedIn = async (page: Page) => {
  await page.waitForURL(url => !url.pathname.startsWith('/login'), { timeout: 15_000 })
  await expect(page.getByRole('heading', { name: /sign in to vaulthalla/i })).toHaveCount(0)
}

test('first-run passkey enrollment, then password + passkey', async ({ page }) => {
  const admin = newAdmin()
  const key = await authenticator(page)

  await test.step('the password alone does not sign in: the guided first run', async () => {
    await password(page, admin.name, admin.password)
    await expect(page.getByText('Set up a second factor')).toBeVisible()
    await expect(page.getByText(/Works with 1Password, your device’s passkey manager, and security keys/).first()).toBeVisible()
    // Pending is not a session: the console's pages still send the browser to the sign-in page.
    const other = await page.context().newPage()
    await other.goto('/files')
    await expect(other).toHaveURL(/\/login/)
    await other.close()
  })

  await test.step('Create passkey (recommended), then the recovery codes sign in', async () => {
    await page.getByTestId('mfa-choose-passkey').click()
    await page.getByTestId('mfa-passkey-create').click()
    await saveRecoveryCodes(page)
    await expect(page.getByText('You’re signed in')).toBeVisible()
    await page.getByTestId('mfa-enrollment-continue').click()
    await signedIn(page)
    const { credentials } = await key.cdp.send('WebAuthn.getCredentials', { authenticatorId: key.authenticatorId })
    expect(credentials).toHaveLength(1)
    expect(credentials[0].isResidentCredential).toBe(true)
  })

  await test.step('password + passkey', async () => {
    await signOut(page)
    await password(page, admin.name, admin.password)
    await expect(page.getByText('Confirm it’s you')).toBeVisible()
    await page.getByTestId('mfa-use-passkey').click()
    await signedIn(page)
  })

  await test.step('Account → Security lists the passkey, and the session is aal 2 with a passkey', async () => {
    await page.goto('/account')
    await expect(page.getByTestId('mfa-factor')).toHaveCount(1)
    await expect(page.getByTestId('mfa-recovery-remaining')).toHaveText('10 of 10 left')
    await expect(page.getByTestId('session-row').filter({ hasText: 'This session' })).toContainText(/Password \+ (Security key or device passkey|Synced passkey)/)
  })
})

test('a passkey without user verification is refused', async ({ page }) => {
  const admin = newAdmin()
  const key = await authenticator(page)
  await password(page, admin.name, admin.password)
  await page.getByTestId('mfa-choose-passkey').click()
  await page.getByTestId('mfa-passkey-create').click()
  await saveRecoveryCodes(page)
  await page.getByTestId('mfa-enrollment-continue').click()
  await signedIn(page)

  await signOut(page)
  await setUserVerified(key, false)
  await password(page, admin.name, admin.password)
  await page.getByTestId('mfa-use-passkey').click()
  // userVerification is required: the browser or the daemon refuses, and the sign-in stays where it was.
  await expect(page.getByTestId('mfa-step').getByRole('alert')).toBeVisible()
  await expect(page).toHaveURL(/\/login/)
  await setUserVerified(key, true)
  await page.getByTestId('mfa-use-passkey').click()
  await signedIn(page)
})

test('authenticator app enrollment and sign-in, then a recovery code', async ({ page }) => {
  test.setTimeout(150_000)
  const admin = newAdmin()
  let secret = ''
  let codes: string[] = []
  let spent = 0

  await test.step('enroll an authenticator app at first sign-in', async () => {
    await password(page, admin.name, admin.password)
    await page.getByTestId('mfa-choose-totp').click()
    await expect(page.getByRole('img', { name: /QR code for your authenticator app/ })).toBeVisible()
    secret = (await page.getByTestId('mfa-totp-secret').getAttribute('data-secret')) ?? ''
    expect(secret).toMatch(/^[A-Z2-7]{32}$/)
    await page.getByTestId('mfa-totp-code').fill(totpCode(secret, (totpStep() + 3) % 1_000_000))
    await page.getByTestId('mfa-totp-confirm').click()
    await expect(page.getByText(/didn.t match/)).toBeVisible()
    spent = totpStep()
    await page.getByTestId('mfa-totp-code').fill(totpCode(secret, spent))
    await page.getByTestId('mfa-totp-confirm').click()
    codes = await saveRecoveryCodes(page)
    await page.getByTestId('mfa-enrollment-continue').click()
    await signedIn(page)
  })

  await test.step('password + authenticator code (a wrong one first)', async () => {
    await signOut(page)
    await password(page, admin.name, admin.password)
    await page.getByTestId('mfa-code').fill(totpCode(secret, spent + 5))
    await page.getByTestId('mfa-submit-code').click()
    await expect(page.getByText(/4 attempts left/)).toBeVisible()
    const step = await nextTotpStep(spent)
    await page.getByTestId('mfa-code').fill(totpCode(secret, step))
    await page.getByTestId('mfa-submit-code').click()
    await signedIn(page)
  })

  await test.step('a recovery code signs in once, into the recovery state', async () => {
    await signOut(page)
    await password(page, admin.name, admin.password)
    await page.getByTestId('mfa-toggle-recovery').click()
    await page.getByTestId('mfa-code').fill(codes[0])
    await page.getByTestId('mfa-submit-code').click()
    await page.waitForURL(/\/account/)
    await expect(page.getByText('You signed in with a recovery code')).toBeVisible()
    await expect(page.getByTestId('mfa-recovery-remaining')).toHaveText('9 of 10 left')

    await signOut(page)
    await password(page, admin.name, admin.password)
    await page.getByTestId('mfa-toggle-recovery').click()
    await page.getByTestId('mfa-code').fill(codes[0])
    await page.getByTestId('mfa-submit-code').click()
    await expect(page.getByText(/That didn.t work/)).toBeVisible()
    await expect(page).toHaveURL(/\/login/)
  })
})
