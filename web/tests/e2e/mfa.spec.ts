import { expect, test, type CDPSession, type Page } from '@playwright/test'
import { execFileSync } from 'node:child_process'
import { nextTotpStep, totpCode, totpStep } from './helpers/totp'

// Pending-MFA sign-in and guided enrollment (#357) and discoverable passkey sign-in (#358) against a real daemon, with Chrome's virtual authenticator
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
// The step-up spec waits out the sign-in's own freshness (an aal 2 sign-in stands in for a step-up within
// auth.mfa.step_up_ttl_seconds): run that daemon with auth.mfa.step_up_ttl_seconds: 60 and say so here.
const STEP_UP_TTL_SECONDS = Number(process.env.VAULTHALLA_E2E_STEP_UP_TTL ?? '60')

test.skip(!VH, 'needs VAULTHALLA_E2E_MFA_VH and a daemon with auth.webauthn for this origin (see the header)')
test.describe.configure({ mode: 'serial' })

let counter = 0
const newAccount = (role: string) => {
  const name = `e2e_su_${Date.now().toString(36)}_${++counter}`
  execFileSync(VH as string, ['user', 'create', name, '--role', role], { encoding: 'utf8' })
  return name
}

const newAdmin = (role = 'admin') => {
  const name = `e2e_mfa_${Date.now().toString(36)}_${++counter}`
  const out = execFileSync(VH as string, ['user', 'create', name, '--role', role], { encoding: 'utf8' })
  const password = /^Password: (.+)$/m.exec(out)?.[1]
  if (!password) throw new Error('vh user create printed no password')
  return { name, password }
}

const authenticator = async (page: Page, options: { isUserVerified?: boolean; synced?: boolean } = {}) => {
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
      // A synced passkey (1Password, iCloud Keychain, Google Password Manager): backup eligible and backed up.
      ...(options.synced ? { defaultBackupEligibility: true, defaultBackupState: true } : {}),
    },
  })
  return { cdp, authenticatorId }
}

// Chrome's virtual authenticator answers a conditional (autofill) request by itself, with the first resident credential
// for the page: /login would sign in with the passkey before a test could type a password or click the button. Tests
// of those flows turn the autofill off; 'the username field's autofill signs in' keeps it.
const withoutAutofill = (page: Page) =>
  page.addInitScript(() => {
    if (typeof window.PublicKeyCredential === 'function')
      Object.defineProperty(window.PublicKeyCredential, 'isConditionalMediationAvailable', { value: async () => false })
  })

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
  await withoutAutofill(page)
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
  await withoutAutofill(page)
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
  // No authenticator here, so the autofill request stays open: every password sign-in below has to end it first.
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

// ── discoverable passkey sign-in (#358) ──────────────────────────────────────────────────────────────────────────

// First run with a passkey, the account's only credential on this authenticator.
const enrollPasskey = async (page: Page, admin: { name: string; password: string }) => {
  await password(page, admin.name, admin.password)
  await page.getByTestId('mfa-choose-passkey').click()
  await page.getByTestId('mfa-passkey-create').click()
  await saveRecoveryCodes(page)
  await page.getByTestId('mfa-enrollment-continue').click()
  await signedIn(page)
}

const thisSession = (page: Page) => page.getByTestId('session-row').filter({ hasText: 'This session' })

test('sign in with a passkey alone: no username, no password', async ({ page }) => {
  await withoutAutofill(page)
  const admin = newAdmin()
  const key = await authenticator(page)
  await enrollPasskey(page, admin)

  await test.step('the sign-in page offers the passkey, and it signs in at aal 2', async () => {
    await signOut(page)
    await expect(page.getByLabel('Username')).toHaveValue('')
    // The username field asks the browser to list passkeys in its autofill (conditional mediation).
    await expect(page.getByLabel('Username')).toHaveAttribute('autocomplete', 'username webauthn')
    await page.getByTestId('passkey-sign-in').click()
    await signedIn(page)
    await page.goto('/account')
    // The passkey alone: no password in the session's methods.
    await expect(thisSession(page)).toContainText('Security key or device passkey')
    await expect(thisSession(page)).not.toContainText('Password')
  })

  await test.step('a passkey without user verification is refused, and the page stays on the sign-in form', async () => {
    await signOut(page)
    await setUserVerified(key, false)
    await page.getByTestId('passkey-sign-in').click()
    // The browser refuses (UV is required): the form says so, and the button is ready again.
    await expect(page.locator('form').getByRole('alert')).toBeVisible()
    await expect(page.getByTestId('passkey-sign-in')).toBeEnabled()
    await expect(page).toHaveURL(/\/login/)
    await setUserVerified(key, true)
    await page.getByTestId('passkey-sign-in').click()
    await signedIn(page)
  })

})

test('the username field’s autofill (conditional mediation) signs in with the passkey', async ({ page }) => {
  const admin = newAdmin()
  await authenticator(page)
  // Enrollment needs the password page to stay put: no autofill while the passkey is created.
  await page.addInitScript(() => {
    if (sessionStorage.getItem('e2e-autofill') !== 'on' && typeof window.PublicKeyCredential === 'function')
      Object.defineProperty(window.PublicKeyCredential, 'isConditionalMediationAvailable', { value: async () => false })
  })
  await enrollPasskey(page, admin)
  await page.evaluate(() => sessionStorage.setItem('e2e-autofill', 'on'))
  await page.context().clearCookies()
  // The browser's autofill request answers with the passkey (the virtual authenticator picks it): no click, no typing.
  await page.goto('/login')
  await signedIn(page)
  await page.goto('/account')
  await expect(thisSession(page)).toContainText('Security key or device passkey')
  await expect(thisSession(page)).not.toContainText('Password')
})

test('a synced passkey whose counter does not grow still signs in', async ({ page }) => {
  await withoutAutofill(page)
  const admin = newAdmin()
  const key = await authenticator(page, { synced: true })
  await enrollPasskey(page, admin)
  const [registered] = (await key.cdp.send('WebAuthn.getCredentials', { authenticatorId: key.authenticatorId })).credentials
  // Backup eligible and backed up, as a passkey manager reports it (BE never changes for a credential).
  await key.cdp.send('WebAuthn.setCredentialProperties', {
    authenticatorId: key.authenticatorId,
    credentialId: registered.credentialId,
    backupEligibility: true,
    backupState: true,
  })

  await test.step('first discoverable sign-in moves the stored counter', async () => {
    await signOut(page)
    await page.getByTestId('passkey-sign-in').click()
    await signedIn(page)
  })

  await test.step('another copy of the passkey reports an older counter: accepted for a synced passkey', async () => {
    // The same credential, as a second device holding the synced passkey reports it: its counter starts over.
    const [current] = (await key.cdp.send('WebAuthn.getCredentials', { authenticatorId: key.authenticatorId })).credentials
    expect(current.signCount).toBeGreaterThan(0)
    await key.cdp.send('WebAuthn.removeCredential', { authenticatorId: key.authenticatorId, credentialId: current.credentialId })
    await key.cdp.send('WebAuthn.addCredential', {
      authenticatorId: key.authenticatorId,
      credential: { ...current, signCount: 0, backupEligibility: true, backupState: true },
    })
    await signOut(page)
    await page.getByTestId('passkey-sign-in').click()
    await signedIn(page)
    await page.goto('/account')
    await expect(thisSession(page)).toContainText('Synced passkey')
    await expect(page.getByTestId('mfa-factor')).toHaveCount(1)
    await expect(page.getByTestId('mfa-factor')).toContainText('Synced passkey')
  })
})

// Step-up (#359): a role change answers step_up_required once the sign-in is older than the step-up window; the
// Step-up dialog confirms with the passkey and the change goes through; a second change within the window doesn't
// prompt (the family-wide identity.admin grant).
test('step-up dialog on a role change; a second change within the window does not prompt', async ({ page }) => {
  test.setTimeout(STEP_UP_TTL_SECONDS * 1000 + 90_000)
  const admin = newAdmin()
  const target = newAccount('unprivileged')
  await authenticator(page)
  await enrollPasskey(page, admin)

  await test.step('wait until the sign-in no longer stands in for a step-up', async () => {
    await page.waitForTimeout((STEP_UP_TTL_SECONDS + 2) * 1000)
  })

  // A grant lives on the page's connection (never another's): the second change stays on the page, as a person would;
  // a reload is a new connection and asks again.
  await page.goto(`/users/${encodeURIComponent(target)}`)
  const changeRole = async (role: string) => {
    await page.locator('#access-role').selectOption(role)
    await page.getByRole('button', { name: 'Change role' }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'Change role' }).click() // the confirm dialog
  }

  await test.step('the first change asks for the passkey, then goes through', async () => {
    await changeRole('auditor')
    await expect(page.getByTestId('stepup-dialog')).toBeVisible()
    await expect(page.getByTestId('stepup-dialog')).toContainText(/Change accounts, roles or groups/)
    await page.getByTestId('stepup-use-passkey').click()
    await expect(page.getByTestId('stepup-dialog')).toHaveCount(0)
    await expect(page.getByText(new RegExp(`${target} is now`, 'i'))).toBeVisible()
  })

  await test.step('a second change within the window does not prompt', async () => {
    await changeRole('unprivileged')
    await expect(page.getByText(new RegExp(`${target} is now unprivileged`, 'i'))).toBeVisible()
    await expect(page.getByTestId('stepup-dialog')).toHaveCount(0)
  })
})

// ── MFA reset and recovery cooldown (#360) ────────────────────────────────────────────────────────────────────────

test('an MFA reset (vh, then the Users page) leads to guided enrollment inside the recovery cooldown', async ({ browser }) => {
  test.setTimeout(150_000)
  // A plain account the boss (an admin) may manage, held to MFA for itself (`vh user mfa require`).
  const target = newAdmin('unprivileged')
  execFileSync(VH as string, ['user', 'mfa', 'require', target.name], { encoding: 'utf8' })
  const boss = newAdmin()

  const targetContext = await browser.newContext()
  const tp = await targetContext.newPage()
  await withoutAutofill(tp)
  await authenticator(tp)

  await test.step('the target enrolls a passkey', async () => {
    await enrollPasskey(tp, target)
    await signOut(tp)
  })

  await test.step('`vh user mfa reset` as the super admin, on the host', async () => {
    const out = execFileSync(VH as string, ['user', 'mfa', 'reset', target.name, '--reason', 'e2e-lost-device', '--yes'], {
      encoding: 'utf8',
    })
    expect(out).toMatch(/1 factor\(s\) disabled/)
    const status = JSON.parse(execFileSync(VH as string, ['user', 'mfa', 'status', target.name, '--json'], { encoding: 'utf8' }))
    expect(status.factors).toHaveLength(0)
    expect(status.required_flag).toBe(true)
    expect(status.cooldown_until).toBeGreaterThan(Date.now() / 1000)
  })

  await test.step('the next sign-in is the guided enrollment; the new passkey is flagged and the cooldown shown', async () => {
    await password(tp, target.name, target.password)
    await expect(tp.getByText('Set up a second factor')).toBeVisible()
    await tp.getByTestId('mfa-choose-passkey').click()
    await tp.getByTestId('mfa-passkey-create').click()
    await saveRecoveryCodes(tp)
    await tp.getByTestId('mfa-enrollment-continue').click()
    await signedIn(tp)
    await tp.goto('/account')
    await expect(tp.getByText('Recovery cooldown')).toBeVisible()
    await expect(tp.getByTestId('mfa-factor')).toHaveCount(1)
    await expect(tp.getByTestId('mfa-factor')).toContainText('Added during recovery')
  })

  await test.step('an administrator resets it again from the Users page', async () => {
    const bossContext = await browser.newContext()
    const bp = await bossContext.newPage()
    await withoutAutofill(bp)
    await authenticator(bp)
    await enrollPasskey(bp, boss)
    await bp.goto(`/users/${encodeURIComponent(target.name)}`)
    await expect(bp.getByTestId('mfa-admin-factors')).toContainText('1 factor')
    await bp.getByTestId('mfa-admin-reset').click()
    await expect(bp.getByTestId('mfa-admin-reset-confirm')).toBeDisabled()
    await bp.getByTestId('mfa-admin-reset-reason').fill('e2e second reset')
    await bp.getByTestId('mfa-admin-reset-confirm').click()
    // A fresh passkey sign-in stands in for the account.credentials step-up; otherwise the dialog asks.
    if (await bp.getByTestId('stepup-dialog').isVisible()) await bp.getByTestId('stepup-use-passkey').click()
    await expect(bp.getByText(new RegExp(`MFA reset for ${target.name}`))).toBeVisible()
    await expect(bp.getByTestId('mfa-admin-factors')).toContainText('No sign-in factors')
    await bossContext.close()
  })

  await test.step('the target was signed out', async () => {
    await tp.goto('/account')
    await expect(tp).toHaveURL(/\/login/)
  })
  await targetContext.close()
})
