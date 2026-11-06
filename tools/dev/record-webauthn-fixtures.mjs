#!/usr/bin/env node
// Records WebAuthn ceremonies from Chrome's virtual authenticator (CDP WebAuthn domain) as verifier fixtures (#355).
//
//   node tools/dev/record-webauthn-fixtures.mjs [core/test-assets/webauthn/chrome-virtual-authenticator.json]
//
// Uses the console's Playwright and its Chromium (pnpm --dir web install; npx playwright install chromium). The page
// is https://vault.example.test/, served by Playwright's router (no network, no certificate), so the ceremonies run
// in a real secure context with RP ID vault.example.test. Each fixture is the browser's own L3 JSON
// (PublicKeyCredential.toJSON()) plus the challenge the "server" chose; core/tests/unit/test_webauthn_recorded.cpp
// verifies them. Fixtures from 1Password, iCloud Keychain and hardware keys need a person and the device, so they
// are recorded with the console ceremonies (#357) in the same shape.
import { randomBytes } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'

const require = createRequire(new URL('../../web/package.json', import.meta.url))
const { chromium } = require('@playwright/test')

const RP_ID = 'vault.example.test'
const ORIGIN = `https://${RP_ID}`
const out = process.argv[2] ?? 'core/test-assets/webauthn/chrome-virtual-authenticator.json'
const b64u = buf => Buffer.from(buf).toString('base64url')

// name, COSE alg, authenticator options, request options, what the verifier must answer
const CASES = [
  { name: 'es256-platform', alg: -7, auth: {}, uv: 'required', expect: 'none' },
  { name: 'eddsa-platform', alg: -8, auth: {}, uv: 'required', expect: 'none' },
  { name: 'rs256-platform', alg: -257, auth: {}, uv: 'required', expect: 'none' },
  {
    name: 'es256-synced',
    alg: -7,
    auth: { defaultBackupEligibility: true, defaultBackupState: true },
    uv: 'required',
    expect: 'none',
  },
  { name: 'es256-security-key-u2f-style', alg: -7, auth: { transport: 'usb', hasResidentKey: false }, uv: 'required', expect: 'none' },
  // Registered with UV, then asked to sign in without it: the assertion carries UV = 0.
  { name: 'es256-assertion-without-uv', alg: -7, auth: {}, uv: 'discouraged', expect: 'user_not_verified', noUvOnGet: true },
]

const browser = await chromium.launch()
const context = await browser.newContext()
await context.route(`${ORIGIN}/**`, route =>
  route.fulfill({ contentType: 'text/html', body: '<!doctype html><title>webauthn fixtures</title>' }),
)
const page = await context.newPage()
await page.goto(`${ORIGIN}/`)
const cdp = await context.newCDPSession(page)
await cdp.send('WebAuthn.enable')

const fixtures = []
for (const c of CASES) {
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
      ...c.auth,
    },
  })
  const regChallenge = randomBytes(32)
  const userId = randomBytes(32)
  const registration = await page.evaluate(
    async ({ challenge, userId, alg, rpId }) => {
      const dec = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), ch => ch.charCodeAt(0))
      const cred = await navigator.credentials.create({
        publicKey: {
          challenge: dec(challenge),
          rp: { id: rpId, name: 'Vaulthalla' },
          user: { id: dec(userId), name: 'fixture', displayName: 'Fixture' },
          pubKeyCredParams: [{ type: 'public-key', alg }],
          authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
          attestation: 'none',
          extensions: { credProps: true },
        },
      })
      return cred.toJSON()
    },
    { challenge: b64u(regChallenge), userId: b64u(userId), alg: c.alg, rpId: RP_ID },
  )
  if (c.noUvOnGet) await cdp.send('WebAuthn.setUserVerified', { authenticatorId, isUserVerified: false })
  const getChallenge = randomBytes(32)
  const assertion = await page.evaluate(
    async ({ challenge, id, rpId, uv }) => {
      const dec = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), ch => ch.charCodeAt(0))
      const cred = await navigator.credentials.get({
        publicKey: {
          challenge: dec(challenge),
          rpId,
          allowCredentials: [{ type: 'public-key', id: dec(id) }],
          userVerification: uv,
        },
      })
      return cred.toJSON()
    },
    { challenge: b64u(getChallenge), id: registration.rawId, rpId: RP_ID, uv: c.uv },
  )
  fixtures.push({
    name: c.name,
    alg: c.alg,
    user_handle: b64u(userId),
    registration: { challenge: b64u(regChallenge), response: registration, expect: 'none' },
    assertion: { challenge: b64u(getChallenge), response: assertion, expect: c.expect },
  })
  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId })
}

const doc = {
  source: `Chrome ${browser.version()} virtual authenticator (CDP WebAuthn domain), recorded by tools/dev/record-webauthn-fixtures.mjs`,
  recorded: new Date().toISOString().slice(0, 10),
  rp_id: RP_ID,
  origin: ORIGIN,
  fixtures,
}
writeFileSync(out, JSON.stringify(doc, null, 1) + '\n')
await browser.close()
console.log(`wrote ${fixtures.length} fixtures to ${out}`)
