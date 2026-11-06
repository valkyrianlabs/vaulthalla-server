import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  assertionToJson,
  base64urlToBytes,
  bytesToBase64url,
  ceremonyMessage,
  creationOptionsFromJson,
  registrationToJson,
  requestOptionsFromJson,
} from './webauthn.ts'

const buf = (...b: number[]) => new Uint8Array(b).buffer

test('base64url round-trips without padding and refuses other alphabets', () => {
  for (const bytes of [[], [0], [0xfb, 0xff], [1, 2, 3], Array.from({ length: 32 }, (_, i) => i * 7)]) {
    const text = bytesToBase64url(new Uint8Array(bytes))
    assert.match(text, /^[A-Za-z0-9_-]*$/)
    assert.deepEqual([...base64urlToBytes(text)], bytes)
  }
  assert.equal(bytesToBase64url(new Uint8Array([0xfb, 0xff])), '-_8')
  assert.throws(() => base64urlToBytes('ab+/'))
  assert.throws(() => base64urlToBytes('ab=='))
})

test('options: binary members decoded, the rest passed through', () => {
  const create = creationOptionsFromJson({
    rp: { id: 'vault.example.com', name: 'Vaulthalla' },
    user: { id: 'AQID', name: 'admin', displayName: 'admin' },
    challenge: 'BAUG',
    pubKeyCredParams: [{ type: 'public-key', alg: -8 }],
    timeout: 120000,
    excludeCredentials: [{ type: 'public-key', id: 'BwgJ', transports: ['internal'] }],
    authenticatorSelection: { residentKey: 'preferred', requireResidentKey: false, userVerification: 'required' },
    attestation: 'none',
    extensions: { credProps: true },
  })
  assert.deepEqual([...create.user.id], [1, 2, 3])
  assert.deepEqual([...create.challenge], [4, 5, 6])
  assert.deepEqual([...create.excludeCredentials[0].id], [7, 8, 9])
  assert.equal(create.authenticatorSelection.userVerification, 'required')

  const get = requestOptionsFromJson({
    challenge: 'BAUG',
    rpId: 'vault.example.com',
    timeout: 120000,
    userVerification: 'required',
    allowCredentials: [{ type: 'public-key', id: 'BwgJ' }],
  })
  assert.deepEqual([...get.allowCredentials[0].id], [7, 8, 9])
  assert.equal('transports' in get.allowCredentials[0], false)
})

test('credentials: only the members the daemon reads', () => {
  const reg = registrationToJson({
    id: 'BwgJ',
    rawId: buf(7, 8, 9),
    type: 'public-key',
    authenticatorAttachment: 'platform',
    response: { clientDataJSON: buf(1), attestationObject: buf(2), getTransports: () => ['internal', 'hybrid'] },
    getClientExtensionResults: () => ({ credProps: { rk: true } }),
  })
  assert.deepEqual(reg, {
    id: 'BwgJ',
    rawId: 'BwgJ',
    type: 'public-key',
    response: { clientDataJSON: 'AQ', attestationObject: 'Ag', transports: ['internal', 'hybrid'] },
    authenticatorAttachment: 'platform',
    clientExtensionResults: { credProps: { rk: true } },
  })
  const assertion = assertionToJson({
    id: 'BwgJ',
    rawId: buf(7, 8, 9),
    type: 'public-key',
    response: { clientDataJSON: buf(1), authenticatorData: buf(3), signature: buf(4), userHandle: null },
  })
  assert.equal(assertion.response.userHandle, null)
  assert.equal(assertion.response.signature, 'BA')
  assert.deepEqual(assertion.clientExtensionResults, {})
  assert.throws(() => assertionToJson({ id: 'x', rawId: buf(1), type: 'public-key', response: { clientDataJSON: buf(1) } }))
})

test('a closed prompt reads as the person’s choice', () => {
  assert.match(ceremonyMessage({ name: 'NotAllowedError' }), /closed or timed out/)
  assert.match(ceremonyMessage({ name: 'InvalidStateError' }), /already registered/)
})
