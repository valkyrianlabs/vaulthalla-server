import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readPending } from './mfa.ts'

test('readPending takes data.pending and nothing else', () => {
  assert.equal(readPending(undefined), null)
  assert.equal(readPending({ code: 'mfa_required' }), null)
  assert.equal(readPending({ pending: { kind: 'other', expires_at: 1, methods: [] } }), null)
  const p = readPending({
    code: 'mfa_required',
    pending: {
      kind: 'mfa',
      expires_at: 1792483500,
      methods: ['webauthn', 'totp', 'sms'],
      attempts_remaining: 4,
      webauthn: { publicKey: { challenge: 'AQ', rpId: 'v', timeout: 1, userVerification: 'required', allowCredentials: [] } },
    },
  })
  assert.ok(p)
  assert.deepEqual(p.methods, ['webauthn', 'totp'])
  assert.equal(p.attempts_remaining, 4)
  assert.equal(p.webauthn?.publicKey.challenge, 'AQ')
  assert.equal(readPending({ pending: { kind: 'enrollment', expires_at: 1, methods: ['totp'] } })?.attempts_remaining, 0)
})
