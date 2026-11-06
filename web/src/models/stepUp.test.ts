import { test } from 'node:test'
import assert from 'node:assert/strict'
import { isTargetBound, readStepUp, stepUpWindowText } from './stepUp.ts'

test('reads a step_up_required refusal', () => {
  const r = readStepUp('step_up_required', {
    code: 'step_up_required',
    family: 'identity.admin',
    target: null,
    methods: ['webauthn', 'password_totp', 'sms'],
    max_age_seconds: 300,
  })
  assert.deepEqual(r, { family: 'identity.admin', target: null, methods: ['webauthn', 'password_totp'], max_age_seconds: 300 })
})

test('ignores other refusals and unknown families', () => {
  assert.equal(readStepUp('denied', { family: 'keys' }), null)
  assert.equal(readStepUp('step_up_required', { family: 'everything' }), null)
  assert.equal(readStepUp('step_up_required', null), null)
})

test('target-bound families confirm one change', () => {
  const keys = readStepUp('step_up_required', { family: 'keys', target: 'vault.keys.export:7', methods: [] })
  assert.ok(keys)
  assert.equal(keys.target, 'vault.keys.export:7')
  assert.equal(isTargetBound('keys'), true)
  assert.equal(isTargetBound('settings'), false)
  assert.equal(stepUpWindowText(keys), 'This confirms this one change.')
  assert.match(stepUpWindowText({ family: 'settings', target: null, methods: [], max_age_seconds: 300 }), /next 5 minutes/)
})
