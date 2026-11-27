import { test } from 'node:test'
import assert from 'node:assert/strict'
import { isTargetBound, readStepUp, stepUpAction, stepUpWindowText } from './stepUp.ts'

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

test('linking a server names what it trusts, though it asks for the device.trust family', () => {
  assert.equal(stepUpAction({ family: 'device.trust', target: 'peer.link.start:tofu:10.0.0.5:36972' }), 'Link this server with another server')
  assert.equal(stepUpAction({ family: 'device.trust', target: 'peer.pairing.approve:r1:ab:cd' }), 'Link this server with another server')
  assert.equal(stepUpAction({ family: 'device.trust', target: 'cloud.relay.enable' }), 'Trust a device')
  assert.equal(stepUpAction({ family: 'device.trust', target: null }), 'Trust a device')
  assert.equal(stepUpAction({ family: 'keys', target: 'peer.x' }), 'Handle vault encryption keys')
  assert.equal(stepUpAction({ family: 'keys', target: 'mirror.add:5' }), 'Give a linked server this vault’s keys')
  assert.equal(stepUpAction({ family: 'data.destroy', target: 'mirror.cancel:5' }), 'End a vault’s mirror')
  assert.equal(stepUpAction({ family: 'data.destroy', target: 'storage.vault.remove:5' }), 'Permanently remove data')
})
