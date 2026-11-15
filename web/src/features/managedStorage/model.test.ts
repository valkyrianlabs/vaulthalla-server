import { test } from 'node:test'
import assert from 'node:assert/strict'
import { leaveUrl, listedVaults, offNeedsConfirm, progressRatio, stateTone, switchable, usageRatio } from './model.ts'
import { COPY, planSentence } from './copy.ts'

test('state tones follow the server state', () => {
  assert.equal(stateTone({ state: 'active', access: 'full', reason: null }), 'ok')
  assert.equal(stateTone({ state: 'active', access: 'read_only', reason: null }), 'warn')
  assert.equal(stateTone({ state: 'moved', access: 'none', reason: null }), 'danger')
  assert.equal(stateTone({ state: 'waiting', access: null, reason: 'payment_required' }), 'warn')
  assert.equal(stateTone({ state: 'off', access: null, reason: null }), 'neutral')
})

test('progress and usage ratios are null while unknown', () => {
  assert.equal(progressRatio({ progress: null }), null)
  assert.equal(progressRatio({ progress: { bytes_total: 0, bytes_done: 0 } as never }), null)
  assert.equal(progressRatio({ progress: { bytes_total: 10, bytes_done: 5 } as never }), 0.5)
  assert.equal(usageRatio({ used_bytes: null, quota_bytes: 10 }), null)
  assert.equal(usageRatio({ used_bytes: 20, quota_bytes: 10 }), 1)
})

test('offered vaults are in the banner only; switches and confirmations', () => {
  const vaults = [{ switch: 'offered' }, { switch: 'on' }, { switch: null }] as never
  assert.equal(listedVaults({ vaults }).length, 2)
  assert.equal(switchable({ storage: 'own', state: 'own' }), false)
  assert.equal(switchable({ storage: 'managed', state: 'active' }), true)
  assert.equal(offNeedsConfirm({ state: 'active' }), true)
  assert.equal(offNeedsConfirm({ state: 'waiting' }), false)
  assert.equal(leaveUrl({ ejection: { portal_url: 'https://example.test/eject' } }), 'https://example.test/eject')
  assert.equal(leaveUrl({ ejection: { portal_url: 'javascript:alert(1)' } }), null)
  assert.equal(leaveUrl({ ejection: null }), null)
})

test('the copy is neutral: it never names the service or ties it to recovery', () => {
  const all = JSON.stringify(COPY) + ['active', 'past_due', 'restricted', 'suspended', 'ended', null].map(s => planSentence(s, 'p')).join(' ')
  // Spelled in parts so the claims lint, which reads this file too, sees no claim here.
  assert.doesNotMatch(all, new RegExp(['vaulthalla', 'cloud'].join('[ .]'), 'i'))
  assert.doesNotMatch(all, /recover/i)
})
