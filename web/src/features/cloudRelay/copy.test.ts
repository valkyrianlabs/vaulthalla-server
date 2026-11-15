import { test } from 'node:test'
import assert from 'node:assert/strict'
import { RELAY_LABELS } from './labels.ts'
import { RELAY_COPY, relayStateText, relaySwitchable, relaySwitchedBy, type RelayState } from './copy.ts'

const when = (s: number) => `t${s}`
const base = { connected_since: null, next_attempt_at: null }
const STATES: RelayState[] = ['off', 'not_linked', 'listener_off', 'connecting', 'connected', 'backoff', 'waiting', 'stopped']

test('every relay state reads as words with a tone', () => {
  const labels = STATES.map(state => relayStateText({ ...base, state }, when).label)
  assert.deepEqual(labels, ['Off', 'Not linked', 'Device listener off', 'Connecting', 'Connected', 'Retrying', 'Waiting', 'Stopped'])
  assert.equal(relayStateText({ ...base, state: 'connected', connected_since: 100 }, when).detail, 'Connected since t100.')
  assert.equal(relayStateText({ ...base, state: 'connected' }, when).tone, 'ok')
  assert.equal(relayStateText({ ...base, state: 'stopped' }, when).tone, 'danger')
  assert.match(relayStateText({ ...base, state: 'waiting', next_attempt_at: 300 }, when).detail, /every 5 minutes\. Next attempt t300\.$/)
  assert.match(relayStateText({ ...base, state: 'backoff', next_attempt_at: 7 }, when).detail, /Next attempt t7\.$/)
})

test('who switched it on is shown only while it is on', () => {
  assert.equal(relaySwitchedBy({ enabled: true, enabled_by: 'ada', enabled_at: 5 }, when), 'Switched on by ada on t5')
  assert.equal(relaySwitchedBy({ enabled: true, enabled_by: 'ada', enabled_at: null }, when), 'Switched on by ada')
  assert.equal(relaySwitchedBy({ enabled: false, enabled_by: null, enabled_at: null }, when), null)
})

test('the switch turns on only on a linked server and always turns off', () => {
  assert.equal(relaySwitchable({ enabled: false, state: 'not_linked' }), false)
  assert.equal(relaySwitchable({ enabled: false, state: 'off' }), true)
  assert.equal(relaySwitchable({ enabled: true, state: 'stopped' }), true)
})

test('the copy is honest about what the relay sees and never says blind', () => {
  const all = [...Object.values(RELAY_COPY), ...Object.values(RELAY_LABELS), ...STATES.map(state => relayStateText({ ...base, state }, when).detail)].join(' ')
  assert.doesNotMatch(all, /blind/i)
  assert.match(RELAY_COPY.what, /one outbound connection/)
  assert.match(RELAY_COPY.what, /read-only/)
  assert.match(RELAY_COPY.sees, /encrypted bytes it can't read/)
  for (const seen of ['account and server', "browser's key", 'network addresses', 'how much data']) assert.ok(RELAY_COPY.sees.includes(seen), seen)
  assert.match(RELAY_COPY.notOffered, /isn't offered to the public yet/)
})
