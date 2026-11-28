import { test } from 'node:test'
import assert from 'node:assert/strict'
import { FINDINGS_COPY as C, SILENCE_LABELS, allCopy } from './copy.ts'

test('every state has its own words', () => {
  assert.equal(C.active, 'Not acknowledged')
  assert.equal(C.acknowledged('ana', '5 minutes ago'), 'Acknowledged by ana 5 minutes ago')
  assert.equal(C.silencedUntil('ana', 'Dec 1, 2026, 9:00 AM'), 'Silenced by ana until Dec 1, 2026, 9:00 AM')
  assert.equal(C.silencedForever('ana'), 'Silenced by ana until turned back on')
})

test('the controls are Acknowledge, Silence and Turn back on', () => {
  assert.deepEqual([C.acknowledge, C.silence, C.turnBackOn], ['Acknowledge', 'Silence…', 'Turn back on'])
  assert.deepEqual(Object.values(SILENCE_LABELS), ['1 hour', '24 hours', '7 days', 'Until turned back on'])
})

test('silencing says it never hides the true status, and that worse news speaks again', () => {
  assert.match(C.silenceBody, /still counts in the health status/)
  assert.match(C.silenceBody, /gets worse, you are told again/)
  assert.match(C.silencedDescription, /still count in the health status/)
  assert.match(C.acknowledgeHint, /clears and comes back, or gets worse/)
})

test('the note limit is spelled out', () => {
  assert.equal(C.noteHint(500), 'Up to 500 characters. Other operators see it next to the silence.')
  assert.equal(C.noteTooLong(500, 512), 'At most 500 characters (512 now).')
})

test('plain operator wording: no command names, codes or internals', () => {
  for (const text of allCopy()) {
    assert.doesNotMatch(text, /health\.|unsilence|unattended|can_manage|admin\.stats|\bws\b|payload/i, text)
    assert.ok(text.trim() === text && text.length > 0, `untrimmed or empty: ${JSON.stringify(text)}`)
  }
})
