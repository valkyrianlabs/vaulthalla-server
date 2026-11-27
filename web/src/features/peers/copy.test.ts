import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ATTEMPT_TEXT } from './model.ts'
import { allCopy, COMPARED_BY, PEERS_COPY } from './copy.ts'

const everything = () => [...allCopy(), ...Object.values(COMPARED_BY), ...Object.values(ATTEMPT_TEXT).map(t => t.label)]

test('only the purpose sentence says what the link carries', () => {
  // The one sentence about what a link is for names mirrored vaults and says it carries nothing else.
  assert.match(PEERS_COPY.purpose, /mirrored vaults/)
  assert.match(PEERS_COPY.purpose, /carries nothing else/)
  for (const text of everything()) {
    if (text === PEERS_COPY.purpose) continue
    assert.doesNotMatch(text, /mirror|sync|replicat|backup|copies|copied/i, text)
  }
})

test('unlinking says what it does and does not do', () => {
  const body = PEERS_COPY.unlinkBody('vps')
  assert.match(body, /keeps nothing it can use to reconnect/)
  assert.match(body, /new pairing with a new code/)
  assert.match(body, /No files, vaults or accounts change/)
})

test('the code is compared, never typed, and a wrong one declines', () => {
  assert.match(PEERS_COPY.acceptSteps.join(' '), /wrong code declines the request/)
  assert.match(PEERS_COPY.codeStep('vps'), /click this code/)
})

test('who compared the code reads as a person or Desktop, nothing in between', () => {
  assert.deepEqual(COMPARED_BY, { person: 'A person', desktop: 'Desktop' })
})
