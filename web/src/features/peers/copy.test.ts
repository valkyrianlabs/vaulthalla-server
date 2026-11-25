import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ATTEMPT_TEXT } from './model.ts'
import { allCopy, COMPARED_BY, PEERS_COPY } from './copy.ts'

const everything = () => [...allCopy(), ...Object.values(COMPARED_BY), ...Object.values(ATTEMPT_TEXT).map(t => t.label)]

test('nothing says or implies that the link carries vaults today', () => {
  // The one sentence about what a link is for puts mirroring in a later release and says it carries nothing else now.
  assert.match(PEERS_COPY.purpose, /later release/)
  assert.match(PEERS_COPY.purpose, /carries nothing else/)
  for (const text of everything()) {
    if (text === PEERS_COPY.purpose) continue
    assert.doesNotMatch(text, /mirror|sync|replicat|backup|copies|copied/i, text)
  }
})

test('the page is marked experimental and the unavailable state names nothing to switch on', () => {
  assert.equal(PEERS_COPY.experimental, 'Experimental')
  for (const text of [PEERS_COPY.unavailableTitle, PEERS_COPY.unavailableBody]) assert.doesNotMatch(text, /experimental|config|peers\./i)
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
