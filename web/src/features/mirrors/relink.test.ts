import { test } from 'node:test'
import assert from 'node:assert/strict'
import { canKeepBoth, choicePayload, countLines, gainsText, kindPayload, kindText, phaseText, winnerOf, type RelinkEntry, type RelinkStatus } from './relink.ts'

type Version = NonNullable<RelinkEntry['this']>
const version = (kind: Version['kind']): Version => ({ kind, trashed: false, path: '/a', hash: 'h', name: 'a', parent: null })

test('drift kinds read in words, naming the other server', () => {
  assert.equal(kindText('only_theirs', 'vps'), 'Only on vps')
  assert.equal(kindText('changed_both', 'vps'), 'Changed on both')
  assert.equal(kindText('differs', 'vps'), 'Differs')
})

test('the counts that are not zero, in order', () => {
  const lines = countLines({ only_this: 2, changed_theirs: 1, differs: 0, total: 3 } as RelinkStatus['counts'], 'vps')
  assert.deepEqual(
    lines.map(l => [l.kind, l.count]),
    [
      ['only_this', 2],
      ['changed_theirs', 1],
    ],
  )
})

test('the winner of an entry follows the plan core', () => {
  assert.equal(winnerOf('core', 'this'), 'this')
  assert.equal(winnerOf('core', 'theirs'), 'theirs')
  assert.equal(winnerOf('mirror', 'this'), 'theirs')
  assert.equal(winnerOf('mirror', 'theirs'), 'this')
  assert.equal(winnerOf('both', 'this'), 'both')
})

test('only files keep both versions', () => {
  assert.equal(canKeepBoth({ this: version('file'), theirs: null }), true)
  assert.equal(canKeepBoth({ this: version('directory'), theirs: version('directory') }), false)
})

test('a choice and a bulk choice as the plan takes them; empty is the default', () => {
  assert.deepEqual(choicePayload('u1', 'both'), { set: [{ uid: 'u1', choice: 'both' }] })
  assert.deepEqual(choicePayload('u1', ''), { set: [{ uid: 'u1', choice: null }] })
  assert.deepEqual(kindPayload('changed_theirs', 'theirs'), { by_kind: [{ kind: 'changed_theirs', choice: 'theirs' }] })
})

test('what each side gains and loses, in words', () => {
  assert.equal(gainsText({ takes: 1, keeps_held: 1, conflict_copies: 0 }), 'takes 1 from the other, keeps 1 of its own as held change')
  assert.match(gainsText({ takes: 0, keeps_held: 2, conflict_copies: 2 }), /2 conflict copies/)
})

test('the phase in words: running while bringing or copying, the server sentence when stale', () => {
  const at = (phase: string, error: string | null = null) => ({ relink: { phase, error } }) as unknown as RelinkStatus
  assert.equal(phaseText(undefined).running, false)
  assert.equal(phaseText(at('bring')).running, true)
  assert.equal(phaseText(at('copying')).running, true)
  assert.equal(phaseText(at('done')).tone, 'ok')
  assert.equal(phaseText(at('stale', 'the vault changed on this server')).text, 'the vault changed on this server')
})
