import { test } from 'node:test'
import assert from 'node:assert/strict'
import { allMirrorCopy, MIRROR_COPY } from './copy.ts'
import { REASON_TEXT, ROLE_TEXT, OP_TEXT } from './model.ts'

const everything = () => [
  ...allMirrorCopy(),
  ...Object.values(REASON_TEXT),
  ...Object.values(ROLE_TEXT).map(r => r.label),
  ...Object.values(OP_TEXT),
]

test('every sentence is plain: no internal codes, no config names, no CLI-only words', () => {
  for (const text of everything()) {
    assert.doesNotMatch(text, /\b(mirror|peer|vault)\.[a-z_]+/i, text) // ws command names
    assert.doesNotMatch(text, /\bmirror_[a-z_]+|experimental|config\.yaml/i, text)
    assert.doesNotMatch(text, /\b(seq|uid|digest|baseline|tombstone|undefined|null|NaN)\b/, text)
  }
})

test('each confirmation says what will happen in one or two sentences', () => {
  const bodies = [
    MIRROR_COPY.endBody('vps'),
    MIRROR_COPY.cancelStartBody('vps'),
    MIRROR_COPY.removeOrphanBody,
    MIRROR_COPY.switchBody('studio', 'vps'),
    MIRROR_COPY.resyncBody('vps'),
    MIRROR_COPY.detachBody('vps'),
    MIRROR_COPY.acceptBody('Projects', 'vps'),
    MIRROR_COPY.declineBody('vps'),
    MIRROR_COPY.heldDiscardBody('a.txt'),
    MIRROR_COPY.takeoverBody('vps'),
    MIRROR_COPY.takeoverWarnBody('vps'),
    MIRROR_COPY.copyBody('vps', true),
    MIRROR_COPY.copyBody('vps', false),
    MIRROR_COPY.copyCancelBody,
  ]
  for (const body of bodies) {
    const sentences = body.split(/(?<=[.!?])\s+/).filter(Boolean)
    assert.ok(sentences.length >= 1 && sentences.length <= 2, body)
  }
})

test('ending a mirror and removing a copy are told apart', () => {
  assert.match(MIRROR_COPY.endLeaveHint('vps'), /keeps the copy/)
  assert.match(MIRROR_COPY.endRemoveHint('vps'), /removes its copy/)
  assert.match(MIRROR_COPY.removeOrphanBody, /for good/)
  assert.match(MIRROR_COPY.detachBody('vps'), /Nothing is deleted/)
})

test('take over warns about the old core’s changes; detaching a copy says the copy stays', () => {
  assert.match(MIRROR_COPY.takeoverWarnTitle('vps'), /may hold changes this server never received/)
  assert.match(MIRROR_COPY.copyBody('vps', true), /stays exactly as it is.*new, separate vault/)
  assert.match(MIRROR_COPY.stTookOverBody('vps'), /has not returned yet/)
})
