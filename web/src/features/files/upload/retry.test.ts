import { test } from 'node:test'
import assert from 'node:assert/strict'
import { backoffMs, BACKOFF_CAP_MS, classifyPart, parseRetryAfter, RETRY_AFTER_CAP_MS, transient } from './retry.ts'
import { contentDigest, formatContentDigest } from './digest.ts'
import { errorText, readError, readSession } from './protocol.ts'

test('Retry-After: seconds, HTTP dates, garbage, cap', () => {
  const now = Date.parse('2026-10-31T12:00:00Z')
  assert.equal(parseRetryAfter('3', now), 3000)
  assert.equal(parseRetryAfter(' 0 ', now), 0)
  assert.equal(parseRetryAfter('Sat, 31 Oct 2026 12:00:05 GMT', now), 5000)
  assert.equal(parseRetryAfter('Sat, 31 Oct 2026 11:00:00 GMT', now), 0)
  assert.equal(parseRetryAfter('soon', now), null)
  assert.equal(parseRetryAfter(null, now), null)
  assert.equal(parseRetryAfter('99999', now), RETRY_AFTER_CAP_MS)
})

test('backoff grows exponentially with jitter and is capped', () => {
  assert.equal(backoffMs(0, null, 0), 500)
  assert.equal(backoffMs(0, null, 0.999999), 1000)
  assert.equal(backoffMs(3, null, 0), 4000)
  for (let attempt = 0; attempt < 40; attempt++) {
    const value = backoffMs(attempt, null, Math.random())
    assert.ok(value >= 0 && value <= BACKOFF_CAP_MS)
  }
  // Retry-After is a floor (plus up to a second of spread).
  assert.ok(backoffMs(0, 5000, 0) >= 5000)
  assert.ok(backoffMs(0, 5000, 0.5) <= 6000)
  assert.ok(backoffMs(10, 1000, 0) >= 1000)
})

test('part answers map to retry, resync, file_state, gone and fatal', () => {
  assert.equal(classifyPart(200, null), 'stored')
  assert.equal(classifyPart(0, null), 'retry')
  assert.equal(classifyPart(503, 'busy'), 'retry')
  assert.equal(classifyPart(502, null), 'retry')
  assert.equal(classifyPart(429, 'too_many_parts_in_flight'), 'retry')
  assert.equal(classifyPart(400, 'digest_mismatch'), 'retry')
  assert.equal(classifyPart(409, 'part_overlap'), 'resync')
  assert.equal(classifyPart(409, 'part_conflict'), 'resync')
  assert.equal(classifyPart(409, 'file_state'), 'file_state')
  assert.equal(classifyPart(404, 'not_found'), 'gone')
  assert.equal(classifyPart(507, 'insufficient_storage'), 'fatal')
  assert.equal(classifyPart(413, 'part_too_large'), 'fatal')
  assert.equal(classifyPart(403, 'forbidden'), 'fatal')
  assert.equal(classifyPart(400, 'bad_request'), 'fatal')
  assert.equal(transient(507), false)
  assert.equal(transient(503), true)
})

test('Content-Digest is RFC 9530 sha-256 in base64 between colons', async () => {
  // SHA-256("abc")
  const hex = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
  const raw = new Uint8Array(hex.match(/../g)!.map(h => parseInt(h, 16)))
  assert.equal(formatContentDigest(raw), 'sha-256=:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=:')
  assert.equal(await contentDigest(new TextEncoder().encode('abc').buffer as ArrayBuffer), 'sha-256=:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=:')
  // No Web Crypto (plain-HTTP origin): no header.
  assert.equal(await contentDigest(new ArrayBuffer(3), null), null)
})

test('errors read only the §3.7 envelope, and codes become console wording', () => {
  assert.deepEqual(readError({ error: { code: 'busy', message: 'later' } }), { code: 'busy', message: 'later' })
  assert.equal(readError({ error: 'Not found' }), null)
  assert.equal(readError(null), null)
  assert.match(errorText({ code: 'key_rotated', message: '' }, 'x'), /Upload the file again/)
  assert.match(errorText({ code: 'already_exists', message: '' }, 'x'), /already exists/)
  assert.match(errorText({ code: 'insufficient_storage', message: '' }, 'x'), /room/)
  assert.equal(errorText({ code: 'something_new', message: 'From the server' }, 'x'), 'From the server')
  assert.equal(errorText(null, 'fallback'), 'fallback')
})

test('session answers are read defensively', () => {
  const part = { default_bytes: 1, min_bytes: 1, max_bytes: 1, max_in_flight: 1 }
  assert.equal(readSession({ files: [] }), null)
  const s = readSession({ upload_id: 'u', part, state: 'weird', files: [{ file_id: 'f0', state: 'receiving', ranges: [[0, 1], 'x', [2]] }, { state: 'committed' }] })
  assert.ok(s)
  assert.equal(s.state, 'open')
  assert.equal(s.files.length, 1)
  assert.deepEqual(s.files[0].ranges, [[0, 1]])
  // Finish answers may omit upload_id/part.
  assert.ok(readSession({ state: 'complete', files: [] }, { upload_id: 'u', part }))
})
