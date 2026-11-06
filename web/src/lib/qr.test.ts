import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { encodeQr, type QrMatrix } from './qr.ts'

// The matrices below were decoded back to their text with zbar (zbarimg) for all eight masks and versions 1..10
// before being pinned: a change to the encoder that alters them has to be decoded again.
const URI =
  'otpauth://totp/Vaulthalla:admin?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Vaulthalla&algorithm=SHA1&digits=6&period=30'

const digest = (m: QrMatrix) =>
  createHash('sha256')
    .update(m.map(row => row.map(c => (c ? '1' : '0')).join('')).join('\n'))
    .digest('hex')

test('pinned matrices (decoded with zbar)', () => {
  assert.equal(digest(encodeQr('HELLO', 3)), '71bc9ab3ffcaa0d281e4873d98c839634768a360dd4020111d405a3c41752367')
  assert.equal(digest(encodeQr('HELLO')), 'c346c75add5698735afe3f7eb4f3e6c57ccefd9563f45f65c6d76aa518fb6f91')
  assert.equal(digest(encodeQr(URI, 3)), '062f75d72164d9b3f1cabd548d8c6787a06dab82fde25eeefe05df4e11b368bb')
  assert.equal(digest(encodeQr(URI)), '875ea3f0cbbe4a8692cbf3920d769f75345ffadca0b6d8ad8ca42a8b10a2af38')
})

test('the version grows with the text, and the structure is in place', () => {
  assert.equal(encodeQr('HELLO').length, 21) // version 1
  const m = encodeQr(URI)
  assert.equal(m.length, 49) // version 8 at level M
  for (const row of m) assert.equal(row.length, 49)
  // Finder patterns: dark 7x7 rings with a dark 3x3 core, at three corners.
  for (const [cx, cy] of [[3, 3], [45, 3], [3, 45]])
    for (let dy = -3; dy <= 3; dy++)
      for (let dx = -3; dx <= 3; dx++) assert.equal(m[cy + dy][cx + dx], Math.max(Math.abs(dx), Math.abs(dy)) !== 2)
  // Timing patterns alternate between the finders.
  for (let i = 8; i < 41; i++) {
    assert.equal(m[6][i], i % 2 === 0)
    assert.equal(m[i][6], i % 2 === 0)
  }
  assert.equal(m[49 - 8][8], true, 'the dark module')
})

test('text that does not fit is refused', () => {
  assert.throws(() => encodeQr('x'.repeat(300)))
})
