import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseLegacySharePath, parseShareHash, shareHash, shareHref } from './shareLocation.ts'

test('a share link carries the token only in the fragment', () => {
  const href = shareHref({ token: 'tok_ABC-123', path: '/' })
  assert.equal(href, '/share#tok_ABC-123')
  assert.equal(new URL(href, 'https://vault.example').pathname, '/share')
  assert.equal(new URL(href, 'https://vault.example').search, '')
})

test('folder names stay in the fragment and round-trip', () => {
  const location = { token: 'tok', path: '/Patients/Jane Doe/scan #1.pdf' }
  const href = shareHref(location)
  const url = new URL(href, 'https://vault.example')
  assert.equal(url.pathname, '/share')
  assert.ok(!url.pathname.includes('Jane'))
  assert.deepEqual(parseShareHash(url.hash), location)
})

test('parseShareHash accepts the bare token, with or without #', () => {
  assert.deepEqual(parseShareHash('#tok'), { token: 'tok', path: '/' })
  assert.deepEqual(parseShareHash('tok/a/b'), { token: 'tok', path: '/a/b' })
  assert.equal(shareHash({ token: 'tok', path: '/a/b' }), '#tok/a/b')
})

test('parseShareHash refuses empty, malformed and escaping fragments', () => {
  assert.equal(parseShareHash(''), null)
  assert.equal(parseShareHash('#'), null)
  assert.equal(parseShareHash('#/a'), null)
  assert.equal(parseShareHash('#tok/%E0%A4%A'), null)
  assert.equal(parseShareHash('#tok/../etc'), null)
  assert.equal(parseShareHash('#tok/a/%2E%2E'), null)
})

test('pre-#327 links map onto the fragment form', () => {
  assert.deepEqual(parseLegacySharePath('/share/tok'), { token: 'tok', path: '/' })
  assert.deepEqual(parseLegacySharePath('/share/tok/a%20b/c'), { token: 'tok', path: '/a b/c' })
  assert.equal(parseLegacySharePath('/share'), null)
  assert.equal(parseLegacySharePath('/shares/tok'), null)
})
