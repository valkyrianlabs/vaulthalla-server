import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  ATTEMPT_TEXT,
  codeChoices,
  formatCode,
  formatRemaining,
  groupHex,
  healthText,
  hostPort,
  linkFinished,
  parseFingerprint,
  parseLinkTarget,
  peerVersion,
  refusalText,
  secondsLeft,
  shortKey,
  shortNodeId,
  type PeerHealth,
} from './model.ts'

const when = (s: number) => `t${s}`
const down: PeerHealth = {
  connected: false,
  since: null,
  dialed_by: null,
  address: null,
  rtt_ms: null,
  peer_protocol: null,
  peer_version: null,
  protocol_compatible: null,
  last_error: null,
  last_error_at: null,
  next_attempt_at: null,
}
const live = (health: Partial<PeerHealth>) => ({ revoked: false, revoked_at: null, health: { ...down, ...health } })

test('a connected link names since when, who dialled, the round trip and the version', () => {
  const h = healthText(live({ connected: true, since: 100, dialed_by: 'peer', rtt_ms: 12, peer_version: '1.27.0', protocol_compatible: true }), when)
  assert.deepEqual(h, { label: 'Connected', tone: 'ok', facts: ['since t100', 'it dialled', '12 ms', 'Vaulthalla 1.27.0'] })
  assert.deepEqual(healthText(live({ connected: true, dialed_by: 'this_server', rtt_ms: 0 }), when).facts, ['this server dialled', '0 ms'])
})

test('another major protocol is a warning, not health', () => {
  const h = healthText(live({ connected: true, protocol_compatible: false }), when)
  assert.equal(h.tone, 'warn')
  assert.equal(h.label, 'Connected, other protocol')
  assert.ok(h.facts.includes('upgrade one of them'))
})

test('a link that is down says why and when it tries again, and never reads as healthy', () => {
  assert.deepEqual(healthText(live({ last_error: 'connection refused', next_attempt_at: 9 }), when), {
    label: 'Not connected',
    tone: 'danger',
    facts: ['connection refused', 'next try t9'],
  })
  assert.deepEqual(healthText(live({ next_attempt_at: 9 }), when), { label: 'Not connected', tone: 'warn', facts: ['next try t9'] })
  // The accepting side before the first dial: nothing known yet, so unknown, not ok.
  assert.deepEqual(healthText(live({}), when), { label: 'Not connected', tone: 'unknown', facts: ['waiting for a connection'] })
  assert.deepEqual(healthText({ revoked: true, revoked_at: 50, health: down }, when), { label: 'Unlinked', tone: 'neutral', facts: ['t50'] })
})

test('the version is the live one when connected, else the last one told', () => {
  assert.equal(peerVersion({ product_version: '1.26.0', health: { ...down, peer_version: '1.27.0' } }), '1.27.0')
  assert.equal(peerVersion({ product_version: '1.26.0', health: down }), '1.26.0')
  assert.equal(peerVersion({ product_version: '', health: down }), null)
})

test('codes, keys and node ids are shown the way the CLI shows them', () => {
  assert.equal(formatCode('227515'), '227 515')
  assert.equal(formatCode('12345'), '12345')
  const key = 'ab12'.repeat(16)
  assert.equal(groupHex(key).split(' ').length, 16)
  assert.equal(shortKey(key), 'ab12ab12ab12ab12')
  assert.equal(shortNodeId('0123456789abcdef'), '0123456789ab')
  assert.equal(shortNodeId('node-a'), 'node-a')
  assert.equal(hostPort({ host: 'fd00::1', port: 36972 }), '[fd00::1]:36972')
  assert.equal(hostPort({ host: 'vps.example.com', port: 1 }), 'vps.example.com:1')
})

test('the address reads like vh peer link: host, host:port, [v6], [v6]:port or a bare v6', () => {
  assert.deepEqual(parseLinkTarget('vps.example.com', '36972'), { ok: true, value: { host: 'vps.example.com', port: 36972 } })
  assert.deepEqual(parseLinkTarget(' 10.0.0.5:40123 ', '36972'), { ok: true, value: { host: '10.0.0.5', port: 40123 } })
  assert.deepEqual(parseLinkTarget('[fd00::1]:9', ''), { ok: true, value: { host: 'fd00::1', port: 9 } })
  assert.deepEqual(parseLinkTarget('[fd00::1]', '36972'), { ok: true, value: { host: 'fd00::1', port: 36972 } })
  assert.deepEqual(parseLinkTarget('fd00::1', '7'), { ok: true, value: { host: 'fd00::1', port: 7 } })
  for (const [address, port] of [
    ['', '36972'],
    ['host:', '36972'],
    ['[fd00::1', '1'],
    ['[fd00::1]x', '1'],
    ['[nothex]:1', '1'],
    ['a b', '1'],
    ['user@host', '1'],
    ['host/path', '1'],
    ['host', ''],
    ['host', '0'],
    ['host', '65536'],
    ['host:99999', '1'],
    ['zz::1', '1'],
  ])
    assert.equal(parseLinkTarget(address, port).ok, false, `${address} ${port}`)
})

test('a key is optional, 64 hex digits, spaces and colons allowed', () => {
  assert.deepEqual(parseFingerprint(''), { ok: true, value: null })
  assert.deepEqual(parseFingerprint('  '), { ok: true, value: null })
  const key = 'AB12'.repeat(16)
  assert.deepEqual(parseFingerprint(groupHex(key)), { ok: true, value: key.toLowerCase() })
  assert.deepEqual(parseFingerprint(key.match(/../g)!.join(':')), { ok: true, value: key.toLowerCase() })
  assert.equal(parseFingerprint('ab12').ok, false)
  assert.equal(parseFingerprint('g'.repeat(64)).ok, false)
})

test('an attempt runs while connecting or awaiting approval, and every state has words', () => {
  assert.equal(linkFinished('connecting'), false)
  assert.equal(linkFinished('awaiting_approval'), false)
  for (const s of ['linked', 'denied', 'expired', 'failed', 'cancelled'] as const) assert.equal(linkFinished(s), true, s)
  assert.equal(ATTEMPT_TEXT.linked.tone, 'ok')
  assert.equal(ATTEMPT_TEXT.failed.tone, 'danger')
})

test('the countdown follows the node clock, and the codes keep the server’s order', () => {
  // The node is 480 s ahead of the browser: 600 s left by the browser would be 120 s by the node.
  assert.equal(secondsLeft(1_000_600, 1_000_000_000, 480_000), 120)
  assert.equal(secondsLeft(1_000_600, 1_000_700_000, 0), 0)
  assert.equal(secondsLeft(null, 0, 0), 0)
  assert.equal(formatRemaining(125.9), '2:05')
  assert.deepEqual(codeChoices({ code_choices: ['760001', '019337', '482913'] }), [
    { code: '760001', label: '760 001' },
    { code: '019337', label: '019 337' },
    { code: '482913', label: '482 913' },
  ])
})

test('a refusal keeps the server’s words and its code', () => {
  assert.deepEqual(refusalText({ message: 'only super admins may link servers', code: 'denied' }, 'x'), {
    message: 'only super admins may link servers',
    code: 'denied',
  })
  assert.deepEqual(refusalText({ message: '' }, 'The link was not started'), { message: 'The link was not started', code: null })
  assert.deepEqual(refusalText(null, 'fallback'), { message: 'fallback', code: null })
})
