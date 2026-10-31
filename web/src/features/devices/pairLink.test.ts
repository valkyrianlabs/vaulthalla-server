import { test } from 'node:test'
import assert from 'node:assert/strict'
import { hostPort, pairLink, readPairingBootstrap } from './pairLink.ts'

const SPKI = 'AB'.repeat(32)

const opened = {
  window: { owner_id: 1, opened_at: 1, expires_at: 2 },
  server_time: 1,
  port: 36972,
  remote: true,
  server_spki_sha256: SPKI,
  endpoints: {
    port: 36972,
    remote: true,
    listening: true,
    candidates: [
      { host: '127.0.0.1', port: 36972, kind: 'loopback', source: 'interface', interface: 'lo' },
      { host: '::1', port: 36972, kind: 'loopback', source: 'interface', interface: 'lo' },
      { host: '10.0.0.11', port: 36972, kind: 'lan', source: 'interface', interface: 'enp3s0' },
      { host: 'vh-storage.local', port: 36972, kind: 'lan', source: 'mdns' },
      { host: 'VH-STORAGE.local', port: 36972, kind: 'lan', source: 'config' },
      { host: 'device.example.com', port: 443, kind: 'passthrough', source: 'config' },
      { host: 'evil/path?x=1', port: 1, kind: 'wan', source: 'config' },
      { host: 'no-port.example', kind: 'wan', source: 'config' },
    ],
  },
}

test('reads the optional §1.2 members, de-duplicating and dropping malformed candidates', () => {
  const boot = readPairingBootstrap(opened)
  assert.equal(boot.spki, SPKI.toLowerCase())
  assert.equal(boot.nodeId, null)
  assert.ok(boot.endpoints)
  assert.deepEqual(
    boot.endpoints.candidates.map(hostPort),
    ['127.0.0.1:36972', '[::1]:36972', '10.0.0.11:36972', 'vh-storage.local:36972', 'device.example.com:443'],
  )
  assert.equal(boot.endpoints.listening, true)
})

test('an older server answer has none of them', () => {
  assert.deepEqual(readPairingBootstrap({ window: {}, server_time: 1, port: 36972, remote: false }), { endpoints: null, spki: null, nodeId: null })
  assert.equal(readPairingBootstrap({ server_spki_sha256: 'not-hex' }).spki, null)
})

test('the link brackets IPv6, percent-encodes the list and omits a missing node id', () => {
  const link = pairLink(readPairingBootstrap(opened))
  assert.equal(
    link,
    `vaulthalla://pair?spki=${SPKI.toLowerCase()}&endpoints=` +
      encodeURIComponent('127.0.0.1:36972,[::1]:36972,10.0.0.11:36972,vh-storage.local:36972,device.example.com:443'),
  )
  const parsed = new URL(link)
  assert.equal(parsed.protocol, 'vaulthalla:')
  assert.equal(parsed.searchParams.get('endpoints')?.split(',')[1], '[::1]:36972')
  assert.equal(parsed.searchParams.has('node'), false)
  const withNode = pairLink({ ...readPairingBootstrap(opened), nodeId: 'node 1' })
  assert.match(withNode, /^vaulthalla:\/\/pair\?node=node%201&spki=/)
  assert.equal(pairLink({ endpoints: null, spki: null, nodeId: null }), 'vaulthalla://pair')
})

test('bracketed hosts from a server are normalized before re-bracketing', () => {
  const boot = readPairingBootstrap({ endpoints: { port: 1, candidates: [{ host: '[fd00::11]', port: 36972 }] } })
  assert.deepEqual(boot.endpoints?.candidates.map(hostPort), ['[fd00::11]:36972'])
})
