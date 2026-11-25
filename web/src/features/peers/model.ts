// Linked servers (design/peers/link.md; ws peer.*, ops::peers): the pure parts of the page. What a link's health reads
// as, what an attempt's state reads as, the address and key an admin types, and the three-code choice. Pure: see
// model.test.ts.
import type { Response } from '@/lib/ws/client'

export type LinkedPeer = Response<'peer.list'>['peers'][number]
export type PeerHealth = LinkedPeer['health']
export type PeerWindow = Response<'peer.pairing.open'>
export type PendingLink = Response<'peer.pairing.pending'>['requests'][number]
export type LinkAttempt = Response<'peer.link.status'>['link']
export type LinkState = LinkAttempt['state']
export type Tone = 'ok' | 'info' | 'warn' | 'danger' | 'neutral' | 'unknown'

// Every read a change to a link can affect.
export const PEER_READS = ['peer.list'] as const

// "227515" → "227 515", as `vh peer` and Desktop show it. Anything that isn't six digits is shown as sent.
export const formatCode = (code: string) => (/^\d{6}$/.test(code) ? `${code.slice(0, 3)} ${code.slice(3)}` : code)

// A key (SPKI SHA-256, 64 hex) in groups of four, for comparing by eye.
export const groupHex = (hex: string) => hex.match(/.{1,4}/g)?.join(' ') ?? hex

// The first 16 hex digits of a key: what audit lines and `vh peer list` show (Record::shortId), and 8+ of them name a
// peer in `vh peer`.
export const shortKey = (hex: string) => hex.slice(0, 16)

// Node ids are long; 12 characters tell two servers apart. The full id is in the cell's title.
export const shortNodeId = (nodeId: string) => (nodeId.length > 12 ? nodeId.slice(0, 12) : nodeId)

export const peerLabel = (peer: { name: string }) => peer.name || 'Unnamed server'

// Live links first (newest first), unlinked ones after.
export const byStatus = (a: LinkedPeer, b: LinkedPeer) => Number(a.revoked) - Number(b.revoked) || b.linked_at - a.linked_at

// `host:port`, IPv6 bracketed (peer::toString).
export const hostPort = (e: { host: string; port: number }) => (e.host.includes(':') ? `[${e.host}]:${e.port}` : `${e.host}:${e.port}`)

export interface HealthText {
  label: string
  tone: Tone
  // Short facts after the label: since when, who dialled, round trip, the peer's version; or why it is down.
  facts: string[]
}

// A link's health in words (peer.list `health`). Connected only after peer.hello answered (the server's rule), never
// guessed from last_seen_at.
export const healthText = (peer: Pick<LinkedPeer, 'revoked' | 'revoked_at' | 'health'>, when: (unix: number) => string): HealthText => {
  if (peer.revoked) return { label: 'Unlinked', tone: 'neutral', facts: peer.revoked_at ? [when(peer.revoked_at)] : [] }
  const h = peer.health
  if (h.connected) {
    const facts: string[] = []
    if (h.since) facts.push(`since ${when(h.since)}`)
    if (h.dialed_by) facts.push(h.dialed_by === 'this_server' ? 'this server dialled' : 'it dialled')
    if (h.rtt_ms !== null && h.rtt_ms !== undefined) facts.push(`${h.rtt_ms} ms`)
    if (h.peer_version) facts.push(`Vaulthalla ${h.peer_version}`)
    if (h.protocol_compatible === false)
      return { label: 'Connected, other protocol', tone: 'warn', facts: [...facts, 'upgrade one of them'] }
    return { label: 'Connected', tone: 'ok', facts }
  }
  const facts: string[] = []
  if (h.last_error) facts.push(h.last_error)
  if (h.next_attempt_at) facts.push(`next try ${when(h.next_attempt_at)}`)
  if (!facts.length) return { label: 'Not connected', tone: 'unknown', facts: ['waiting for a connection'] }
  return { label: 'Not connected', tone: h.last_error ? 'danger' : 'warn', facts }
}

// The version a peer runs: the live hello's when connected, else what it last told this server.
export const peerVersion = (peer: Pick<LinkedPeer, 'product_version' | 'health'>) => peer.health.peer_version || peer.product_version || null

// ---- Link a server: what an admin types

export const DEFAULT_DEVICE_PORT = 36972

export type Parsed<T> = { ok: true; value: T } | { ok: false; error: string }

const HOST_FORBIDDEN = /[\s/@?#]/
const IPV6 = /^[0-9a-f:.]+$/i

const validHost = (host: string) =>
  host.length > 0 && host.length <= 253 && !HOST_FORBIDDEN.test(host) && [...host].every(c => c > ' ' && c < '\x7f')

const parsePort = (text: string): number | null => {
  if (!/^\d{1,5}$/.test(text)) return null
  const n = Number(text)
  return n >= 1 && n <= 65535 ? n : null
}

// The other server's address, as peer::parseAddress reads `vh peer link <address>`: host, host:port, [v6], [v6]:port or
// a bare IPv6 literal. A port in the address wins over the Port field, which is used otherwise.
export const parseLinkTarget = (addressText: string, portText: string): Parsed<{ host: string; port: number }> => {
  const text = addressText.trim()
  if (!text) return { ok: false, error: 'Enter the other server’s address.' }
  let host = text
  let port: string | null = null
  if (text.startsWith('[')) {
    const close = text.indexOf(']')
    if (close < 0) return { ok: false, error: 'An IPv6 address in brackets needs its closing bracket.' }
    host = text.slice(1, close)
    const rest = text.slice(close + 1)
    if (rest) {
      if (!rest.startsWith(':') || rest.length < 2) return { ok: false, error: 'Write [IPv6]:port, or leave the port out.' }
      port = rest.slice(1)
    }
    if (!IPV6.test(host) || !host.includes(':')) return { ok: false, error: 'That is not an IPv6 address.' }
  } else {
    const first = text.indexOf(':')
    if (first >= 0) {
      if (text.indexOf(':', first + 1) >= 0) {
        // A bare IPv6 literal: no port.
        if (!IPV6.test(text)) return { ok: false, error: 'That is not an IPv6 address.' }
      } else {
        host = text.slice(0, first)
        port = text.slice(first + 1)
        if (!port) return { ok: false, error: 'Write host:port, or leave the port out.' }
      }
    }
  }
  if (!validHost(host)) return { ok: false, error: 'A host is 1-253 characters with no spaces, /, @, ? or #.' }
  const portSource = port ?? portText.trim()
  if (!portSource) return { ok: false, error: 'Enter the other server’s port.' }
  const value = parsePort(portSource)
  if (value === null) return { ok: false, error: 'A port is a number from 1 to 65535.' }
  return { ok: true, value: { host, port: value } }
}

// An optional key (expect_spki), as the server reads it: 64 hex digits, spaces or colons between them allowed. Empty
// means none (trust on first use, closed by the code).
export const parseFingerprint = (text: string): Parsed<string | null> => {
  const hex = text.replace(/[\s:]/g, '').toLowerCase()
  if (!hex) return { ok: true, value: null }
  if (!/^[0-9a-f]+$/.test(hex)) return { ok: false, error: 'A key is hex digits (0-9, a-f); spaces and colons are fine.' }
  if (hex.length !== 64) return { ok: false, error: `A key is 64 hex digits; this has ${hex.length}.` }
  return { ok: true, value: hex }
}

// ---- Link a server: how the attempt stands

export const linkFinished = (state: LinkState) => state !== 'connecting' && state !== 'awaiting_approval'

export interface AttemptText {
  label: string
  tone: Tone
}

export const ATTEMPT_TEXT: Readonly<Record<LinkState, AttemptText>> = {
  connecting: { label: 'Connecting', tone: 'info' },
  awaiting_approval: { label: 'Waiting for approval', tone: 'info' },
  linked: { label: 'Linked', tone: 'ok' },
  denied: { label: 'Declined', tone: 'danger' },
  expired: { label: 'Expired', tone: 'warn' },
  failed: { label: 'Failed', tone: 'danger' },
  cancelled: { label: 'Cancelled', tone: 'neutral' },
}

// ---- Accept a link: the window's countdown and the three codes

// Seconds left in a window by the node's clock: `skewMs` is the node's clock minus the browser's, from the latest answer
// that carried server_time (never the browser's clock alone).
export const secondsLeft = (expiresAt: number | null | undefined, browserNowMs: number, skewMs: number) =>
  expiresAt ? Math.max(0, expiresAt - (browserNowMs + skewMs) / 1000) : 0

export const formatRemaining = (seconds: number) => {
  const s = Math.max(0, Math.floor(seconds))
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`
}

// The code buttons of a request, in the server's (random) order: what is sent is the digits, what is shown is grouped.
export const codeChoices = (request: Pick<PendingLink, 'code_choices'>) =>
  request.code_choices.map(code => ({ code, label: formatCode(code) }))

// ---- refusals

// A refusal as the page shows it: the server's own words and its data.code, never swallowed.
export const refusalText = (error: { message?: string; code?: string } | null | undefined, fallback: string) => {
  const message = error?.message?.trim() || fallback
  return error?.code ? { message, code: error.code } : { message, code: null }
}
