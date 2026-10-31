// Pairing bootstrap (docs/reference/transfer-protocol.md §1.2): with capability `device.endpoints`, the answer to
// device.pairing.open also carries `endpoints` (§1.1 without node_id) and `server_spki_sha256`. The console shows the
// candidate addresses and a vaulthalla://pair link that prefills Vaulthalla Desktop's Add Node sheet; Desktop treats
// the link as untrusted input and the number match stays authoritative.
//
// The members are typed in the generated contract (Response<'device.pairing.open'>), but they end up in a URL, so they
// are still read through the guard below: a host that isn't a plain name or address never reaches the link.
// Pure: see pairLink.test.ts.

export interface EndpointCandidate {
  host: string
  port: number
  kind: string
  source: string
  interface?: string
}

export interface PairingEndpoints {
  port: number
  remote: boolean
  listening: boolean
  candidates: EndpointCandidate[]
}

export interface PairingBootstrap {
  endpoints: PairingEndpoints | null
  spki: string | null
  nodeId: string | null
}

type Obj = Record<string, unknown>
const isObj = (value: unknown): value is Obj => typeof value === 'object' && value !== null && !Array.isArray(value)
const isPort = (value: unknown): value is number => typeof value === 'number' && Number.isInteger(value) && value > 0 && value < 65536
const MAX_CANDIDATES = 32

const readCandidate = (value: unknown): EndpointCandidate | null => {
  if (!isObj(value) || typeof value.host !== 'string' || !value.host || !isPort(value.port)) return null
  // A host is a name or an address: nothing that could smuggle URL syntax into the link.
  if (!/^[A-Za-z0-9.:_%-]+$/.test(value.host.replace(/^\[(.*)\]$/, '$1'))) return null
  return {
    host: value.host.replace(/^\[(.*)\]$/, '$1'),
    port: value.port,
    kind: typeof value.kind === 'string' ? value.kind : 'lan',
    source: typeof value.source === 'string' ? value.source : 'interface',
    ...(typeof value.interface === 'string' ? { interface: value.interface } : {}),
  }
}

const SPKI = /^[0-9a-f]{64}$/

// The optional §1.2 members of a device.pairing.open answer; nulls when the server doesn't send them.
export const readPairingBootstrap = (opened: unknown): PairingBootstrap => {
  if (!isObj(opened)) return { endpoints: null, spki: null, nodeId: null }
  const raw = opened.endpoints
  let endpoints: PairingEndpoints | null = null
  if (isObj(raw) && Array.isArray(raw.candidates)) {
    const seen = new Set<string>()
    const candidates: EndpointCandidate[] = []
    for (const value of raw.candidates) {
      const candidate = readCandidate(value)
      if (!candidate) continue
      const key = `${candidate.host.toLowerCase()} ${candidate.port}`
      if (seen.has(key)) continue
      seen.add(key)
      candidates.push(candidate)
      if (candidates.length >= MAX_CANDIDATES) break
    }
    endpoints = {
      port: isPort(raw.port) ? raw.port : (candidates[0]?.port ?? 0),
      remote: raw.remote === true,
      listening: raw.listening !== false,
      candidates,
    }
  }
  const spki = typeof opened.server_spki_sha256 === 'string' ? opened.server_spki_sha256.toLowerCase() : ''
  const nodeId = typeof opened.node_id === 'string' ? opened.node_id : isObj(raw) && typeof raw.node_id === 'string' ? raw.node_id : ''
  return { endpoints, spki: SPKI.test(spki) ? spki : null, nodeId: nodeId || null }
}

// "host:port", with IPv6 addresses bracketed.
export const hostPort = (candidate: Pick<EndpointCandidate, 'host' | 'port'>) =>
  candidate.host.includes(':') ? `[${candidate.host}]:${candidate.port}` : `${candidate.host}:${candidate.port}`

// vaulthalla://pair?node=<node_id>&spki=<hex>&endpoints=<host:port,host:port,…> (§1.2): node and spki left out when
// unknown, the endpoint list percent-encoded as one value.
export const pairLink = ({ nodeId, spki, endpoints }: PairingBootstrap): string => {
  const params: string[] = []
  if (nodeId) params.push(`node=${encodeURIComponent(nodeId)}`)
  if (spki) params.push(`spki=${encodeURIComponent(spki)}`)
  const list = (endpoints?.candidates ?? []).map(hostPort)
  if (list.length) params.push(`endpoints=${encodeURIComponent(list.join(','))}`)
  return `vaulthalla://pair${params.length ? `?${params.join('&')}` : ''}`
}

export const KIND_LABELS: Record<string, string> = {
  loopback: 'This server',
  lan: 'Local network',
  vpn: 'VPN',
  wan: 'Internet',
  passthrough: 'Proxy',
}
