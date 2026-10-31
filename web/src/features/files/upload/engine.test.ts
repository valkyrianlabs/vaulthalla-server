// The engine against an in-memory server that follows transfer-protocol.md §3, with injectable faults.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { TransportError, uploadBatch, type EngineOptions, type HttpAnswer, type UploadHttp, type UploadItem } from './engine.ts'
import { contentDigest } from './digest.ts'
import { gapsOf, mergeRanges, REQUEST_BODY_LIMIT, type Range } from './plan.ts'
import { createResumeStore, resumeKey, type KeyValueStorage } from './resumeStore.ts'

interface FakeFile {
  file_id: string
  path: string
  size: number
  bytes: Uint8Array
  ranges: Range[]
  parts: Map<number, { length: number; sha: string }>
  state: 'receiving' | 'sealing' | 'committing' | 'committed' | 'failed'
  error: { code: string; message: string } | null
}
interface FakeSession {
  upload_id: string
  files: FakeFile[]
  cancelled: boolean
}

interface Faults {
  // Answer status (with optional code / Retry-After) instead of handling the n-th part request (1-based).
  partAnswers?: Map<number, { status: number; code?: string; retryAfter?: string }>
  // Throw a network error on these part requests without storing.
  dropBefore?: Set<number>
  // Store the part, then lose the answer.
  dropAfter?: Set<number>
  // Answers before finish reports complete.
  finishPending?: number
  // A plain 404 on create (a daemon without /upload/sessions).
  legacy?: boolean
  // Fail this file at commit with this code.
  commitError?: { path: string; code: string }
}

const PART = { default_bytes: 4096, min_bytes: 1024, max_bytes: 4096, max_in_flight: 4 }

const json = (status: number, body: unknown, headers: Record<string, string> = {}): HttpAnswer => ({
  status,
  header: name => headers[name.toLowerCase()] ?? null,
  body,
})
const fail = (status: number, code: string, headers: Record<string, string> = {}) => json(status, { error: { code, message: code } }, headers)

const fakeServer = (faults: Faults = {}, part = PART) => {
  const sessions = new Map<string, FakeSession>()
  const log: { method: string; url: string; length?: number; digest?: string | null }[] = []
  let partRequests = 0
  let finishCalls = 0
  let inFlight = 0
  let maxInFlight = 0
  let nextId = 1

  const status = (s: FakeSession) => ({
    upload_id: s.upload_id,
    state: s.cancelled ? 'cancelled' : s.files.every(f => f.state === 'committed' || f.state === 'failed') ? 'complete' : 'open',
    expires_at: 4_000_000_000,
    part,
    files: s.files.map(f => ({
      file_id: f.file_id,
      path: f.path,
      size: f.size,
      state: f.state,
      received_bytes: f.ranges.reduce((n, [a, b]) => n + b - a, 0),
      ranges: f.ranges,
      error: f.error,
      entry: f.state === 'committed' ? { path: f.path } : null,
    })),
  })

  const seal = (f: FakeFile) => {
    if (f.state === 'receiving' && gapsOf(f.ranges, f.size).length === 0) f.state = 'committing'
  }

  const http: UploadHttp = {
    async request(method, url, body) {
      log.push({ method, url })
      const [path] = url.split('?')
      const parts = path.split('/').filter(Boolean) // upload, sessions, id, finish
      if (method === 'POST' && parts.length === 2) {
        if (faults.legacy) return json(404, null)
        const payload = body as { files: { file_id: string; path: string; size: number }[] }
        const s: FakeSession = {
          upload_id: `u${nextId++}`,
          cancelled: false,
          files: payload.files.map(f => ({ ...f, bytes: new Uint8Array(f.size), ranges: [], parts: new Map(), state: 'receiving', error: null })),
        }
        for (const f of s.files) seal(f)
        sessions.set(s.upload_id, s)
        return json(201, { ...status(s), resumable: true })
      }
      const s = sessions.get(decodeURIComponent(parts[2]))
      if (!s || s.cancelled) return fail(404, 'not_found')
      if (method === 'GET') return json(200, status(s))
      if (method === 'DELETE') {
        s.cancelled = true
        return json(204, null)
      }
      if (method === 'POST' && parts[3] === 'finish') {
        finishCalls++
        if (s.files.some(f => f.state === 'receiving')) return json(409, { error: { code: 'incomplete', message: 'gaps' }, ...status(s) })
        if (finishCalls <= (faults.finishPending ?? 0)) return json(202, { state: 'finalizing', files: status(s).files }, { 'retry-after': '1' })
        for (const f of s.files) {
          if (f.state !== 'committing') continue
          if (faults.commitError?.path === f.path) {
            f.state = 'failed'
            f.error = { code: faults.commitError.code, message: '' }
          } else f.state = 'committed'
        }
        const st = status(s)
        return json(200, { state: s.files.some(f => f.state === 'failed') ? 'failed' : 'complete', files: st.files })
      }
      return fail(400, 'bad_request')
    },

    async putPart(url, data, headers, _signal, onProgress) {
      const n = ++partRequests
      const [path, qs] = url.split('?')
      const offset = Number(new URLSearchParams(qs).get('offset'))
      log.push({ method: 'PUT', url, length: data.byteLength, digest: headers['Content-Digest'] ?? null })
      assert.ok(data.byteLength < REQUEST_BODY_LIMIT)
      inFlight++
      maxInFlight = Math.max(maxInFlight, inFlight)
      try {
        await new Promise(resolve => setTimeout(resolve, 1))
        if (faults.dropBefore?.has(n)) throw new TransportError('network')
        const scripted = faults.partAnswers?.get(n)
        if (scripted) return fail(scripted.status, scripted.code ?? 'x', scripted.retryAfter ? { 'retry-after': scripted.retryAfter } : {})
        const segs = path.split('/').filter(Boolean)
        const s = sessions.get(decodeURIComponent(segs[2]))
        if (!s || s.cancelled) return fail(404, 'not_found')
        const f = s.files.find(x => x.file_id === decodeURIComponent(segs[4]))
        if (!f) return fail(404, 'not_found')
        const length = data.byteLength
        if (f.state !== 'receiving') return fail(409, 'file_state')
        if (offset + length > f.size || length > part.max_bytes || (length < part.min_bytes && offset + length !== f.size) || length === 0) return fail(400, 'bad_request')
        const bytes = new Uint8Array(data)
        const sha = createHash('sha256').update(bytes).digest('hex')
        const same = f.parts.get(offset)
        if (same && same.length === length) {
          if (same.sha !== sha) return fail(409, 'part_conflict')
        } else {
          if (f.ranges.some(([a, b]) => offset < b && a < offset + length)) return fail(409, 'part_overlap')
          if (headers['Content-Digest'] && headers['Content-Digest'] !== `sha-256=:${createHash('sha256').update(bytes).digest('base64')}:`) return fail(400, 'digest_mismatch')
          f.bytes.set(bytes, offset)
          f.parts.set(offset, { length, sha })
          f.ranges = mergeRanges(f.ranges, [[offset, offset + length]], f.size)
          seal(f)
        }
        onProgress(length)
        if (faults.dropAfter?.has(n)) throw new TransportError('network')
        return json(200, { file_id: f.file_id, offset, length, sha256: sha, received_bytes: 0, ranges: f.ranges, state: f.state })
      } finally {
        inFlight--
      }
    },
  }
  return { http, sessions, log, stats: () => ({ partRequests, finishCalls, maxInFlight }) }
}

const memory = (): KeyValueStorage => {
  const data = new Map<string, string>()
  return { getItem: k => data.get(k) ?? null, setItem: (k, v) => void data.set(k, v), removeItem: k => void data.delete(k) }
}

const blob = (size: number, seed = 1) => {
  const bytes = new Uint8Array(size)
  let x = seed
  for (let i = 0; i < size; i++) bytes[i] = (x = (x * 1103515245 + 12345) & 0x7fffffff) & 0xff
  return { blob: new Blob([bytes]), bytes }
}

const item = (path: string, size: number, seed = 1): UploadItem & { bytes: Uint8Array } => {
  const { blob: file, bytes } = blob(size, seed)
  return { file, bytes, path, name: path.split('/').at(-1) as string, mime: null, resumeKey: resumeKey('vault:1', path, size, 0) }
}

const options = (http: UploadHttp, over: Partial<EngineOptions> = {}) => {
  const sleeps: number[] = []
  let progress = 0
  const opts: EngineOptions = {
    http,
    query: '',
    vaultId: 1,
    store: createResumeStore(memory, () => 0),
    digest: data => contentDigest(data),
    sleep: async ms => void sleeps.push(ms),
    random: () => 0.5,
    now: () => 0,
    signal: new AbortController().signal,
    onBytes: delta => (progress += delta),
    ...over,
  }
  return { opts, sleeps, progress: () => progress }
}

test('uploads every file in legal parts with digests, bounded concurrency and exact bytes', async () => {
  const server = fakeServer()
  const a = item('/docs/a.bin', 4096 * 5 + 77, 1)
  const b = item('/docs/b.bin', 300, 2)
  const z = item('/docs/empty', 0, 3)
  const { opts, progress } = options(server.http)
  const outcome = await uploadBatch([a, b, z], opts)
  assert.equal(outcome.kind, 'done')
  if (outcome.kind !== 'done') return
  assert.deepEqual(outcome.results.map(r => r.ok), [true, true, true])
  const s = [...server.sessions.values()][0]
  assert.deepEqual(s.files[0].bytes, a.bytes)
  assert.deepEqual(s.files[1].bytes, b.bytes)
  assert.equal(s.files[2].state, 'committed')
  const puts = server.log.filter(e => e.method === 'PUT')
  assert.equal(puts.length, 7)
  assert.ok(puts.every(p => /^sha-256=:[A-Za-z0-9+/]+=*:$/.test(p.digest ?? '')))
  assert.ok(server.stats().maxInFlight <= 3)
  assert.equal(progress(), a.bytes.length + b.bytes.length)
  // Create carries the §3.1 body.
  assert.ok(server.log[0].url === '/upload/sessions')
})

test('share links add ?share=1 to every URL and send no vault_id', async () => {
  const server = fakeServer()
  const seen: unknown[] = []
  const http: UploadHttp = {
    request: (method, url, body, signal) => {
      if (method === 'POST' && url.startsWith('/upload/sessions?')) seen.push(body)
      return server.http.request(method, url, body, signal)
    },
    putPart: server.http.putPart,
  }
  const { opts } = options(http, { query: '?share=1', vaultId: null })
  const outcome = await uploadBatch([item('/a.bin', 5000)], opts)
  assert.equal(outcome.kind, 'done')
  assert.ok(server.log.every(e => e.url.includes('share=1')), JSON.stringify(server.log.map(e => e.url)))
  assert.ok(server.log.some(e => /\?share=1&offset=\d+$/.test(e.url)))
  assert.equal((seen[0] as { vault_id?: number }).vault_id, undefined)
})

test('an older daemon (plain 404 on create) means unsupported, with nothing sent', async () => {
  const server = fakeServer({ legacy: true })
  const { opts } = options(server.http)
  const outcome = await uploadBatch([item('/a', 10)], opts)
  assert.deepEqual(outcome, { kind: 'unsupported' })
  assert.equal(server.log.length, 1)
})

test('busy and rate-limited parts are retried, honoring Retry-After', async () => {
  const server = fakeServer({
    partAnswers: new Map([
      [1, { status: 503, code: 'busy', retryAfter: '7' }],
      [2, { status: 429, code: 'too_many_parts_in_flight', retryAfter: '2' }],
      [3, { status: 500, code: 'internal' }],
    ]),
  })
  const { opts, sleeps } = options(server.http)
  const a = item('/a', 4096 * 3)
  const outcome = await uploadBatch([a], opts)
  assert.equal(outcome.kind === 'done' && outcome.results[0].ok, true)
  assert.deepEqual([...server.sessions.values()][0].files[0].bytes, a.bytes)
  assert.ok(sleeps.some(ms => ms >= 7000), `slept ${sleeps}`)
  assert.ok(sleeps.some(ms => ms >= 2000 && ms < 7000), `slept ${sleeps}`)
})

test('lost answers lead to a status read and only the gaps are sent again', async () => {
  // Part 1 stored but its answer lost twice over (the same part resent is idempotent), part 2 never arrived.
  const server = fakeServer({ dropAfter: new Set([1]), dropBefore: new Set([2, 4, 5]) })
  const a = item('/a', 4096 * 4)
  const { opts, progress } = options(server.http)
  const outcome = await uploadBatch([a], opts)
  assert.equal(outcome.kind === 'done' && outcome.results[0].ok, true)
  assert.deepEqual([...server.sessions.values()][0].files[0].bytes, a.bytes)
  assert.ok(server.log.some(e => e.method === 'GET'), 'read the status')
  assert.equal(progress(), a.bytes.length)
})

test('409 part_overlap re-syncs from the status', async () => {
  const server = fakeServer({ partAnswers: new Map([[2, { status: 409, code: 'part_overlap' }]]) })
  const a = item('/a', 4096 * 3)
  const { opts } = options(server.http)
  const outcome = await uploadBatch([a], opts)
  assert.equal(outcome.kind === 'done' && outcome.results[0].ok, true)
  assert.ok(server.log.some(e => e.method === 'GET'))
})

test('finish 202 is polled with Retry-After until complete', async () => {
  const server = fakeServer({ finishPending: 2 })
  const { opts, sleeps } = options(server.http)
  const finishing: boolean[] = []
  const outcome = await uploadBatch([item('/a', 100)], { ...opts, onFinishing: f => finishing.push(f) })
  assert.equal(outcome.kind === 'done' && outcome.results[0].ok, true)
  assert.equal(server.stats().finishCalls, 3)
  assert.deepEqual(sleeps, [1000, 1000])
  assert.deepEqual(finishing, [true, false])
})

test('a file failing at commit is reported per file; the others succeed', async () => {
  const server = fakeServer({ commitError: { path: '/b', code: 'key_rotated' } })
  const { opts } = options(server.http)
  const outcome = await uploadBatch([item('/a', 100), item('/b', 100, 2)], opts)
  assert.equal(outcome.kind, 'done')
  if (outcome.kind !== 'done') return
  assert.equal(outcome.results[0].ok, true)
  const b = outcome.results[1]
  assert.equal(b.ok, false)
  assert.match(b.ok ? '' : b.error, /Upload the file again/)
})

test('a refused create fails every file with the server reason', async () => {
  const server = fakeServer()
  const http: UploadHttp = {
    request: async (method, url, body, signal) =>
      method === 'POST' && url === '/upload/sessions' ? fail(507, 'insufficient_storage') : server.http.request(method, url, body, signal),
    putPart: server.http.putPart,
  }
  const { opts } = options(http)
  const outcome = await uploadBatch([item('/a', 10), item('/b', 10)], opts)
  assert.equal(outcome.kind, 'done')
  if (outcome.kind !== 'done') return
  assert.ok(outcome.results.every(r => !r.ok && /room/.test(r.error)))
})

test('after an interruption, the same file resumes in its session and sends only what is missing', async () => {
  const server = fakeServer({ dropBefore: new Set(Array.from({ length: 40 }, (_, i) => i + 3)) })
  const storage = memory()
  const a = item('/big', 4096 * 6)
  const first = options(server.http, { store: createResumeStore(() => storage, () => 0) })
  const outcome = await uploadBatch([a], first.opts)
  assert.equal(outcome.kind, 'done')
  if (outcome.kind !== 'done') return
  const failed = outcome.results[0]
  assert.equal(failed.ok, false)
  assert.equal(!failed.ok && failed.resumable, true)
  assert.match(!failed.ok ? failed.error : '', /resume/)
  const stored = [...server.sessions.values()][0].files[0].ranges
  assert.ok(stored.length > 0)

  // "Reload": a new batch with a new Blob of the same file and the same store.
  const putsBefore = server.log.filter(e => e.method === 'PUT').length
  const second = options(fakeServerAgain(server), { store: createResumeStore(() => storage, () => 0) })
  let resumedBytes = -1
  const again = item('/big', 4096 * 6)
  const result = await uploadBatch([again], { ...second.opts, onResume: (_i, bytes) => (resumedBytes = bytes) })
  assert.equal(result.kind === 'done' && result.results[0].ok, true)
  assert.equal(server.sessions.size, 1, 'no new session')
  assert.equal(resumedBytes, 4096 * 2)
  const resent = server.log.slice(putsBefore + 0).filter(e => e.method === 'PUT' && e.length)
  assert.ok(resent.every(e => !/offset=(0|4096)$/.test(e.url)), 'stored parts not resent')
  assert.deepEqual([...server.sessions.values()][0].files[0].bytes, again.bytes)
  assert.equal(second.progress(), 4096 * 6)
})

// The same server state with the faults cleared (the network came back).
function fakeServerAgain(server: ReturnType<typeof fakeServer>): UploadHttp {
  const healthy = fakeServer()
  for (const [id, s] of server.sessions) healthy.sessions.set(id, s)
  return {
    request: async (m, u, b, sig) => {
      server.log.push({ method: m, url: u })
      return healthy.http.request(m, u, b, sig)
    },
    putPart: async (u, d, h, sig, p) => {
      server.log.push({ method: 'PUT', url: u, length: d.byteLength })
      return healthy.http.putPart(u, d, h, sig, p)
    },
  }
}

test('a stale record (session gone) starts a new session', async () => {
  const server = fakeServer()
  const storage = memory()
  const store = createResumeStore(() => storage, () => 0)
  const a = item('/a', 5000)
  store.put([[a.resumeKey as string, { upload_id: 'gone', file_id: 'f0', expires_at: null }]])
  const { opts } = options(server.http, { store })
  const outcome = await uploadBatch([a], opts)
  assert.equal(outcome.kind === 'done' && outcome.results[0].ok, true)
  assert.equal(store.get(a.resumeKey as string), null, 'record cleared after commit')
})

test('cancelling aborts and deletes the session', async () => {
  const server = fakeServer()
  const controller = new AbortController()
  const http: UploadHttp = {
    request: server.http.request,
    putPart: async () => {
      controller.abort()
      throw new DOMException('Cancelled', 'AbortError')
    },
  }
  const storage = memory()
  const store = createResumeStore(() => storage, () => 0)
  const a = item('/a', 5000)
  const { opts } = options(http, { signal: controller.signal, store })
  await assert.rejects(uploadBatch([a], opts), (e: unknown) => e instanceof DOMException && e.name === 'AbortError')
  assert.ok(server.log.some(e => e.method === 'DELETE'))
  assert.equal(store.get(a.resumeKey as string), null)
})
