// Resumable upload engine (docs/reference/transfer-protocol.md §3): create a session, send each file's missing byte
// ranges as parts (bounded concurrency, SHA-256 Content-Digest, retries with backoff), re-sync from the server's
// status when views differ, then finish and wait for every file to commit. Files go one after another; parts of a
// file go up to min(3, part.max_in_flight) at a time.
//
// No DOM and no globals: HTTP, digests, sleeping, randomness, time and storage are injected, so engine.test.ts drives
// it against a fake server with `node --test`. The browser wiring is resumable.ts (+ http.ts).
import { assertPart, choosePartSize, coveredBytes, gapsOf, maxPartSize, mergeRanges, normalizeRanges, partsInFlight, planParts, type Part, type PartLimits, type Range } from './plan.ts'
import { backoffMs, classifyPart, MAX_ATTEMPTS, parseRetryAfter, RESYNC_AFTER_CONNECTION_FAILURES, transient } from './retry.ts'
import { errorText, isTerminal, readError, readPartAnswer, readSession, type FileError, type FileState, type SessionStatus } from './protocol.ts'
import type { ResumeStore } from './resumeStore.ts'

export interface HttpAnswer {
  status: number
  header: (name: string) => string | null
  // Parsed JSON, or null when the body isn't JSON.
  body: unknown
}

// No HTTP answer at all. Cancellation rejects with a DOMException named AbortError instead.
export class TransportError extends Error {
  kind: 'network' | 'timeout'
  constructor(kind: 'network' | 'timeout') {
    super(kind === 'timeout' ? 'The server stopped responding' : 'Network error while uploading')
    this.kind = kind
  }
}

export interface UploadHttp {
  request(method: 'GET' | 'POST' | 'DELETE', url: string, body: unknown, signal: AbortSignal | null): Promise<HttpAnswer>
  // `onProgress` gets the body bytes sent so far.
  putPart(url: string, data: ArrayBuffer, headers: Record<string, string>, signal: AbortSignal, onProgress: (loaded: number) => void): Promise<HttpAnswer>
}

export interface UploadItem {
  file: Blob
  // Full target path (vault path, or share-relative path on a share link).
  path: string
  name: string
  mime: string | null
  // resumeStore key, or null when this file can't be resumed after a reload.
  resumeKey: string | null
}

export type ItemResult = { item: UploadItem; ok: true; entry: unknown } | { item: UploadItem; ok: false; error: string; resumable: boolean }

export interface EngineOptions {
  http: UploadHttp
  // '' or '?share=1': appended to every /upload/sessions URL.
  query: string
  // Sent as vault_id; null on share links (the share session scopes the upload).
  vaultId: number | null
  store: ResumeStore | null
  digest: (data: ArrayBuffer) => Promise<string | null>
  sleep: (ms: number, signal: AbortSignal) => Promise<void>
  random: () => number
  now: () => number
  signal: AbortSignal
  onBytes: (delta: number) => void
  onFileSettled?: (result: ItemResult) => void
  onFinishing?: (finishing: boolean) => void
  // A file picked up an unfinished upload from an earlier page (bytes already on the server).
  onResume?: (item: UploadItem, storedBytes: number) => void
  maxSessionFiles?: number
}

export type BatchOutcome = { kind: 'unsupported' } | { kind: 'done'; results: ItemResult[] }

export const SESSIONS_PATH = '/upload/sessions'
const DEFAULT_SESSION_FILES = 500
const MAX_FINISH_ROUNDS = 4

// Control flow between the layers below.
class Restart extends Error {} // this file can't continue in its session: upload it again in a new one
class SessionGone extends Error {} // 404: the session expired or was cancelled elsewhere
class FileFatal extends Error {} // this file can never succeed as sent
class Exhausted extends Error {} // the server stayed unreachable or busy for MAX_ATTEMPTS tries

interface Tracked {
  item: UploadItem
  size: number
  fileId: string
  ranges: Range[]
  state: FileState
  error: FileError | null
  entry: unknown
  failures: number
  reported: number
  inflight: Map<number, number>
  settled: boolean
}

interface Session {
  uploadId: string
  part: PartLimits
  created: boolean
  files: Tracked[]
}

const abortError = () => new DOMException('Cancelled', 'AbortError')
const isAbort = (error: unknown) => error instanceof DOMException && error.name === 'AbortError'

const statusText = (status: number) => {
  if (status === 0) return 'The server couldn’t be reached.'
  if (status === 401) return 'Your session has ended. Sign in again to upload.'
  if (status === 403) return 'You don’t have permission to upload here.'
  if (status === 413) return 'This file is larger than the server accepts.'
  if (status === 507) return 'This upload is larger than the vault has room for.'
  return `Upload failed (HTTP ${status})`
}

const INTERRUPTED = 'The connection to the server keeps failing. Choose the same files again to resume.'

export const uploadBatch = async (items: UploadItem[], o: EngineOptions): Promise<BatchOutcome> => {
  const results = new Map<UploadItem, ItemResult>()
  const touched: Session[] = []
  const restarted = new Set<UploadItem>()
  const queue: UploadItem[] = []

  const url = (path: string, params: Record<string, string | number> = {}) => {
    const search = new URLSearchParams(o.query.replace(/^\?/, ''))
    for (const [key, value] of Object.entries(params)) search.set(key, String(value))
    const qs = search.toString()
    return qs ? `${path}?${qs}` : path
  }
  const sessionUrl = (s: Session, suffix = '') => `${SESSIONS_PATH}/${encodeURIComponent(s.uploadId)}${suffix}`
  const checkAbort = () => {
    if (o.signal.aborted) throw abortError()
  }
  const wait = (attempt: number, answer: HttpAnswer | null) => o.sleep(backoffMs(attempt, parseRetryAfter(answer?.header('retry-after'), o.now()), o.random()), o.signal)

  // Bytes shown for a file: what the server holds plus what's in flight, reported as deltas.
  const report = (t: Tracked) => {
    let value = t.state === 'receiving' ? coveredBytes(t.ranges) : t.size
    for (const loaded of t.inflight.values()) value += loaded
    value = Math.min(t.size, value)
    if (value !== t.reported) {
      o.onBytes(value - t.reported)
      t.reported = value
    }
  }

  const settle = (t: Tracked, result: ItemResult) => {
    if (t.settled) return
    t.settled = true
    results.set(t.item, result)
    if (t.item.resumeKey && !(result.ok === false && result.resumable)) o.store?.remove([t.item.resumeKey])
    o.onFileSettled?.(result)
  }
  const settleItem = (item: UploadItem, error: string, resumable = false) => {
    if (results.has(item)) return
    const result: ItemResult = { item, ok: false, error, resumable }
    results.set(item, result)
    if (item.resumeKey && !resumable) o.store?.remove([item.resumeKey])
    o.onFileSettled?.(result)
  }
  const settleByState = (t: Tracked) => {
    if (t.state === 'committed') {
      report(t)
      settle(t, { item: t.item, ok: true, entry: t.entry })
    } else if (t.state === 'failed') settle(t, { item: t.item, ok: false, error: errorText(t.error, 'The server couldn’t store this file.'), resumable: false })
  }
  const requeue = (t: Tracked) => {
    t.settled = true
    if (t.item.resumeKey) o.store?.remove([t.item.resumeKey])
    if (t.reported) o.onBytes(-t.reported)
    t.reported = 0
    if (restarted.has(t.item)) settleItem(t.item, 'The upload couldn’t be resumed on the server. Try again.')
    else {
      restarted.add(t.item)
      queue.push(t.item)
    }
  }

  // Applies a status/finish answer to the tracked files: the server's ranges are the truth.
  const apply = (s: Session, status: SessionStatus) => {
    for (const f of status.files) {
      const t = s.files.find(x => x.fileId === f.file_id)
      if (!t || t.settled) continue
      t.ranges = normalizeRanges(f.ranges, t.size)
      t.state = f.state
      t.error = f.error
      t.entry = f.entry
      report(t)
    }
  }

  // A JSON request with transport/busy retries. Answers with any status but a transient one.
  const call = async (method: 'GET' | 'POST', target: string, body?: unknown): Promise<HttpAnswer> => {
    for (let attempt = 0; ; attempt++) {
      checkAbort()
      let answer: HttpAnswer | null = null
      try {
        answer = await o.http.request(method, target, body, o.signal)
      } catch (error) {
        if (!(error instanceof TransportError)) throw error
      }
      if (answer && !transient(answer.status)) return answer
      if (attempt + 1 >= MAX_ATTEMPTS) throw new Exhausted(INTERRUPTED)
      await wait(attempt, answer)
    }
  }

  const refresh = async (s: Session) => {
    const answer = await call('GET', url(sessionUrl(s)))
    if (answer.status === 404) throw new SessionGone()
    const status = answer.status === 200 ? readSession(answer.body, { upload_id: s.uploadId, part: s.part }) : null
    if (!status) throw new FileFatal(errorText(readError(answer.body), statusText(answer.status)))
    s.part = status.part
    apply(s, status)
    return status
  }

  // One part, retried until stored. Returns 'resync' when the server's view must be read first.
  const sendPart = async (s: Session, t: Tracked, part: Part): Promise<'ok' | 'resync' | 'file_state'> => {
    assertPart(part, t.size, { min_bytes: s.part.min_bytes, max_bytes: maxPartSize(s.part) })
    const data = await t.item.file.slice(part.offset, part.offset + part.length).arrayBuffer()
    if (data.byteLength !== part.length) throw new FileFatal('The file changed while it was being uploaded.')
    const digest = await o.digest(data)
    const headers: Record<string, string> = { 'Content-Type': 'application/octet-stream' }
    if (digest) headers['Content-Digest'] = digest
    const target = url(sessionUrl(s, `/files/${encodeURIComponent(t.fileId)}`), { offset: part.offset })
    let connectionFailures = 0
    for (;;) {
      checkAbort()
      let answer: HttpAnswer | null = null
      try {
        answer = await o.http.putPart(target, data, headers, o.signal, loaded => {
          t.inflight.set(part.offset, Math.min(part.length, Math.max(0, loaded)))
          report(t)
        })
      } catch (error) {
        if (!(error instanceof TransportError)) {
          t.inflight.delete(part.offset)
          report(t)
          throw error
        }
      }
      const error = answer ? readError(answer.body) : null
      const verdict = classifyPart(answer?.status ?? 0, error?.code ?? null)
      if (verdict === 'stored') {
        const stored = readPartAnswer(answer?.body)
        t.ranges = mergeRanges(t.ranges, stored.ranges ?? [[part.offset, part.offset + part.length]], t.size)
        if (stored.state) t.state = stored.state
        t.failures = 0
        t.inflight.delete(part.offset)
        report(t)
        return 'ok'
      }
      t.inflight.delete(part.offset)
      report(t)
      if (verdict === 'gone') throw new SessionGone()
      if (verdict === 'fatal') throw new FileFatal(errorText(error, statusText(answer?.status ?? 0)))
      if (verdict === 'file_state') return 'file_state'
      if (++t.failures >= MAX_ATTEMPTS) throw new Exhausted(INTERRUPTED)
      if (verdict === 'resync') return 'resync'
      // Lost answers may still have stored the part: after a few, ask the server what it has before resending.
      if (!answer && ++connectionFailures >= RESYNC_AFTER_CONNECTION_FAILURES) {
        await wait(t.failures - 1, null)
        return 'resync'
      }
      await wait(t.failures - 1, answer)
    }
  }

  // Sends parts with bounded concurrency; stops launching on the first non-ok verdict and waits for the rest.
  const runParts = async (s: Session, t: Tracked, parts: Part[]): Promise<'ok' | 'resync' | 'file_state'> => {
    let next = 0
    let verdict: 'ok' | 'resync' | 'file_state' = 'ok'
    let failure: unknown = null
    const worker = async () => {
      while (next < parts.length && verdict === 'ok' && failure === null) {
        const part = parts[next++]
        try {
          const outcome = await sendPart(s, t, part)
          if (outcome !== 'ok' && verdict === 'ok') verdict = outcome
        } catch (error) {
          failure ??= error
        }
      }
    }
    await Promise.all(Array.from({ length: Math.min(partsInFlight(s.part), parts.length) }, worker))
    if (failure !== null) throw failure
    return verdict
  }

  // Every missing byte of one file, re-syncing with the server as needed.
  const sendFile = async (s: Session, t: Tracked) => {
    while (t.state === 'receiving') {
      const gaps = gapsOf(t.ranges, t.size)
      if (!gaps.length) return
      const plan = planParts(gaps, t.size, choosePartSize(s.part), s.part.min_bytes, maxPartSize(s.part))
      if (plan.unsendable) throw new Restart()
      const verdict = await runParts(s, t, plan.parts)
      if (verdict !== 'ok') await refresh(s)
    }
  }

  // POST finish until every one of our files is terminal. Returns the files that still have gaps.
  const finalize = async (s: Session): Promise<Tracked[]> => {
    o.onFinishing?.(true)
    try {
      for (;;) {
        const live = s.files.filter(t => !t.settled)
        if (!live.length) return []
        const answer = await call('POST', url(sessionUrl(s, '/finish')))
        if (answer.status === 404) throw new SessionGone()
        if (answer.status === 200 || answer.status === 202 || answer.status === 409) {
          const body = answer.body as { status?: unknown } | null
          const status = readSession(answer.body, { upload_id: s.uploadId, part: s.part }) ?? readSession(body?.status, { upload_id: s.uploadId, part: s.part })
          if (status) apply(s, status)
          for (const t of live) if (isTerminal(t.state)) settleByState(t)
          const missing = live.filter(t => !t.settled && t.state === 'receiving' && gapsOf(t.ranges, t.size).length > 0)
          if (missing.length) return missing
          if (live.every(t => t.settled)) return []
          if (answer.status === 200 && status && status.state === 'failed') {
            for (const t of live) settle(t, { item: t.item, ok: false, error: errorText(t.error, 'The server couldn’t store this file.'), resumable: false })
            return []
          }
          // Still sealing or committing (202), or our files are done but others in a resumed session aren't (409).
          await o.sleep(parseRetryAfter(answer.header('retry-after'), o.now()) ?? 1000, o.signal)
          continue
        }
        const message = errorText(readError(answer.body), statusText(answer.status))
        for (const t of live) settle(t, { item: t.item, ok: false, error: message, resumable: false })
        return []
      }
    } finally {
      o.onFinishing?.(false)
    }
  }

  const processSession = async (s: Session) => {
    try {
      for (let round = 0; ; round++) {
        const pending = s.files.filter(t => !t.settled && t.state === 'receiving')
        for (const t of pending) {
          if (t.settled) continue
          try {
            await sendFile(s, t)
          } catch (error) {
            if (error instanceof Restart) requeue(t)
            else if (error instanceof FileFatal) settle(t, { item: t.item, ok: false, error: error.message, resumable: false })
            else throw error
          }
          if (!t.settled && isTerminal(t.state)) settleByState(t)
        }
        const missing = await finalize(s)
        if (!missing.length) break
        if (round + 1 >= MAX_FINISH_ROUNDS) {
          for (const t of missing) settle(t, { item: t.item, ok: false, error: 'The server kept reporting missing bytes. Try again.', resumable: false })
          break
        }
      }
    } catch (error) {
      if (error instanceof SessionGone) {
        o.store?.removeUpload(s.uploadId)
        for (const t of s.files) if (!t.settled) requeue(t)
        return
      }
      throw error
    }
    // A session this batch opened whose files all ended, some of them failed: free the server's spool now.
    if (s.created && s.files.some(t => results.get(t.item)?.ok === false)) void o.http.request('DELETE', url(sessionUrl(s)), undefined, null).catch(() => undefined)
  }

  const track = (item: UploadItem, fileId: string): Tracked => ({
    item,
    size: item.file.size,
    fileId,
    ranges: [],
    state: 'receiving',
    error: null,
    entry: null,
    failures: 0,
    reported: 0,
    inflight: new Map(),
    settled: false,
  })

  // Files with a record from an earlier page: continue in their session when it still holds them.
  const resume = async () => {
    const groups = new Map<string, { item: UploadItem; fileId: string }[]>()
    for (const item of items) {
      const record = item.resumeKey ? o.store?.get(item.resumeKey) : null
      if (!record) {
        queue.push(item)
        continue
      }
      const group = groups.get(record.upload_id) ?? []
      group.push({ item, fileId: record.file_id })
      groups.set(record.upload_id, group)
    }
    for (const [uploadId, group] of groups) {
      const s: Session = { uploadId, part: { default_bytes: 0, min_bytes: 1, max_bytes: 1, max_in_flight: 1 }, created: false, files: [] }
      // Unreachable (Exhausted) fails the batch as resumable, keeping the records for the next try.
      const answer = await call('GET', url(sessionUrl(s)))
      const status = answer.status === 200 ? readSession(answer.body) : null
      if (!status || status.state === 'cancelled' || status.state === 'failed') {
        o.store?.removeUpload(uploadId)
        queue.push(...group.map(g => g.item))
        continue
      }
      s.part = status.part
      for (const { item, fileId } of group) {
        const f = status.files.find(x => x.file_id === fileId)
        if (!f || f.size !== item.file.size || f.state === 'failed') {
          if (item.resumeKey) o.store?.remove([item.resumeKey])
          queue.push(item)
          continue
        }
        const t = track(item, fileId)
        s.files.push(t)
        t.ranges = normalizeRanges(f.ranges, t.size)
        t.state = f.state
        t.entry = f.entry
        o.onResume?.(item, f.state === 'receiving' ? coveredBytes(t.ranges) : t.size)
        report(t)
        if (t.state === 'committed') settleByState(t)
      }
      if (s.files.length) touched.push(s)
    }
  }

  const create = async (chunk: UploadItem[], allowUnsupported: boolean): Promise<Session | 'unsupported' | null> => {
    const files = chunk.map((item, index) => ({ file_id: `f${index}`, path: item.path, size: item.file.size, mime_type: item.mime, duplicate_policy: 'reject' }))
    let answer: HttpAnswer
    try {
      answer = await call('POST', url(SESSIONS_PATH), o.vaultId === null ? { files } : { vault_id: o.vaultId, files })
    } catch (error) {
      if (!(error instanceof Exhausted)) throw error
      for (const item of chunk) settleItem(item, 'The server couldn’t be reached. Try again.')
      return null
    }
    const error = readError(answer.body)
    // A daemon without /upload/sessions answers its generic plain 404 (or 405): use the whole-file flow there.
    if (allowUnsupported && ((answer.status === 404 && !error) || answer.status === 405)) return 'unsupported'
    const status = answer.status === 201 || answer.status === 200 ? readSession(answer.body) : null
    if (!status) {
      const message = answer.status === 201 || answer.status === 200 ? 'The server did not open an upload session' : errorText(error, statusText(answer.status))
      for (const item of chunk) settleItem(item, message)
      return null
    }
    const s: Session = { uploadId: status.upload_id, part: status.part, created: true, files: chunk.map((item, index) => track(item, files[index].file_id)) }
    apply(s, status)
    o.store?.put(
      s.files.filter(t => t.item.resumeKey).map(t => [t.item.resumeKey as string, { upload_id: s.uploadId, file_id: t.fileId, expires_at: status.expires_at }]),
    )
    touched.push(s)
    return s
  }

  try {
    await resume()
    for (const s of [...touched]) await processSession(s)
    const limit = Math.max(1, o.maxSessionFiles ?? DEFAULT_SESSION_FILES)
    let first = touched.length === 0
    while (queue.length) {
      const chunk = queue.splice(0, limit)
      const s = await create(chunk, first)
      if (s === 'unsupported') return { kind: 'unsupported' }
      first = false
      if (s) await processSession(s)
    }
  } catch (error) {
    if (isAbort(error) || o.signal.aborted) {
      // Cancelled: discard what this batch staged; nothing is left to resume.
      for (const s of touched) {
        if (s.files.every(t => t.settled)) continue
        o.store?.removeUpload(s.uploadId)
        void o.http.request('DELETE', url(sessionUrl(s)), undefined, null).catch(() => undefined)
      }
      throw abortError()
    }
    const message = error instanceof Exhausted ? error.message : error instanceof Error ? error.message : String(error)
    const resumable = error instanceof Exhausted
    for (const s of touched) for (const t of s.files) if (!t.settled) settle(t, { item: t.item, ok: false, error: message, resumable })
    for (const item of items) settleItem(item, message, resumable)
  }
  for (const item of items) if (!results.has(item)) settleItem(item, 'The upload did not finish.')
  return { kind: 'done', results: items.map(item => results.get(item) as ItemResult) }
}
