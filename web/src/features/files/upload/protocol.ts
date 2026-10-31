// Wire shapes of /upload/sessions (transfer-protocol.md §3) and narrow readers for them. HTTP answers aren't covered by
// the ws contract, so every field is checked here instead of trusted. Pure; see engine.test.ts.
import type { PartLimits, Range } from './plan.ts'

export type SessionState = 'open' | 'finalizing' | 'complete' | 'failed' | 'cancelled'
export type FileState = 'receiving' | 'sealing' | 'committing' | 'committed' | 'failed'

export interface FileError {
  code: string
  message: string
}

export interface FileStatus {
  file_id: string
  path: string
  size: number
  state: FileState
  received_bytes: number
  ranges: Range[]
  error: FileError | null
  entry: unknown
}

export interface SessionStatus {
  upload_id: string
  state: SessionState
  expires_at: number | null
  part: PartLimits
  files: FileStatus[]
}

export interface PartAnswer {
  ranges: Range[] | null
  state: FileState | null
}

type Obj = Record<string, unknown>
const isObj = (value: unknown): value is Obj => typeof value === 'object' && value !== null && !Array.isArray(value)
const num = (value: unknown, fallback = 0) => (typeof value === 'number' && Number.isFinite(value) ? value : fallback)
const str = (value: unknown, fallback = '') => (typeof value === 'string' ? value : fallback)

const FILE_STATES: readonly FileState[] = ['receiving', 'sealing', 'committing', 'committed', 'failed']
const SESSION_STATES: readonly SessionState[] = ['open', 'finalizing', 'complete', 'failed', 'cancelled']

export const isTerminal = (state: FileState) => state === 'committed' || state === 'failed'

const readRanges = (value: unknown): Range[] | null =>
  Array.isArray(value) ?
    value.filter((r): r is [number, number] => Array.isArray(r) && r.length === 2 && typeof r[0] === 'number' && typeof r[1] === 'number')
  : null

const readFileState = (value: unknown): FileState | null => (FILE_STATES.includes(value as FileState) ? (value as FileState) : null)

// `{error: {code, message}}` (§3.7). Null for any other body, including an older daemon's plain-text refusal.
export const readError = (body: unknown): FileError | null => {
  if (!isObj(body) || !isObj(body.error)) return null
  const code = str(body.error.code)
  return code ? { code, message: str(body.error.message) } : null
}

export const readPart = (body: unknown): PartLimits | null => {
  if (!isObj(body)) return null
  const part = { default_bytes: num(body.default_bytes), min_bytes: num(body.min_bytes), max_bytes: num(body.max_bytes), max_in_flight: num(body.max_in_flight) }
  return part.max_bytes > 0 ? part : null
}

const readFile = (value: unknown): FileStatus | null => {
  if (!isObj(value)) return null
  const state = readFileState(value.state)
  const fileId = str(value.file_id)
  if (!state || !fileId) return null
  const error = isObj(value.error) ? { code: str(value.error.code, 'internal'), message: str(value.error.message) } : null
  return {
    file_id: fileId,
    path: str(value.path),
    size: num(value.size),
    state,
    received_bytes: num(value.received_bytes),
    ranges: readRanges(value.ranges) ?? [],
    error,
    entry: value.entry ?? null,
  }
}

// A create (201), status (200) or finish answer. Finish answers may omit `upload_id` and `part`.
export const readSession = (body: unknown, fallback?: Pick<SessionStatus, 'upload_id' | 'part'>): SessionStatus | null => {
  if (!isObj(body)) return null
  const uploadId = str(body.upload_id, fallback?.upload_id ?? '')
  const part = readPart(body.part) ?? fallback?.part ?? null
  if (!uploadId || !part) return null
  const state = SESSION_STATES.includes(body.state as SessionState) ? (body.state as SessionState) : 'open'
  const files = Array.isArray(body.files) ? body.files.map(readFile).filter((f): f is FileStatus => f !== null) : []
  return { upload_id: uploadId, state, expires_at: typeof body.expires_at === 'number' ? body.expires_at : null, part, files }
}

export const readPartAnswer = (body: unknown): PartAnswer =>
  isObj(body) ? { ranges: readRanges(body.ranges), state: readFileState(body.state) } : { ranges: null, state: null }

// User-facing text for a file or request error code (§3.2, §3.7), in the console's existing wording.
export const errorText = (error: FileError | null, fallback: string): string => {
  switch (error?.code) {
    case 'already_exists':
      return 'A file with that name already exists here.'
    case 'precondition_failed':
    case 'conflict':
      return 'The file changed on the server during the upload.'
    case 'forbidden':
      return 'You don’t have permission to upload here.'
    case 'quota_exceeded':
    case 'insufficient_storage':
      return 'This upload is larger than the vault has room for.'
    case 'file_too_large':
      return 'This file is larger than the server accepts.'
    case 'key_rotated':
      return 'The vault key changed during the upload. Upload the file again.'
    case 'integrity':
      return 'The server couldn’t verify the uploaded bytes. Upload the file again.'
    case 'not_found':
      return 'The upload session expired on the server. Try again.'
    case 'internal':
      return error.message || 'The server couldn’t store this file.'
    default:
      return error?.message || fallback
  }
}
