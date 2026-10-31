// Retry policy for resumable uploads (transfer-protocol.md §3.3, §3.7). Pure; see retry.test.ts.

export const BACKOFF_BASE_MS = 1_000
export const BACKOFF_CAP_MS = 30_000
// A server's Retry-After is honored up to this much; anything longer is treated as this.
export const RETRY_AFTER_CAP_MS = 120_000
// Consecutive failed attempts (without a stored part in between) before a file gives up: roughly ten minutes of
// backoff, enough to ride out a Wi-Fi drop or a daemon restart. The session stays, so choosing the file again resumes.
export const MAX_ATTEMPTS = 20
// Connection failures in a row on one part before the client asks the server what it actually stored.
export const RESYNC_AFTER_CONNECTION_FAILURES = 2

// Retry-After: delta-seconds or an HTTP date. Null when absent or unreadable.
export const parseRetryAfter = (value: string | null | undefined, now: number): number | null => {
  if (!value) return null
  const trimmed = value.trim()
  if (/^\d+$/.test(trimmed)) return Math.min(RETRY_AFTER_CAP_MS, Number(trimmed) * 1000)
  const at = Date.parse(trimmed)
  if (Number.isNaN(at)) return null
  return Math.min(RETRY_AFTER_CAP_MS, Math.max(0, at - now))
}

// Exponential backoff with "equal jitter" (half fixed, half random), capped; a server's Retry-After is a floor.
// `attempt` counts from 0; `random` is in [0, 1).
export const backoffMs = (attempt: number, retryAfterMs: number | null, random: number): number => {
  const ceiling = Math.min(BACKOFF_CAP_MS, BACKOFF_BASE_MS * 2 ** Math.min(attempt, 20))
  const jittered = ceiling / 2 + (ceiling / 2) * random
  if (retryAfterMs === null) return Math.round(jittered)
  // Spread clients that were all told the same Retry-After by up to a second.
  return Math.round(Math.max(retryAfterMs + 1000 * random, Math.min(jittered, retryAfterMs)))
}

export type PartVerdict =
  | 'stored' // 2xx
  | 'retry' // transient: back off and send the same part again
  | 'resync' // the server's view differs from ours: read the status, send the gaps
  | 'file_state' // the file left `receiving`: read the status for the outcome
  | 'gone' // the session no longer exists (expired, cancelled elsewhere)
  | 'fatal' // the request can never succeed

// 5xx is transient except 501 (never implemented) and 507 insufficient_storage (needs room, not time).
const serverBusy = (status: number) => status >= 500 && status !== 501 && status !== 507

// What to do with the answer to a part PUT. `status` 0 means no answer (network error or timeout).
export const classifyPart = (status: number, code: string | null): PartVerdict => {
  if (status >= 200 && status < 300) return 'stored'
  if (status === 0 || status === 408 || status === 429 || serverBusy(status)) return 'retry'
  if (status === 400 && code === 'digest_mismatch') return 'retry'
  if (status === 409) return code === 'file_state' ? 'file_state' : 'resync'
  if (status === 404) return 'gone'
  return 'fatal'
}

// Requests other than part PUTs (create, status, finish): only transport trouble and busy answers are retried.
export const transient = (status: number) => status === 0 || status === 408 || status === 429 || serverBusy(status)
