export type WsErrorKind =
  | 'unauthorized' // no or expired access token: the router refused before running the command
  | 'denied' // authenticated, but not allowed
  | 'not_found'
  | 'invalid'
  | 'conflict'
  | 'needs_confirmation' // the server wants an explicit acceptance (e.g. encryption waiver) before proceeding
  | 'error'
  | 'timeout' // no answer yet; the server may still be working
  | 'disconnected'
  | 'aborted'

export class WsError extends Error {
  constructor(
    public readonly kind: WsErrorKind,
    message: string,
    public readonly code?: string,
    // The refusal's data beside its code (e.g. auth.login's mfa_required carries data.pending).
    public readonly data?: Record<string, unknown>,
  ) {
    super(message)
    this.name = 'WsError'
  }
}

const REFUSAL_CODES: Record<string, WsErrorKind> = { denied: 'denied', not_found: 'not_found', invalid: 'invalid', conflict: 'conflict' }

// Older daemons send refusals without a code; their wording is stable enough to classify the common case.
const DENIED_TEXT = /(permission|not allowed|must be an admin|forbidden|access denied|not authori[sz]ed to)/i

export const wsErrorFromMessage = (message: Record<string, unknown>): WsError | null => {
  const status = typeof message.status === 'string' ? message.status.toUpperCase() : ''
  if (!status || status === 'OK' || status === 'SUCCESS') return null

  const text = typeof message.error === 'string' && message.error ? message.error : 'The server refused the request'
  if (status === 'UNAUTHORIZED') return new WsError('unauthorized', text)

  const data = message.data && typeof message.data === 'object' ? (message.data as Record<string, unknown>) : {}
  const code = typeof data.code === 'string' ? data.code : undefined
  if (code && REFUSAL_CODES[code]) return new WsError(REFUSAL_CODES[code], text, code, data)
  if (code) return new WsError('needs_confirmation', text, code, data)
  if (DENIED_TEXT.test(text)) return new WsError('denied', text)
  return new WsError('error', text)
}

export const isWsError = (error: unknown, ...kinds: WsErrorKind[]): error is WsError =>
  error instanceof WsError && (kinds.length === 0 || kinds.includes(error.kind))

export const errorMessage = (error: unknown, fallback = 'Something went wrong'): string => {
  if (error instanceof Error && error.message) return error.message
  if (typeof error === 'string' && error) return error
  return fallback
}
