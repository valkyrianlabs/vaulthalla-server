import type { WebSocketCommandMap } from '@/util/webSocketCommands'
import { getWebsocketUrl } from '@/util/getUrl'
import { WsError, wsErrorFromMessage } from '@/lib/ws/errors'
import { randomId } from '@/lib/randomId'
import { WS_CONTRACT_TIMEOUTS } from '@/util/generated/wsContract'

export type Command = keyof WebSocketCommandMap
export type Payload<C extends Command> = WebSocketCommandMap[C]['payload']
export type Response<C extends Command> = WebSocketCommandMap[C]['response']

export type ConnectionStatus = 'idle' | 'connecting' | 'open' | 'reconnecting' | 'closed'

export interface SendOptions {
  timeoutMs?: number
  signal?: AbortSignal
}

interface Pending {
  command: Command
  resolve: (data: unknown) => void
  reject: (error: WsError) => void
  timer: ReturnType<typeof setTimeout>
  cleanup: () => void
}

interface WsClientOptions {
  path: string
  // Supplies the envelope access token for a command ('' when none); called per send.
  token?: (command: Command) => string
  // Called with the token the server returns in a response envelope (auth.login / auth.refresh rotate it).
  onToken?: (token: string) => void
  // Called once per UNAUTHORIZED rejection; resolve true to retry the command once (the server never ran it).
  onUnauthorized?: (command: Command) => Promise<boolean>
  // Called each time a socket opens (first connect and every reconnect).
  onOpen?: () => void
  // Commands that must never trigger the unauthorized retry (they are the session lifecycle itself).
  lifecycle?: ReadonlySet<Command>
}

const CONNECT_DEADLINE_MS = 8_000
const DEFAULT_TIMEOUT_MS = 15_000
const BACKOFF_BASE_MS = 500
const BACKOFF_MAX_MS = 15_000

// Commands whose server-side work can legitimately take longer than the default. A timeout on these means "no
// answer yet", not "failed": callers surface it as such and must not blindly resend. Commands in the server-owned
// contract take the timeout the server declares (core/usage); the rest are listed here.
const COMMAND_TIMEOUTS: Partial<Record<Command, number>> = {
  ...WS_CONTRACT_TIMEOUTS,
  'share.upload.start': 30_000,
  'share.upload.finish': 180_000,
  'share.preview.get': 30_000,
  'storage.vault.update': 60_000,
  'storage.apiKey.add': 60_000,
  'storage.apiKey.update': 60_000,
  'email.test.send': 60_000,
  's3.gateway.buckets.createRemoteCache': 180_000,
  'pricing.budget.preflight': 60_000,
  // Resolving uploads or downloads each file (price-preflighted, metered); a bulk run can take minutes.
  'sync.conflicts.resolve': 600_000,
  // Upstream control plane (#237/#96): each of these talks to the provider (probes, ListBuckets pages, bucket
  // configuration, queue provisioning, bounded LIST/HEAD admission and cleanup passes).
  'upstream.admin.enable': 60_000,
  'upstream.admin.status': 60_000,
  'upstream.bucket.list': 60_000,
  'upstream.bucket.inspect': 60_000,
  'upstream.bucket.lifecycle.set': 60_000,
  'upstream.bucket.adopt.preflight': 180_000,
  'upstream.bucket.detach': 60_000,
  'upstream.bucket.cleanup.preflight': 180_000,
  'upstream.bucket.cleanup': 600_000,
  'upstream.events.enable': 120_000,
  'upstream.events.disable': 60_000,
  'upstream.events.repair': 120_000,
}

export const commandTimeout = (command: Command) => COMMAND_TIMEOUTS[command] ?? DEFAULT_TIMEOUT_MS

type Listener = (status: ConnectionStatus) => void
type MessageListener = (message: Record<string, unknown>) => void

export class WsClient {
  private socket: WebSocket | null = null
  private status: ConnectionStatus = 'idle'
  private wanted = false
  private attempt = 0
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private readonly pending = new Map<string, Pending>()
  private readonly statusListeners = new Set<Listener>()
  private readonly messageListeners = new Set<MessageListener>()
  private readonly openWaiters = new Set<() => void>()
  private windowHooked = false

  constructor(private readonly options: WsClientOptions) {}

  getStatus = () => this.status

  subscribe = (listener: Listener) => {
    this.statusListeners.add(listener)
    return () => {
      this.statusListeners.delete(listener)
    }
  }

  onMessage(listener: MessageListener) {
    this.messageListeners.add(listener)
    return () => {
      this.messageListeners.delete(listener)
    }
  }

  connect() {
    if (typeof window === 'undefined') return
    this.wanted = true
    this.hookWindow()
    if (this.socket) return
    this.clearReconnect()
    this.open()
  }

  // Drops the socket and every pending request. Used on logout and when a share session ends.
  close() {
    this.wanted = false
    this.clearReconnect()
    const socket = this.socket
    this.socket = null
    if (socket) {
      socket.onopen = socket.onclose = socket.onmessage = socket.onerror = null
      socket.close()
    }
    this.failAll(new WsError('disconnected', 'Connection closed'))
    this.setStatus('closed')
  }

  async send<C extends Command>(command: C, payload: Payload<C>, options: SendOptions = {}): Promise<Response<C>> {
    try {
      return await this.sendOnce(command, payload, options)
    } catch (error) {
      const lifecycle = this.options.lifecycle?.has(command) ?? false
      if (!(error instanceof WsError) || error.kind !== 'unauthorized' || lifecycle || !this.options.onUnauthorized) throw error
      // The router rejected the command before running it, so a single retry after a refresh is always safe.
      if (!(await this.options.onUnauthorized(command))) throw error
      return this.sendOnce(command, payload, options)
    }
  }

  private async sendOnce<C extends Command>(command: C, payload: Payload<C>, options: SendOptions): Promise<Response<C>> {
    if (options.signal?.aborted) throw new WsError('aborted', 'Request cancelled')
    await this.ready(options.signal)
    const socket = this.socket
    if (!socket || socket.readyState !== WebSocket.OPEN) throw new WsError('disconnected', 'Not connected to the server')

    const requestId = randomId()
    const token = this.options.token?.(command) ?? ''
    const timeoutMs = options.timeoutMs ?? commandTimeout(command)

    return new Promise<Response<C>>((resolve, reject) => {
      const onAbort = () => settle(new WsError('aborted', 'Request cancelled'))
      const settle = (error: WsError | null, data?: unknown) => {
        const entry = this.pending.get(requestId)
        if (!entry) return
        this.pending.delete(requestId)
        entry.cleanup()
        if (error) reject(error)
        else resolve(data as Response<C>)
      }
      const timer = setTimeout(
        () => settle(new WsError('timeout', 'The server has not answered yet. It may still be working on this.')),
        timeoutMs,
      )
      this.pending.set(requestId, {
        command,
        resolve: data => settle(null, data),
        reject: error => settle(error),
        timer,
        cleanup: () => {
          clearTimeout(timer)
          options.signal?.removeEventListener('abort', onAbort)
        },
      })
      options.signal?.addEventListener('abort', onAbort, { once: true })

      try {
        socket.send(JSON.stringify({ command, payload, requestId, token }))
      } catch {
        settle(new WsError('disconnected', 'Unable to reach the server'))
      }
    })
  }

  private ready(signal?: AbortSignal): Promise<void> {
    if (this.status === 'open') return Promise.resolve()
    this.connect()
    return new Promise((resolve, reject) => {
      const done = (error?: WsError) => {
        clearTimeout(timer)
        this.openWaiters.delete(onOpen)
        signal?.removeEventListener('abort', onAbort)
        if (error) reject(error)
        else resolve()
      }
      const onOpen = () => done()
      const onAbort = () => done(new WsError('aborted', 'Request cancelled'))
      const timer = setTimeout(() => done(new WsError('disconnected', 'Cannot reach the Vaulthalla server')), CONNECT_DEADLINE_MS)
      this.openWaiters.add(onOpen)
      signal?.addEventListener('abort', onAbort, { once: true })
    })
  }

  private open() {
    this.setStatus(this.attempt > 0 ? 'reconnecting' : 'connecting')
    let socket: WebSocket
    try {
      socket = new WebSocket(getWebsocketUrl(this.options.path))
    } catch {
      this.scheduleReconnect()
      return
    }
    this.socket = socket

    socket.onopen = () => {
      if (socket !== this.socket) return
      this.attempt = 0
      this.setStatus('open')
      for (const waiter of [...this.openWaiters]) waiter()
      this.options.onOpen?.()
    }

    socket.onclose = () => {
      if (socket !== this.socket) return
      this.socket = null
      this.failAll(new WsError('disconnected', 'Connection to the server was lost'))
      if (this.wanted) this.scheduleReconnect()
      else this.setStatus('closed')
    }

    socket.onmessage = event => {
      if (socket !== this.socket) return
      this.handleMessage(event.data)
    }
  }

  private handleMessage(raw: unknown) {
    if (typeof raw !== 'string') return
    let message: Record<string, unknown>
    try {
      message = JSON.parse(raw)
    } catch {
      return
    }

    if (typeof message.token === 'string' && message.token) this.options.onToken?.(message.token)

    const requestId = typeof message.requestId === 'string' ? message.requestId : null
    const entry = requestId ? this.pending.get(requestId) : undefined
    if (!entry) {
      for (const listener of this.messageListeners) listener(message)
      return
    }

    const error = wsErrorFromMessage(message)
    if (error) entry.reject(error)
    else entry.resolve(message.data ?? {})
  }

  private failAll(error: WsError) {
    for (const entry of [...this.pending.values()]) entry.reject(error)
    this.pending.clear()
  }

  private scheduleReconnect() {
    this.clearReconnect()
    this.setStatus('reconnecting')
    const ceiling = Math.min(BACKOFF_MAX_MS, BACKOFF_BASE_MS * 2 ** this.attempt)
    const delay = Math.round(ceiling / 2 + Math.random() * (ceiling / 2))
    this.attempt += 1
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null
      if (this.wanted && !this.socket) this.open()
    }, delay)
  }

  private clearReconnect() {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer)
    this.reconnectTimer = null
  }

  // Reconnect immediately when the network or the tab comes back instead of waiting out the backoff.
  private hookWindow() {
    if (this.windowHooked || typeof window === 'undefined') return
    this.windowHooked = true
    const kick = () => {
      if (!this.wanted || this.socket) return
      this.attempt = 0
      this.clearReconnect()
      this.open()
    }
    window.addEventListener('online', kick)
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') kick()
    })
  }

  private setStatus(status: ConnectionStatus) {
    if (this.status === status) return
    this.status = status
    for (const listener of this.statusListeners) listener(status)
  }
}
