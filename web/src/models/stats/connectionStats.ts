export type ConnectionHealthStatus = 'healthy' | 'warning' | 'critical' | 'unknown'

type UnknownRecord = Record<string, unknown>
type CountMap = Record<string, number>

function isRecord(value: unknown): value is UnknownRecord {
  return !!value && typeof value === 'object' && !Array.isArray(value)
}

function asNumber(value: unknown, fallback = 0): number {
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value)
    if (Number.isFinite(parsed)) return parsed
  }
  return fallback
}

function asNullableNumber(value: unknown): number | null {
  if (value == null) return null
  const parsed = asNumber(value, Number.NaN)
  return Number.isFinite(parsed) ? parsed : null
}

function asNullableDate(value: unknown): number | string | null {
  return typeof value === 'string' ? value : asNullableNumber(value)
}

function asStatus(value: unknown): ConnectionHealthStatus {
  return value === 'healthy' || value === 'warning' || value === 'critical' ? value : 'unknown'
}

function asCountMap(value: unknown, keys: string[]): CountMap {
  const data = isRecord(value) ? value : {}
  return keys.reduce<CountMap>((out, key) => {
    out[key] = asNumber(data[key])
    return out
  }, {})
}

export class ConnectionStats {
  status: ConnectionHealthStatus
  active_ws_sessions_total: number
  active_human_sessions: number
  active_share_sessions: number
  active_share_pending_sessions: number
  active_unauthenticated_sessions: number
  oldest_session_age_seconds: number | null
  oldest_unauthenticated_session_age_seconds: number | null
  idle_timeout_minutes: number
  unauthenticated_timeout_seconds: number
  sweep_interval_seconds: number
  sessions_swept_24h: number | null
  connections_opened_24h: number | null
  connections_closed_24h: number | null
  connection_errors_24h: number | null
  sessions_by_mode: CountMap
  top_user_agents_available: boolean
  top_remote_ips_available: boolean
  checked_at: number | string | null

  constructor(input: unknown = {}) {
    const data = isRecord(input) ? input : {}
    this.status = asStatus(data.status)
    this.active_ws_sessions_total = asNumber(data.active_ws_sessions_total)
    this.active_human_sessions = asNumber(data.active_human_sessions)
    this.active_share_sessions = asNumber(data.active_share_sessions)
    this.active_share_pending_sessions = asNumber(data.active_share_pending_sessions)
    this.active_unauthenticated_sessions = asNumber(data.active_unauthenticated_sessions)
    this.oldest_session_age_seconds = asNullableNumber(data.oldest_session_age_seconds)
    this.oldest_unauthenticated_session_age_seconds = asNullableNumber(data.oldest_unauthenticated_session_age_seconds)
    this.idle_timeout_minutes = asNumber(data.idle_timeout_minutes)
    this.unauthenticated_timeout_seconds = asNumber(data.unauthenticated_timeout_seconds)
    this.sweep_interval_seconds = asNumber(data.sweep_interval_seconds)
    this.sessions_swept_24h = asNullableNumber(data.sessions_swept_24h)
    this.connections_opened_24h = asNullableNumber(data.connections_opened_24h)
    this.connections_closed_24h = asNullableNumber(data.connections_closed_24h)
    this.connection_errors_24h = asNullableNumber(data.connection_errors_24h)
    this.sessions_by_mode = asCountMap(data.sessions_by_mode, ['unauthenticated', 'human', 'share_pending', 'share', 'device', 'device_pairing'])
    this.top_user_agents_available = data.top_user_agents_available === true
    this.top_remote_ips_available = data.top_remote_ips_available === true
    this.checked_at = asNullableDate(data.checked_at)
  }

  static from(input: unknown): ConnectionStats {
    return new ConnectionStats(input)
  }
}
