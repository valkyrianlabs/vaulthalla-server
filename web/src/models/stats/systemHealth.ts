export type HealthStatus = 'healthy' | 'degraded' | 'critical'

export interface IRuntimeServiceHealth {
  entry_name: string
  service_name: string
  running: boolean
  interrupted: boolean
}

export interface IRuntimeHealth {
  all_running: boolean
  service_count: number
  services: RuntimeServiceHealth[]
}

export interface IProtocolHealth {
  running: boolean
  io_context_initialized: boolean
  websocket_configured: boolean
  websocket_ready: boolean
  http_preview_configured: boolean
  http_preview_ready: boolean
}

export interface IDependencyHealth {
  storage_manager: boolean
  api_key_manager: boolean
  auth_manager: boolean
  session_manager: boolean
  secrets_manager: boolean
  sync_controller: boolean
  fs_cache: boolean
  shell_usage_manager: boolean
  http_cache_stats: boolean
  fuse_session: boolean
  // Configured mount mode: "disabled" | "service_private" | "multiuser" (macOS: always "disabled"); absent from older
  // daemons.
  fuse_mount?: string
  // What the mount actually is: "disabled" | "mounted" | "not_mounted" | "unavailable" | "unsupported".
  mount_state?: string
  mount_backend?: string
  // "enforced" | "unproven" | "not_applicable".
  mount_isolation?: string
  mount_detail?: string | null
  // "tpm2", or "file" (macOS development backend).
  secrets_backend?: string
}

export interface IShellHealth {
  admin_uid_bound: boolean | null
}

export interface IHealthSummary {
  services_ready: number
  services_total: number
  deps_ready: number
  deps_total: number
  protocols_ready: number
  protocols_total: number
  checked_at: number | string | null
}

export interface ISystemHealth {
  overall_status: HealthStatus
  runtime: RuntimeHealth
  protocols: ProtocolHealth
  deps: DependencyHealth
  shell: ShellHealth
  summary: HealthSummary
}

function asObject(v: unknown): Record<string, unknown> {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {}
}

function asString(v: unknown, fallback = ''): string {
  return typeof v === 'string' ? v : fallback
}

function asNumber(v: unknown, fallback = 0): number {
  return typeof v === 'number' && Number.isFinite(v) ? v : fallback
}

function asBoolean(v: unknown, fallback = false): boolean {
  return typeof v === 'boolean' ? v : fallback
}

function asNullableBoolean(v: unknown): boolean | null {
  return typeof v === 'boolean' ? v : null
}

function asHealthStatus(v: unknown): HealthStatus {
  return v === 'healthy' || v === 'critical' || v === 'degraded' ? v : 'degraded'
}

function asCheckedAt(v: unknown): number | string | null {
  if (typeof v === 'number' && Number.isFinite(v)) return v
  if (typeof v === 'string' && v.length > 0) return v
  return null
}

function countReady(values: boolean[]): number {
  return values.filter(Boolean).length
}

export class RuntimeServiceHealth implements IRuntimeServiceHealth {
  entry_name = 'unknown'
  service_name = 'unknown'
  running = false
  interrupted = false

  constructor(data?: Partial<IRuntimeServiceHealth>) {
    if (!data) return
    this.entry_name = data.entry_name ?? this.entry_name
    this.service_name = data.service_name ?? this.service_name
    this.running = data.running ?? this.running
    this.interrupted = data.interrupted ?? this.interrupted
  }

  static from(raw: unknown): RuntimeServiceHealth {
    const data = asObject(raw)
    return new RuntimeServiceHealth({
      entry_name: asString(data.entry_name, 'unknown'),
      service_name: asString(data.service_name, 'unknown'),
      running: asBoolean(data.running),
      interrupted: asBoolean(data.interrupted),
    })
  }
}

export class RuntimeHealth implements IRuntimeHealth {
  all_running = false
  service_count = 0
  services: RuntimeServiceHealth[] = []

  constructor(data?: Partial<IRuntimeHealth>) {
    if (!data) return
    this.all_running = data.all_running ?? this.all_running
    this.services = data.services ?? this.services
    this.service_count = data.service_count ?? this.services.length
  }

  static from(raw: unknown): RuntimeHealth {
    const data = asObject(raw)
    const services = Array.isArray(data.services) ? data.services.map(RuntimeServiceHealth.from) : []
    return new RuntimeHealth({
      all_running: asBoolean(data.all_running),
      service_count: asNumber(data.service_count, services.length),
      services,
    })
  }
}

export class ProtocolHealth implements IProtocolHealth {
  running = false
  io_context_initialized = false
  websocket_configured = false
  websocket_ready = false
  http_preview_configured = false
  http_preview_ready = false

  constructor(data?: Partial<IProtocolHealth>) {
    if (!data) return
    this.running = data.running ?? this.running
    this.io_context_initialized = data.io_context_initialized ?? this.io_context_initialized
    this.websocket_configured = data.websocket_configured ?? this.websocket_configured
    this.websocket_ready = data.websocket_ready ?? this.websocket_ready
    this.http_preview_configured = data.http_preview_configured ?? this.http_preview_configured
    this.http_preview_ready = data.http_preview_ready ?? this.http_preview_ready
  }

  static from(raw: unknown): ProtocolHealth {
    const data = asObject(raw)
    return new ProtocolHealth({
      running: asBoolean(data.running),
      io_context_initialized: asBoolean(data.io_context_initialized),
      websocket_configured: asBoolean(data.websocket_configured),
      websocket_ready: asBoolean(data.websocket_ready),
      http_preview_configured: asBoolean(data.http_preview_configured),
      http_preview_ready: asBoolean(data.http_preview_ready),
    })
  }

  configuredTotal(): number {
    return Number(this.websocket_configured) + Number(this.http_preview_configured)
  }

  readyTotal(): number {
    return (
      Number(this.websocket_configured && this.websocket_ready)
      + Number(this.http_preview_configured && this.http_preview_ready)
    )
  }
}

export class DependencyHealth implements IDependencyHealth {
  storage_manager = false
  api_key_manager = false
  auth_manager = false
  session_manager = false
  secrets_manager = false
  sync_controller = false
  fs_cache = false
  shell_usage_manager = false
  http_cache_stats = false
  fuse_session = false

  constructor(data?: Partial<IDependencyHealth>) {
    if (!data) return
    this.storage_manager = data.storage_manager ?? this.storage_manager
    this.api_key_manager = data.api_key_manager ?? this.api_key_manager
    this.auth_manager = data.auth_manager ?? this.auth_manager
    this.session_manager = data.session_manager ?? this.session_manager
    this.secrets_manager = data.secrets_manager ?? this.secrets_manager
    this.sync_controller = data.sync_controller ?? this.sync_controller
    this.fs_cache = data.fs_cache ?? this.fs_cache
    this.shell_usage_manager = data.shell_usage_manager ?? this.shell_usage_manager
    this.http_cache_stats = data.http_cache_stats ?? this.http_cache_stats
    this.fuse_session = data.fuse_session ?? this.fuse_session
  }

  static from(raw: unknown): DependencyHealth {
    const data = asObject(raw)
    return new DependencyHealth({
      storage_manager: asBoolean(data.storage_manager),
      api_key_manager: asBoolean(data.api_key_manager),
      auth_manager: asBoolean(data.auth_manager),
      session_manager: asBoolean(data.session_manager),
      secrets_manager: asBoolean(data.secrets_manager),
      sync_controller: asBoolean(data.sync_controller),
      fs_cache: asBoolean(data.fs_cache),
      shell_usage_manager: asBoolean(data.shell_usage_manager),
      http_cache_stats: asBoolean(data.http_cache_stats),
      fuse_session: asBoolean(data.fuse_session),
    })
  }

  coreValues(): boolean[] {
    return [
      this.storage_manager,
      this.api_key_manager,
      this.auth_manager,
      this.session_manager,
      this.secrets_manager,
      this.sync_controller,
      this.fs_cache,
      this.shell_usage_manager,
      this.http_cache_stats,
    ]
  }
}

export class ShellHealth implements IShellHealth {
  admin_uid_bound: boolean | null = null

  constructor(data?: Partial<IShellHealth>) {
    if (!data) return
    this.admin_uid_bound = data.admin_uid_bound ?? this.admin_uid_bound
  }

  static from(raw: unknown): ShellHealth {
    const data = asObject(raw)
    return new ShellHealth({ admin_uid_bound: asNullableBoolean(data.admin_uid_bound) })
  }
}

export class HealthSummary implements IHealthSummary {
  services_ready = 0
  services_total = 0
  deps_ready = 0
  deps_total = 9
  protocols_ready = 0
  protocols_total = 0
  checked_at: number | string | null = null

  constructor(data?: Partial<IHealthSummary>) {
    if (!data) return
    this.services_ready = data.services_ready ?? this.services_ready
    this.services_total = data.services_total ?? this.services_total
    this.deps_ready = data.deps_ready ?? this.deps_ready
    this.deps_total = data.deps_total ?? this.deps_total
    this.protocols_ready = data.protocols_ready ?? this.protocols_ready
    this.protocols_total = data.protocols_total ?? this.protocols_total
    this.checked_at = data.checked_at ?? this.checked_at
  }

  static from(raw: unknown, runtime: RuntimeHealth, deps: DependencyHealth, protocols: ProtocolHealth): HealthSummary {
    const data = asObject(raw)
    return new HealthSummary({
      services_ready: asNumber(data.services_ready, runtime.services.filter(service => service.running).length),
      services_total: asNumber(data.services_total, runtime.service_count),
      deps_ready: asNumber(data.deps_ready, countReady(deps.coreValues())),
      deps_total: asNumber(data.deps_total, deps.coreValues().length),
      protocols_ready: asNumber(data.protocols_ready, protocols.readyTotal()),
      protocols_total: asNumber(data.protocols_total, protocols.configuredTotal()),
      checked_at: asCheckedAt(data.checked_at),
    })
  }
}

export class SystemHealth implements ISystemHealth {
  overall_status: HealthStatus = 'degraded'
  runtime = new RuntimeHealth()
  protocols = new ProtocolHealth()
  deps = new DependencyHealth()
  shell = new ShellHealth()
  summary = new HealthSummary()

  constructor(data?: Partial<ISystemHealth>) {
    if (!data) return
    this.overall_status = data.overall_status ?? this.overall_status
    this.runtime = data.runtime ?? this.runtime
    this.protocols = data.protocols ?? this.protocols
    this.deps = data.deps ?? this.deps
    this.shell = data.shell ?? this.shell
    this.summary = data.summary ?? this.summary
  }

  static from(raw: unknown): SystemHealth {
    const data = asObject(raw)
    const runtime = RuntimeHealth.from(data.runtime)
    const protocols = ProtocolHealth.from(data.protocols)
    const deps = DependencyHealth.from(data.deps)
    const shell = ShellHealth.from(data.shell)
    const summary = HealthSummary.from(data.summary, runtime, deps, protocols)

    return new SystemHealth({
      overall_status: asHealthStatus(data.overall_status),
      runtime,
      protocols,
      deps,
      shell,
      summary,
    })
  }
}
