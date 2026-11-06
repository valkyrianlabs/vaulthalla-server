// Mirrors `vh::config::to_json(Config)` in core/src/config/Config.cpp. The daemon never sends secrets here
// (the DB password is TPM-sealed and the JWT secret lives in the secrets manager), so the web never renders,
// defaults, or sends them. `settings.update` merges a partial payload onto the current config server-side.

export type SettingsValue = string | number | boolean | null | SettingsValue[] | SettingsSection

export interface SettingsSection {
  [key: string]: SettingsValue
}

export interface WebsocketServerSettings extends SettingsSection {
  enabled: boolean
  host: string
  port: number
  max_connections: number
  max_upload_size_bytes: number
}

export interface HttpPreviewServerSettings extends SettingsSection {
  enabled: boolean
  host: string
  port: number
  max_connections: number
  max_preview_size_bytes: number
}

export interface DatabaseSettings extends SettingsSection {
  host: string
  port: number
  name: string
  user: string
  pool_size: number
}

// auth.webauthn.* (core WebAuthnConfig, #355): the passkey relying party. Empty rp_id: passkeys are unavailable.
export interface WebAuthnSettings extends SettingsSection {
  rp_id: string
  rp_name: string
  origins: string[]
}

export interface AuthSettings extends SettingsSection {
  access_token_expiry_minutes: number
  refresh_token_expiry_days: number
  webauthn: WebAuthnSettings
}

// sharing.* (core share::policy): `enabled` gates every link; the others gate one kind each. enable_anonymous is
// access_mode 'public', enable_email_validated is 'email_validated'. Signed-in vault users are governed by RBAC.
// Daemons before #164 sent enable_public_links instead of enable_email_validated.
export interface SharingSettings extends SettingsSection {
  enabled: boolean
  enable_anonymous: boolean
  enable_email_validated: boolean
}

// Defaults for vaults created without an explicit sync strategy / conflict policy.
export interface VaultRemoteDefaults extends SettingsSection {
  default_remote_sync_strategy: 'cache' | 'sync' | 'mirror'
  default_remote_conflict_policy: 'keep_local' | 'keep_remote' | 'keep_newest' | 'ask'
}

export interface VaultsSettings extends SettingsSection {
  retention_window: string
  tpm_retention_window: string
  s3: VaultRemoteDefaults & { tpm_retention_window: string }
}

// settings.policy.get: the part of the config any signed-in console needs (super admins get all of it from
// settings.get). Not secret.
export interface ServerPolicy {
  sharing: SharingSettings
  vaults: VaultsSettings
}

export interface Settings {
  websocket_server: WebsocketServerSettings
  http_preview_server: HttpPreviewServerSettings
  s3_gateway: SettingsSection
  caching: SettingsSection
  database: DatabaseSettings
  auth: AuthSettings
  sync: SettingsSection
  pricing: SettingsSection
  services: SettingsSection
  stats_snapshots: SettingsSection
  sharing: SharingSettings
  vaults: VaultsSettings
  email: SettingsSection
  operator_emails: SettingsSection
  auditing: SettingsSection
  logging: SettingsSection
  dev: SettingsSection
}

export const isSettingsSection = (value: SettingsValue | undefined): value is SettingsSection =>
  typeof value === 'object' && value !== null && !Array.isArray(value)
