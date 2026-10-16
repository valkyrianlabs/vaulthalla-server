// Plain shapes of what the daemon sends for vaults (the legacy classes in models/vaults.ts are never instantiated by
// the query layer, so nothing here relies on their methods or defaults).

export type VaultType = 'local' | 's3'
export type SyncStrategy = 'cache' | 'sync' | 'mirror'
export type ConflictPolicy = 'keep_local' | 'keep_remote' | 'keep_newest' | 'ask'

export interface S3RequestBudget {
  list_requests: number | null
  head_requests: number | null
  get_requests: number | null
  put_requests: number | null
  copy_requests: number | null
  delete_requests: number | null
  downloaded_bytes: number | null
}

export interface SyncPolicy {
  id?: number
  vault_id?: number
  strategy: SyncStrategy
  conflict_policy: ConflictPolicy
  // The daemon sends "10m 0s"; it accepts that form or a number of seconds.
  interval: number | string
  enabled: boolean
  s3_request_budget: S3RequestBudget
  max_remote_index_age_seconds: number | null
  last_sync_at?: string | null
  last_success_at?: string | null
}

// storage.vault.list rows. The list carries owner_id only (no owner name): see ownerName().
export interface VaultRow {
  id: number
  name: string
  slug: string
  fuse_name: string | null
  effective_fuse_name: string
  description: string
  type: VaultType
  owner_id: number
  quota: number
  is_active: boolean
  created_at: string
  mount_point?: string
  allow_fs_write?: boolean
  api_key_id?: number
  bucket?: string
  storage_tier_id?: string | null
  encrypt_upstream?: boolean
}

// storage.vault.get adds the owner's name and, for S3 vaults, the sync policy.
export interface VaultDetail extends VaultRow {
  owner?: string
  sync?: SyncPolicy
}

export interface ProviderCredential {
  api_key_id: number
  name: string
  provider?: string
  region?: string
  endpoint?: string
  user_id?: number
  admin_enabled?: boolean // #237: the credential can provision and adopt buckets
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  Boolean(value) && typeof value === 'object' && !Array.isArray(value)

// storage.apiKey.list answered `keys` as a JSON *string* through 1.8; newer daemons send a real array. Accept both.
export const parseCredentials = (keys: unknown): ProviderCredential[] => {
  let list: unknown = keys
  if (typeof keys === 'string') {
    try {
      list = JSON.parse(keys)
    } catch {
      return []
    }
  }
  if (!Array.isArray(list)) return []
  return list.filter(isRecord).flatMap(item => {
    const id = Number(item.api_key_id ?? item.id)
    if (!Number.isFinite(id) || id <= 0) return []
    return [
      {
        api_key_id: id,
        name: typeof item.name === 'string' ? item.name : `Credential ${id}`,
        provider: typeof item.provider === 'string' && item.provider ? item.provider : undefined,
        region: typeof item.region === 'string' ? item.region : undefined,
        endpoint: typeof item.endpoint === 'string' ? item.endpoint : undefined,
        user_id: typeof item.user_id === 'number' ? item.user_id : undefined,
        admin_enabled: item.admin_enabled === true,
      },
    ]
  })
}

export const vaultTypeLabel = (type: string | undefined) => (type === 's3' ? 'S3' : type === 'local' ? 'Local disk' : 'Unknown')

// What the vault stores on: "Local disk", or the S3 credential's provider ("Cloudflare R2") when we can see it.
export const providerLabel = (vault: Pick<VaultRow, 'type' | 'api_key_id'>, credentials?: ProviderCredential[]) => {
  if (vault.type !== 's3') return 'Local disk'
  const credential = credentials?.find(c => c.api_key_id === vault.api_key_id)
  return credential?.provider ?? 'S3'
}

// The daemon reports never-run sync timestamps as the epoch.
export const realTimestamp = (value: string | number | null | undefined) => {
  if (value === null || value === undefined || value === '') return null
  const ms = typeof value === 'number' ? (value < 1e12 ? value * 1000 : value) : Date.parse(value)
  return Number.isFinite(ms) && ms > 86_400_000 ? value : null
}

// A vault role assignment's subject. The daemon nests it under `assignment` with string ids.
export interface AssignmentSubject {
  type: 'user' | 'group'
  id: number
}

export const assignmentSubject = (role: { assignment?: { subject_type?: unknown; subject_id?: unknown } | null }): AssignmentSubject | null => {
  const a = role.assignment
  if (!a) return null
  const id = Number(a.subject_id)
  if (!Number.isFinite(id) || id <= 0) return null
  if (a.subject_type !== 'user' && a.subject_type !== 'group') return null
  return { type: a.subject_type, id }
}
