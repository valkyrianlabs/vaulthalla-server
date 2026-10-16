// Upstream S3/R2 provider credentials ("API keys" in core: storage.apiKey.*). The daemon never returns the secret.

export interface ProviderCredential {
  api_key_id: number
  user_id: number | null
  name: string
  provider: string
  access_key: string
  region: string
  endpoint: string
  created_at: string | null
  // Provider administration (#237). Older daemons send none of these: treat as "not enabled".
  admin_enabled: boolean
  provider_account_id: string | null
  has_provider_token: boolean
  admin_validated_at: string | null
}

// Matches s3_provider_from_string in core/src/vault/model/APIKey.cpp.
export const PROVIDERS = [
  'AWS',
  'Cloudflare R2',
  'Wasabi',
  'Backblaze B2',
  'DigitalOcean',
  'MinIO',
  'Ceph',
  'Storj',
  'Other',
] as const

// Placeholders only — never defaults that get saved.
export const PROVIDER_HINTS: Record<string, { endpoint: string; region: string }> = {
  AWS: { endpoint: 'https://s3.us-east-1.amazonaws.com', region: 'us-east-1' },
  'Cloudflare R2': { endpoint: 'https://<account-id>.r2.cloudflarestorage.com', region: 'auto' },
  Wasabi: { endpoint: 'https://s3.us-east-1.wasabisys.com', region: 'us-east-1' },
  'Backblaze B2': { endpoint: 'https://s3.us-west-004.backblazeb2.com', region: 'us-west-004' },
  DigitalOcean: { endpoint: 'https://nyc3.digitaloceanspaces.com', region: 'nyc3' },
  MinIO: { endpoint: 'https://minio.example.com', region: 'us-east-1' },
}

const record = (value: unknown): Record<string, unknown> =>
  value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : {}

const text = (value: unknown) =>
  typeof value === 'string' ? value
  : typeof value === 'number' ? String(value)
  : ''

export const toCredential = (input: unknown): ProviderCredential => {
  const data = record(input)
  const id = Number(data.api_key_id ?? data.id)
  return {
    api_key_id: Number.isFinite(id) ? id : 0,
    user_id: typeof data.user_id === 'number' ? data.user_id : null,
    name: text(data.name),
    provider: text(data.provider),
    access_key: text(data.access_key),
    region: text(data.region),
    endpoint: text(data.endpoint),
    created_at: typeof data.created_at === 'string' && data.created_at ? data.created_at : null,
    admin_enabled: data.admin_enabled === true,
    provider_account_id:
      typeof data.provider_account_id === 'string' && data.provider_account_id ? data.provider_account_id : null,
    has_provider_token: data.has_provider_token === true,
    admin_validated_at:
      typeof data.admin_validated_at === 'string' && data.admin_validated_at ? data.admin_validated_at : null,
  }
}

// storage.apiKey.list: older daemons double-encode the list as a JSON string, newer ones send an array (#154).
export const parseApiKeyList = (keys: unknown): ProviderCredential[] => {
  let list: unknown = keys
  if (typeof keys === 'string') {
    try {
      list = JSON.parse(keys)
    } catch {
      list = []
    }
  }
  return Array.isArray(list) ? list.map(toCredential).filter(key => key.api_key_id > 0) : []
}

// "AKIA…WXYZ": enough to recognise a key without putting the whole identifier on screen.
export const maskAccessKey = (key: string) => (key.length > 10 ? `${key.slice(0, 4)}…${key.slice(-4)}` : key)
