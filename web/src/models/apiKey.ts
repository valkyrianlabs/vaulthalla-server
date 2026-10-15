export interface APIKeyType {
  api_key_id: number
  user_id: number
  type: string // 's3', 'vault', etc.
  name: string
  created_at: string
  provider?: string // Optional for S3APIKey
  // Provider administration (#237); absent on older daemons.
  admin_enabled?: boolean
  provider_account_id?: string | null
  has_provider_token?: boolean
  admin_validated_at?: string | null
}

interface S3APIKeyType extends APIKeyType {
  access_key: string
  secret_access_key: string
  region: string
  endpoint: string
}

export class APIKey implements APIKeyType {
  api_key_id: number
  user_id: number
  type: string
  name: string
  created_at: string
  provider?: string // Optional for generic APIKey

  constructor(data: APIKeyType) {
    this.api_key_id = data.api_key_id
    this.user_id = data.user_id
    this.type = data.type
    this.name = data.name
    this.created_at = data.created_at
    this.provider = data.provider ?? ''
  }
}

export class S3APIKey extends APIKey {
  provider: string
  access_key: string
  secret_access_key: string
  region: string
  endpoint: string

  constructor(data: APIKeyType & S3APIKeyType) {
    super(data)
    this.provider = data.provider ?? 's3'
    this.access_key = data.access_key
    this.secret_access_key = data.secret_access_key
    this.region = data.region
    this.endpoint = data.endpoint
  }
}
