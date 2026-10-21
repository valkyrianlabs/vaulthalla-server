import { LocalDiskVault, RemoteSyncPolicy, S3Vault, Vault } from '@/models/vaults'
import type { VaultDeletion, VaultRemovalPlan } from '@/models/vaultDeletion'
import type {
  SyncConflict,
  SyncConflictResolution,
  SyncConflictResolveResponse,
  SyncConflictSummary,
} from '@/models/syncConflicts'
import { VaultStats } from '@/models/stats/vaultStats'
import { VaultActivity } from '@/models/stats/vaultActivity'
import { VaultRecovery } from '@/models/stats/vaultRecovery'
import { VaultSecurity } from '@/models/stats/vaultSecurity'
import { VaultShareStats } from '@/models/stats/vaultShareStats'
import { VaultSyncHealth } from '@/models/stats/vaultSyncHealth'
import { APIKey } from '@/models/apiKey'
import type {
  AdminStatus,
  AdmissionReport,
  AuditEntry,
  BucketRow,
  BucketState,
  CleanupPlan,
  CleanupResult,
  EventStatus,
  ForeignObjects,
  Inspection,
  Inventory,
  LifecyclePatch,
  Provision,
} from '@/models/upstream'
import type {
  ProviderRetentionInput,
  RecoveryCostReport,
  RecoveryDisclosure,
  RecoveryPlan,
  RecoveryPoint,
  RecoveryPointDetail,
  RecoveryRestoreResult,
  RecoveryStatus,
  RecoveryUpdate,
} from '@/models/recovery'
import type { GroupRecord, UserRecord } from '@/features/access/types'
import type { Device } from '@/models/device'
import type { ProviderName } from '@/features/credentials/types'
import { Permission } from '@/models/role'
import type { WsContract } from '@/util/generated/wsContract'
import { ServerPolicy, Settings, SettingsSection } from '@/models/settings'
import { File } from '@/models/file'
import { Directory } from '@/models/directory'
import {
  DashboardPreference,
  DashboardPreferencePayload,
  DashboardPreferenceUpdatePayload,
} from '@/models/dashboard/dashboardPreferences'
import { CacheStats } from '@/models/stats/cacheStats'
import { ConnectionStats } from '@/models/stats/connectionStats'
import { DashboardOverview, DashboardOverviewRequest, type DashboardSeverity } from '@/models/stats/dashboardOverview'
import { DbStats } from '@/models/stats/dbStats'
import { FuseStats } from '@/models/stats/fuseStats'
import { OperationStats } from '@/models/stats/operationStats'
import { RetentionStats } from '@/models/stats/retentionStats'
import { StatsTrends } from '@/models/stats/statsTrends'
import { StorageBackendStats } from '@/models/stats/storageBackendStats'
import { SystemHealth } from '@/models/stats/systemHealth'
import { ThreadPoolManagerStats } from '@/models/stats/threadPoolStats'
import { AdminRoleDTO, VaultRoleDTO } from '@/models/permission'
import {
  ShareDownloadCancelResponse,
  ShareDownloadChunkResponse,
  ShareDownloadStartResponse,
  ShareEmailChallengeConfirmResponse,
  ShareEmailChallengeStartResponse,
  ShareLinkCreatePayload,
  ShareLinkListResponse,
  ShareLinkResponse,
  ShareLinkTokenResponse,
  ShareLinkUpdatePayload,
  ShareListResponse,
  ShareMetadataResponse,
  SharePreviewResponse,
  ShareSessionOpenResponse,
  ShareUploadCancelResponse,
  ShareUploadFinishResponse,
  ShareUploadStartResponse,
} from '@/models/linkShare'
import {
  OperatorEmailConfigPatch,
  OperatorEmailConfigResponse,
  OperatorEmailHistoryRecord,
  OperatorEmailSecretPayload,
  OperatorEmailTestPayload,
  OperatorEmailTestResponse,
} from '@/models/operatorEmail'
import {
  PriceBudgetPolicy,
  PriceBudgetPolicyPayload,
  PriceBudgetPreflightPayload,
  PriceBudgetPreflightResult,
  PriceBudgetScope,
  PriceBudgetStatus,
} from '@/models/pricing/priceBudget'
import { PriceBudgetLedgerEntry } from '@/models/pricing/priceBudgetLedger'
import { PriceNotification, type PriceNotificationSummary } from '@/models/pricing/priceNotification'
import { PriceOverride, PriceOverrideRequestPayload } from '@/models/pricing/priceOverride'
import { PricingBudgetStats } from '@/models/stats/pricingBudgetStats'
import {
  S3GatewayBucketBinding,
  S3GatewayBucketBindPayload,
  S3GatewayBudgetPolicyDisablePayload,
  S3GatewayBudgetPolicyPayload,
  S3GatewayCreateLocalBucketPayload,
  S3GatewayCreateRemoteCachePayload,
  S3GatewayCredential,
  S3GatewayCredentialCreatePayload,
  S3GatewayCredentialDefaultVaultRole,
  S3GatewayCredentialDefaultVaultRoleOverride,
  S3GatewayCredentialDefaultVaultRoleOverridePayload,
  S3GatewayCredentialDefaultVaultRolePayload,
  S3GatewayCredentialScopeUpdatePayload,
  S3GatewayCredentialSelectedVault,
  S3GatewayCredentialSelectedVaultPayload,
  S3GatewayCredentialVaultRoleAssignment,
  S3GatewayCredentialVaultRoleAssignmentPayload,
  S3GatewayCredentialVaultRoleOverride,
  S3GatewayCredentialVaultRoleOverridePayload,
  S3GatewayStatus,
} from '@/models/s3Gateway'

interface VaultCommonFields {
  name: string
  description?: string
  quota?: number
  owner_id?: number
  slug?: string
  fuse_name?: string | null
}

// One vault role assignment: the subject on a vault.
interface VaultSubjectPayload {
  vault_id: number
  subject_type: 'user' | 'group'
  subject_id: number
}

export interface VaultRoleOverrideDTO {
  id: number
  assignment_id: number
  permission: { id?: number; qualified: string; description?: string; slug?: string }
  effect: 'allow' | 'deny'
  enabled: boolean
  glob_path: string
}

export interface RolePermissionValue {
  qualified: string
  value: boolean
}

export interface RoleCreatePayload {
  name: string
  description?: string
  permissions: RolePermissionValue[]
}

export interface RoleUpdatePayload {
  id: number
  name?: string
  description?: string
  permissions?: RolePermissionValue[]
}

// Commands covered by the server-owned contract (core/usage, generated into util/generated/wsContract.ts) are
// type-checked against it by util/wsContractCheck.ts; plain ones take the contract's type directly.
export interface WebSocketCommandMap {
  // The daemon's contract identity; the console compares ws_hash with WS_CONTRACT_HASH after connecting.
  'meta.contract.get': WsContract['meta.contract.get']

  // Auth
  // The access token arrives in the response envelope (`token`), not in data.
  'auth.login': { payload: { name: string; password: string }; response: { user: UserRecord } }

  'auth.register': {
    // role: an admin role name or id. The password is required here (only the CLI can generate one).
    payload: { name: string; email?: string; password: string; is_active?: boolean; role: string }
    response: { user: UserRecord }
  }

  // A patch. Role changes and deactivation end the account's sessions. Never send server-owned fields: core refuses
  // linux_uid, updated_by, protected, is_protected and system_only, and passwords go through change_password.
  'auth.user.update': {
    payload: { id: number; name?: string; email?: string | null; role?: string; is_active?: boolean }
    response: { user: UserRecord }
  }

  'auth.user.change_password': {
    payload: { id: number; old_password?: string; new_password: string }
    response: { user: UserRecord }
  }

  // Validates the envelope token; the payload is not read.
  'auth.isAuthenticated': { payload: null; response: { isAuthenticated: boolean; user?: UserRecord } }

  'auth.refresh': { payload: null; response: { user: UserRecord } }

  'auth.logout': WsContract['auth.logout']

  // May carry slim users (admin_role without permissions): use only the role's id and name from it.
  'auth.users.list': { payload: null; response: { users: UserRecord[] } }

  'auth.user.get': { payload: { id: number }; response: { user: UserRecord } }

  // Without confirm the reply is an error with data.code 'user_delete' and the question to ask. The user's vaults
  // are destroyed unless transfer_to names who gets them.
  'auth.user.delete': {
    payload: { id: number; confirm?: boolean; transfer_to?: number | null }
    response: { user_id: number }
  }

  'auth.user.get.byName': { payload: { name: string }; response: { user: UserRecord } }

  // Security posture for the signed-in account: the super admin's initial password file while its generated
  // password is still in use and the file is still on disk, else null. A warning, never a gate.
  'auth.security.status': { payload: null; response: { initial_password_file: string | null } }

  // Vault commands

  'storage.vault.list': { payload: null; response: { vaults: Vault[] } }

  // owner_id, description and quota (bytes, 0 = unlimited) are optional on both types. There is no mount point
  // input: the daemon picks a vault's backing directory itself.
  'storage.vault.add': {
    payload:
      | (VaultCommonFields & { type: 'local' })
      | (VaultCommonFields & {
          type: 's3'
          api_key_id: number
          bucket: string
          storage_tier_id?: string | null
          encrypt_upstream?: boolean
          sync?: Partial<RemoteSyncPolicy>
          accept_encryption_waiver?: boolean
          // #237: create a managed bucket or adopt an existing one (admin-enabled credentials). Absent or mode
          // 'existing' binds `bucket` as before. Refusals with data.code 'upstream_adoption' (resend with
          // provision.accept_adoption).
          provision?: Provision
        })
    response: { vault: LocalDiskVault | S3Vault }
  }

  // A patch: fields left out keep their current values; a vault's type can never change. A refusal with data.code
  // 'encryption_waiver' means the bucket already holds data; resend with accept_encryption_waiver once the person
  // accepts the message.
  'storage.vault.update': {
    payload: Partial<VaultCommonFields> & {
      id: number
      is_active?: boolean
      api_key_id?: number
      bucket?: string
      storage_tier_id?: string | null
      encrypt_upstream?: boolean
      sync?: Partial<RemoteSyncPolicy>
      accept_encryption_waiver?: boolean
    }
    response: { vault: LocalDiskVault | S3Vault }
  }

  // Safe deletion (#162): schedules the deletion (restorable until the retention window ends) or, with `now`, purges on
  // the next pass; on a vault already pending deletion, `now` purges it. Refusals with data.code
  // 'vault_upstream_key_loss' (resend with accept_key_loss) or 'vault_delete_now' (resend with confirm_now).
  'storage.vault.remove': {
    payload: { id: number; now?: boolean; delete_upstream?: boolean; confirm_now?: boolean; accept_key_loss?: boolean }
    response: { deletion: VaultDeletion | null }
  }

  // What a delete would do (windows, provider, whether the key was ever exported). Changes nothing.
  'storage.vault.remove.plan': { payload: { id: number }; response: { plan: VaultRemovalPlan } }

  // Deletions the caller could have made: pending, purging, and purged ones (tombstones), newest first.
  'storage.vault.deleted.list': { payload: null; response: { deleted: VaultDeletion[] } }

  'storage.vault.restore': { payload: { id: number }; response: { vault: LocalDiskVault | S3Vault } }

  'storage.vault.get': { payload: { id: number }; response: { vault: LocalDiskVault | S3Vault } }

  'storage.vault.sync': { payload: { id: number }; response: { status: 'started' | 'rerun_queued' } }

  // Sync conflicts (#187): open conflicts recorded under the `ask` policy, only in vaults where the caller holds
  // vault.sync.action.resolve_conflicts. Resolving is per item (one failure never aborts the batch).
  'sync.conflicts.summary': { payload: null; response: SyncConflictSummary }
  'sync.conflicts.list': { payload: { vault_id?: number | null }; response: { conflicts: SyncConflict[] } }
  'sync.conflicts.resolve': {
    payload: { resolution: SyncConflictResolution; conflict_ids: number[] }
    response: SyncConflictResolveResponse
  }

  // API Key commands

  // Older daemons send `keys` as a JSON-encoded string, newer ones as an array: parse with parseApiKeyList()
  // (features/credentials/types.ts).
  'storage.apiKey.list': { payload: null; response: { keys: string | APIKey[] } }

  // owner_id defaults to the caller; region to "auto". The credentials are checked against the provider first.
  'storage.apiKey.add': {
    payload: {
      name: string
      provider: ProviderName
      access_key: string
      secret_access_key: string
      endpoint: string
      region?: string
      owner_id?: number | null
    }
    response: { api_key: APIKey }
  }

  // Edit in place: same id, so vaults bound to the key keep their binding. Fields left out keep their value; an
  // empty or missing secret_access_key keeps the stored secret. Daemons before 1.9 answer "Unknown command".
  'storage.apiKey.update': {
    payload: {
      id: number
      name?: string
      provider?: ProviderName
      region?: string
      endpoint?: string
      access_key?: string
      secret_access_key?: string
    }
    response: { api_key: APIKey }
  }

  // Refused (data.code 'invalid') while any vault still uses the key.
  'storage.apiKey.remove': { payload: { id: number }; response: Record<string, never> | null }

  'storage.apiKey.get': { payload: { id: number }; response: { api_key: APIKey } }

  // Upstream control plane (#237) and event-driven sync (#96): ops::upstream. Authority is admin.upstream.*
  // (view, configure, provision, protect, unprotect, destroy) plus the key's own keys.api permission.
  // NeedsConfirmation codes: upstream_unprotect, upstream_destructive_lifecycle, upstream_adoption, upstream_cleanup.

  // provider_token: the Cloudflare account API token (R2 Queues + event notifications); never sent back.
  'upstream.admin.enable': {
    payload: { api_key_id: number; provider_token?: string; clear_provider_token?: boolean }
    response: { admin: AdminStatus }
  }
  'upstream.admin.disable': { payload: { api_key_id: number }; response: { admin: AdminStatus } }
  // probe re-checks the credential against the provider (configure); without it, the last probe (view).
  'upstream.admin.status': { payload: { api_key_id: number; probe?: boolean }; response: { admin: AdminStatus } }

  // One page of the account's ListBuckets merged with what Vaulthalla knows. No bucket-specific calls.
  'upstream.bucket.list': {
    payload: { api_key_id: number; token?: string; max?: number; state?: BucketState; filter?: string }
    response: { inventory: Inventory }
  }
  'upstream.bucket.protect': {
    payload: { api_key_id: number; bucket: string; reason: string }
    response: { bucket: BucketRow }
  }
  'upstream.bucket.unprotect': {
    payload: { api_key_id: number; bucket: string; confirm?: boolean }
    response: { bucket: BucketRow }
  }
  'upstream.bucket.inspect': { payload: { api_key_id: number; bucket: string }; response: { inspection: Inspection } }
  'upstream.bucket.lifecycle.set': {
    payload: { api_key_id: number; bucket: string } & LifecyclePatch
    response: { inspection: Inspection }
  }
  'upstream.bucket.adopt.preflight': {
    payload: { api_key_id: number; bucket: string; max_objects?: number; sample_heads?: number }
    response: { report: AdmissionReport }
  }
  'upstream.bucket.detach': { payload: { api_key_id: number; bucket: string }; response: { bucket: BucketRow } }
  'upstream.bucket.cleanup.preflight': {
    payload: { api_key_id: number; bucket: string }
    response: { plan: CleanupPlan }
  }
  'upstream.bucket.cleanup': {
    payload: { api_key_id: number; bucket: string; confirm_token: string; delete_bucket?: boolean }
    response: { result: CleanupResult }
  }

  'upstream.events.enable': {
    payload: { vault_id: number; prefix?: string; foreign_objects?: ForeignObjects }
    response: { events: EventStatus }
  }
  'upstream.events.disable': { payload: { vault_id: number }; response: { events: EventStatus } }
  'upstream.events.repair': { payload: { vault_id: number }; response: { events: EventStatus } }
  'upstream.events.status': { payload: { vault_id?: number }; response: { events: EventStatus[] } }

  'upstream.audit.list': { payload: { bucket?: string; limit?: number }; response: { entries: AuditEntry[] } }

  // File recovery: ops::recovery (core/include/ops/Recovery.hpp). Reads need filesystem Read on the point's path
  // (points you can't read are omitted / not_found); the vault policy needs vault sync.config view/edit, provider
  // versioning also admin.upstream.configure. NeedsConfirmation codes: RECOVERY_CODES in models/recovery.ts.
  'recovery.list': {
    payload: {
      vault_id: number
      path?: string
      refresh_provider?: boolean
      include_snapshots?: boolean
      include_versions?: boolean
      include_provider?: boolean
      limit?: number
    }
    response: { points: RecoveryPoint[] }
  }
  'recovery.inspect': { payload: { recovery_id: string }; response: { detail: RecoveryPointDetail } }
  'recovery.snapshot.create': {
    payload: { vault_id: number; path: string; name?: string }
    response: { detail: RecoveryPointDetail }
  }
  'recovery.point.delete': { payload: { recovery_id: string; confirm?: boolean }; response: { recovery_id: string } }
  // A point to restore (recovery_id), or a point in time (vault_id + path + at). Never atomic unless plan.atomic.
  'recovery.plan': {
    payload: {
      recovery_id?: string
      vault_id?: number
      path?: string
      at?: string | number
      destination?: string
      prune?: boolean
      refresh_provider?: boolean
    }
    response: { plan: RecoveryPlan }
  }
  'recovery.plan.get': { payload: { plan_id: number }; response: { plan: RecoveryPlan } }
  'recovery.restore': {
    payload: { plan_id: number; token?: string; accept_unverified?: boolean }
    response: { result: RecoveryRestoreResult }
  }
  'recovery.costs': { payload: { vault_id: number }; response: { costs: RecoveryCostReport } }
  'vault.recovery.status': {
    payload: { vault_id: number; refresh_provider?: boolean }
    response: { status: RecoveryStatus }
  }
  // mode provider_versioning needs disclosure_token from vault.recovery.disclosure, shown to a person first.
  'vault.recovery.update': { payload: { vault_id: number } & RecoveryUpdate; response: { status: RecoveryStatus } }
  'vault.recovery.disclosure': {
    payload: { vault_id: number; provider_retention?: ProviderRetentionInput }
    response: { disclosure: RecoveryDisclosure }
  }
  'vault.recovery.suspend': { payload: { vault_id: number; confirm?: boolean }; response: { status: RecoveryStatus } }

  // Roles and Permissions

  // permissions is a complete snapshot: every admin permission as {qualified, value}, or core refuses the edit.
  'role.admin.add': { payload: RoleCreatePayload; response: { role: AdminRoleDTO } }

  // A patch for name/description; permissions, when present, is a complete snapshot. Core refuses edits to
  // super_admin and to the actor's own role, and grants beyond the actor's own permissions.
  'role.admin.update': { payload: RoleUpdatePayload; response: { role: AdminRoleDTO } }

  'role.admin.delete': { payload: { id: number }; response: { role: number } }

  'role.admin.get': { payload: { id: number }; response: { role: AdminRoleDTO } }

  'role.admin.get.byName': { payload: { name: string }; response: { role: AdminRoleDTO } }

  'roles.admin.list': { payload: null; response: { roles: AdminRoleDTO[] } }

  // Role definitions only; assigning a role to a subject on a vault is role.vault.assign.
  'role.vault.add': { payload: RoleCreatePayload; response: { role: VaultRoleDTO } }

  'role.vault.update': { payload: RoleUpdatePayload; response: { role: VaultRoleDTO } }

  'role.vault.delete': { payload: { id: number }; response: { role_id: number } }

  'role.vault.get': { payload: { id: number }; response: { role: VaultRoleDTO } }

  'role.vault.get.byName': { payload: { name: string }; response: { role: VaultRoleDTO } }

  'roles.vault.list': { payload: null; response: { roles: VaultRoleDTO[] } }

  'roles.vault.list.assigned': { payload: { id: number }; response: { assigned_roles: VaultRoleDTO[] } }

  'role.vault.assign': {
    payload: VaultSubjectPayload & { id: number }
    response: { assignment: VaultRoleDTO }
  }

  'role.vault.unassign': {
    payload: VaultSubjectPayload
    response: { unassigned: boolean }
  }

  // Path-scoped allow/deny overrides on one assignment (same ops as `vh vault role override ...`).
  'role.vault.overrides.list': { payload: VaultSubjectPayload; response: { overrides: VaultRoleOverrideDTO[] } }

  // permissions: value true = allow, false = deny. pattern is a vault-relative glob ("/docs/**").
  'role.vault.overrides.add': {
    payload: VaultSubjectPayload & { permissions: { qualified: string; value: boolean }[]; pattern: string; enabled?: boolean }
    response: { overrides: VaultRoleOverrideDTO[] }
  }

  'role.vault.overrides.update': {
    payload: VaultSubjectPayload & { override_id: number; effect?: 'allow' | 'deny'; pattern?: string; enabled?: boolean }
    response: { override: VaultRoleOverrideDTO }
  }

  'role.vault.overrides.remove': {
    payload: VaultSubjectPayload & { override_id: number }
    response: { removed: boolean }
  }

  'permission.get': { payload: { id: number }; response: { permission: Permission } }

  'permission.get.byName': { payload: { name: string }; response: { permission: Permission } }

  'permissions.list': { payload: null; response: { permissions: Permission[] } }

  // Settings
  'settings.get': { payload: null; response: { settings: Settings } }

  // Any signed-in user: which share links the operator allows and the defaults for new vaults.
  'settings.policy.get': { payload: null; response: { policy: ServerPolicy } }

  // A JSON merge patch (RFC 7386) onto the current config: send only what changed; null removes an optional key.
  'settings.update': { payload: Partial<Record<keyof Settings, SettingsSection>>; response: { settings: Settings } }

  // Operator email administration
  'email.config.get': { payload: null; response: OperatorEmailConfigResponse }

  'email.config.update': { payload: OperatorEmailConfigPatch; response: OperatorEmailConfigResponse }

  'email.provider.secret.set': { payload: OperatorEmailSecretPayload; response: { secrets: OperatorEmailConfigResponse['secrets'] } }

  'email.test.send': { payload: OperatorEmailTestPayload; response: OperatorEmailTestResponse }

  'email.history': { payload: { limit?: number }; response: { history: OperatorEmailHistoryRecord[] } }

  // S3 price budget command center
  'pricing.budget.policy.list': {
    payload: { vault_id?: number | null; gateway_credential_id?: number | null; include_inactive?: boolean }
    response: { policies: PriceBudgetPolicy[] }
  }

  'pricing.budget.policy.upsert': { payload: PriceBudgetPolicyPayload; response: { policy: PriceBudgetPolicy } }

  'pricing.budget.policy.disable': {
    payload: { scope: PriceBudgetScope; provider_key?: string | null; vault_id?: number | null; gateway_credential_id?: number | null }
    response: { disabled: boolean }
  }

  'pricing.budget.ledger.list': {
    payload: { vault_id?: number | null; gateway_credential_id?: number | null; limit?: number }
    response: { ledger: PriceBudgetLedgerEntry[] }
  }

  'pricing.budget.status': {
    payload: { vault_id?: number | null; gateway_credential_id?: number | null; limit?: number; include_inactive?: boolean }
    response: PriceBudgetStatus
  }

  'pricing.budget.preflight': { payload: PriceBudgetPreflightPayload; response: PriceBudgetPreflightResult }

  'pricing.budget.override.request': { payload: PriceOverrideRequestPayload; response: { override: PriceOverride } }

  'pricing.budget.override.approve': { payload: { override_id: number }; response: { override: PriceOverride } }

  'pricing.budget.override.deny': {
    payload: { override_id: number; reason?: string | null }
    response: { override: PriceOverride }
  }

  'pricing.budget.override.list': {
    payload: { vault_id?: number | null; limit?: number; include_expired?: boolean }
    response: { overrides: PriceOverride[] }
  }

  'pricing.notifications.list': {
    payload: { vault_id?: number | null; limit?: number; include_acknowledged?: boolean }
    // `summary` always covers every open alert in scope, whatever `limit` and `include_acknowledged` are.
    response: { notifications: PriceNotification[]; summary: PriceNotificationSummary }
  }

  'pricing.notifications.ack': {
    payload: { notification_id: number; vault_id?: number | null }
    response: { notification: PriceNotification }
  }

  // S3 gateway management

  's3.gateway.status': { payload: null; response: { status: S3GatewayStatus } }

  's3.gateway.credentials.create': {
    payload: S3GatewayCredentialCreatePayload
    response: { credential: S3GatewayCredential; secret_access_key: string }
  }

  's3.gateway.credentials.list': {
    payload: { include_disabled?: boolean }
    response: { credentials: S3GatewayCredential[] }
  }

  's3.gateway.credentials.revoke': {
    payload: { access_key?: string; name?: string }
    response: { revoked: boolean }
  }

  's3.gateway.credentials.scope.update': {
    payload: S3GatewayCredentialScopeUpdatePayload
    response: { credential: S3GatewayCredential | null }
  }

  's3.gateway.credentials.defaultRole.get': {
    payload: { credential_id?: number; access_key?: string; name?: string; credential_name?: string }
    response: { credential: S3GatewayCredential; default_role: S3GatewayCredentialDefaultVaultRole | null }
  }

  's3.gateway.credentials.defaultRole.set': {
    payload: S3GatewayCredentialDefaultVaultRolePayload
    response: { credential: S3GatewayCredential; default_role: S3GatewayCredentialDefaultVaultRole | null }
  }

  's3.gateway.credentials.defaultRole.clear': {
    payload: { credential_id?: number; access_key?: string; name?: string; credential_name?: string }
    response: { cleared: boolean; credential: S3GatewayCredential }
  }

  's3.gateway.credentials.selectedVaults.list': {
    payload: { credential_id?: number; access_key?: string; name?: string; credential_name?: string }
    response: { credential: S3GatewayCredential; selected_vaults: S3GatewayCredentialSelectedVault[]; vaults?: S3GatewayCredentialSelectedVault[] }
  }

  's3.gateway.credentials.selectedVaults.replace': {
    payload: Omit<S3GatewayCredentialSelectedVaultPayload, 'vault_id' | 'vault_name' | 'vault' | 'enabled'>
    response: { credential: S3GatewayCredential; selected_vaults: S3GatewayCredentialSelectedVault[]; vaults?: S3GatewayCredentialSelectedVault[] }
  }

  's3.gateway.credentials.selectedVaults.add': {
    payload: Omit<S3GatewayCredentialSelectedVaultPayload, 'vault_ids' | 'selected_vault_ids'>
    response: { credential: S3GatewayCredential; selected_vault: S3GatewayCredentialSelectedVault }
  }

  's3.gateway.credentials.selectedVaults.remove': {
    payload: Omit<S3GatewayCredentialSelectedVaultPayload, 'vault_ids' | 'selected_vault_ids' | 'enabled'>
    response: { removed: boolean; credential: S3GatewayCredential; vault?: { id: number; name: string } | null }
  }

  's3.gateway.credentials.defaultRole.overrides.list': {
    payload: { credential_id?: number; access_key?: string; name?: string; credential_name?: string }
    response: { credential: S3GatewayCredential; default_role: S3GatewayCredentialDefaultVaultRole | null; overrides: S3GatewayCredentialDefaultVaultRoleOverride[] }
  }

  's3.gateway.credentials.defaultRole.overrides.add': {
    payload: Omit<S3GatewayCredentialDefaultVaultRoleOverridePayload, 'override_id'>
    response: { override: S3GatewayCredentialDefaultVaultRoleOverride }
  }

  's3.gateway.credentials.defaultRole.overrides.remove': {
    payload: Pick<S3GatewayCredentialDefaultVaultRoleOverridePayload, 'credential_id' | 'access_key' | 'name' | 'credential_name' | 'override_id'>
    response: { removed: boolean; credential: S3GatewayCredential }
  }

  's3.gateway.credentials.roles.list': {
    payload: { credential_id?: number; access_key?: string; name?: string; credential_name?: string }
    response: { credential: S3GatewayCredential; roles: S3GatewayCredentialVaultRoleAssignment[]; assignments?: S3GatewayCredentialVaultRoleAssignment[] }
  }

  's3.gateway.credentials.roles.assign': {
    payload: S3GatewayCredentialVaultRoleAssignmentPayload
    response: { assignment: S3GatewayCredentialVaultRoleAssignment; role?: S3GatewayCredentialVaultRoleAssignment }
  }

  's3.gateway.credentials.roles.revoke': {
    payload: Omit<
      S3GatewayCredentialVaultRoleAssignmentPayload,
      'vault_role_id' | 'vault_role_name' | 'role_id' | 'role_name' | 'role' | 'enabled'
    >
    response: { revoked: boolean; credential: S3GatewayCredential; vault?: { id: number; name: string } | null }
  }

  's3.gateway.credentials.roles.overrides.list': {
    payload: Pick<S3GatewayCredentialVaultRoleOverridePayload, 'credential_id' | 'access_key' | 'name' | 'credential_name' | 'vault_id' | 'vault_name' | 'vault'>
    response: { credential: S3GatewayCredential; vault?: { id: number; name: string } | null; overrides: S3GatewayCredentialVaultRoleOverride[] }
  }

  's3.gateway.credentials.roles.overrides.add': {
    payload: Omit<S3GatewayCredentialVaultRoleOverridePayload, 'override_id'>
    response: { override: S3GatewayCredentialVaultRoleOverride }
  }

  's3.gateway.credentials.roles.overrides.remove': {
    payload: Pick<
      S3GatewayCredentialVaultRoleOverridePayload,
      'credential_id' | 'access_key' | 'name' | 'credential_name' | 'vault_id' | 'vault_name' | 'vault' | 'override_id'
    >
    response: { removed: boolean; credential: S3GatewayCredential; vault?: { id: number; name: string } | null }
  }

  's3.gateway.buckets.list': { payload: null; response: { buckets: S3GatewayBucketBinding[] } }

  's3.gateway.buckets.bind': { payload: S3GatewayBucketBindPayload; response: { bound: boolean } }

  's3.gateway.buckets.unbind': { payload: { bucket_name: string }; response: { unbound: boolean } }

  's3.gateway.buckets.createLocal': {
    payload: S3GatewayCreateLocalBucketPayload
    response: { bucket: S3GatewayBucketBinding }
  }

  's3.gateway.buckets.createRemoteCache': {
    payload: S3GatewayCreateRemoteCachePayload
    response: { bucket: S3GatewayBucketBinding }
  }

  's3.gateway.budget.policy.list': {
    payload: { gateway_credential_id?: number | null; vault_id?: number | null; include_inactive?: boolean }
    response: { policies: PriceBudgetPolicy[] }
  }

  's3.gateway.budget.policy.upsert': { payload: S3GatewayBudgetPolicyPayload; response: { policy: PriceBudgetPolicy } }

  's3.gateway.budget.policy.disable': { payload: S3GatewayBudgetPolicyDisablePayload; response: { disabled: boolean } }

  's3.gateway.budget.ledger.list': {
    payload: { gateway_credential_id?: number | null; vault_id?: number | null; limit?: number }
    response: { ledger: PriceBudgetLedgerEntry[] }
  }

  's3.gateway.budget.status': {
    payload: { gateway_credential_id?: number | null; vault_id?: number | null; limit?: number }
    response: Pick<PriceBudgetStatus, 'policies' | 'ledger' | 'trends'>
  }

  // Dashboard preferences

  'dashboard.preferences.get': { payload: DashboardPreferencePayload; response: { preferences: DashboardPreference } }

  'dashboard.preferences.update': { payload: DashboardPreferenceUpdatePayload; response: { preferences: DashboardPreference } }

  'dashboard.preferences.reset': { payload: DashboardPreferencePayload; response: { reset: boolean; deleted?: boolean } }

  // Group commands

  'group.add': {
    payload: { name: string; description?: string; linux_gid?: number }
    response: { name: string; group: GroupRecord }
  }

  'group.remove': { payload: { id: number }; response: { id: number } }

  // A patch: name, description and linux_gid are each optional.
  'group.update': {
    payload: { id: number; name?: string; description?: string; linux_gid?: number }
    response: { id: number; name: string; group: GroupRecord }
  }

  'group.get': { payload: { id: number }; response: { group: GroupRecord } }

  // Every group for group viewers; otherwise only the caller's own groups.
  'groups.list': { payload: null; response: { groups: GroupRecord[] } }

  'group.member.add': {
    payload: { group_id: number; user_id: number }
    response: { group: GroupRecord; group_id: number; user_id: number }
  }

  'group.member.remove': {
    payload: { group_id: number; user_id: number }
    response: { group: GroupRecord; group_id: number; user_id: number }
  }

  'group.get.byName': { payload: { name: string }; response: { group: GroupRecord } }

  'groups.list.byUser': { payload: { user_id: number }; response: { groups: GroupRecord[] } }


  // FS commands

  'fs.dir.create': { payload: { vault_id: number; path: string }; response: { path: string } }

  'fs.dir.list': {
    payload: { vault_id: number; path?: string | undefined }
    response: { vault: string; path: string; entry?: Directory; files: (File | Directory)[] }
  }

  'fs.metadata': {
    payload: { vault_id?: number | null; path?: string }
    response: { vault?: string; path: string; entry: File | Directory | ShareMetadataResponse['entry'] }
  }

  'fs.list': {
    payload: { vault_id?: number | null; path?: string }
    response: { vault?: string; path: string; entry?: File | Directory | ShareMetadataResponse['entry']; files: (File | Directory | ShareMetadataResponse['entry'])[] }
  }

  'fs.download.start': { payload: { path?: string; vault_id?: number | null }; response: ShareDownloadStartResponse }

  'fs.download.chunk': {
    payload: { transfer_id: string; offset: number; length?: number }
    response: ShareDownloadChunkResponse
  }

  'fs.download.cancel': { payload: { transfer_id: string }; response: ShareDownloadCancelResponse }

  // Native ws transfers (the console uploads over HTTP); console and share-session forms.
  'fs.upload.start': WsContract['fs.upload.start']

  'fs.upload.finish': WsContract['fs.upload.finish']

  'fs.upload.cancel': WsContract['fs.upload.cancel']

  'fs.entry.delete': { payload: { vault_id: number; path: string }; response: { path: string } }

  'fs.entry.move': { payload: { vault_id: number; from: string; to: string }; response: { from: string; to: string } }

  'fs.entry.copy': { payload: { vault_id: number; from: string; to: string }; response: { from: string; to: string } }

  'fs.entry.rename': { payload: { vault_id: number; from: string; to: string }; response: { from: string; to: string } }

  // Share management commands

  'share.link.create': { payload: ShareLinkCreatePayload; response: ShareLinkTokenResponse }

  'share.link.get': { payload: { id: string }; response: ShareLinkResponse }

  'share.link.list': {
    payload: { vault_id?: number | null; limit?: number; offset?: number; page?: number; sort?: string; direction?: 'asc' | 'desc' }
    response: ShareLinkListResponse
  }

  'share.link.update': { payload: ShareLinkUpdatePayload; response: ShareLinkResponse }

  'share.link.revoke': { payload: { id: string }; response: { revoked: boolean } }

  'share.link.rotate_token': { payload: { id: string }; response: ShareLinkTokenResponse }

  // Public/share session commands

  'share.session.open': { payload: { public_token: string }; response: ShareSessionOpenResponse }

  'share.email.challenge.start': {
    payload: { email: string; public_token?: string; session_token?: string }
    response: ShareEmailChallengeStartResponse
  }

  'share.email.challenge.confirm': {
    payload: { challenge_id: string; code: string; session_id?: string; session_token?: string }
    response: ShareEmailChallengeConfirmResponse
  }

  // Ready share-mode filesystem and transfer commands

  'share.fs.metadata': { payload: { path?: string }; response: ShareMetadataResponse }

  'share.fs.list': { payload: { path?: string }; response: ShareListResponse }

  'share.download.start': { payload: { path?: string }; response: ShareDownloadStartResponse }

  'share.download.chunk': {
    payload: { transfer_id: string; offset: number; length?: number }
    response: ShareDownloadChunkResponse
  }

  'share.download.cancel': { payload: { transfer_id: string }; response: ShareDownloadCancelResponse }

  'share.preview.get': { payload: { path?: string; size?: number }; response: SharePreviewResponse }

  'share.upload.start': {
    payload: { path?: string; filename: string; size_bytes: number; mime_type?: string | null; duplicate_policy?: 'reject' }
    response: ShareUploadStartResponse
  }

  'share.upload.finish': { payload: { upload_id: string }; response: ShareUploadFinishResponse }

  'share.upload.cancel': { payload: { upload_id: string }; response: ShareUploadCancelResponse }

  // stats
  'stats.vault': { payload: { vault_id: number }; response: { stats: VaultStats } }

  'stats.vault.sync': { payload: { vault_id: number }; response: { stats: VaultSyncHealth } }

  'stats.vault.activity': { payload: { vault_id: number }; response: { stats: VaultActivity } }

  'stats.vault.shares': { payload: { vault_id: number }; response: { stats: VaultShareStats } }

  'stats.vault.recovery': { payload: { vault_id: number }; response: { stats: VaultRecovery } }

  'stats.vault.operations': { payload: { vault_id: number }; response: { stats: OperationStats } }

  'stats.vault.security': { payload: { vault_id: number }; response: { stats: VaultSecurity } }

  'stats.vault.storage': { payload: { vault_id: number }; response: { stats: StorageBackendStats } }

  'stats.vault.retention': { payload: { vault_id: number }; response: { stats: RetentionStats } }

  'stats.vault.trends': { payload: { vault_id: number; window_hours?: number }; response: { stats: StatsTrends } }

  'stats.vault.pricing': { payload: { vault_id: number }; response: { stats: PricingBudgetStats } }

  'stats.dashboard.overview': { payload: DashboardOverviewRequest; response: { stats: DashboardOverview } }

  // Cheap admin-only rollup of the default overview cards (no cards, sections or series). Daemons before 1.9 answer
  // "Unknown command".
  'stats.dashboard.severity': {
    payload: null
    response: {
      stats: {
        overall_status: DashboardSeverity
        error_count: number
        warning_count: number
        checked_at: number | string | null
      }
    }
  }

  'stats.pricing.budget': { payload: { vault_id?: number | null }; response: { stats: PricingBudgetStats } }

  'stats.system.health': { payload: null; response: { stats: SystemHealth } }

  'stats.system.threadpools': { payload: null; response: { stats: ThreadPoolManagerStats } }

  'stats.system.fuse': { payload: null; response: { stats: FuseStats } }

  'stats.system.db': { payload: null; response: { stats: DbStats } }

  'stats.system.operations': { payload: null; response: { stats: OperationStats } }

  'stats.system.connections': { payload: null; response: { stats: ConnectionStats } }

  'stats.system.storage': { payload: null; response: { stats: StorageBackendStats } }

  'stats.system.retention': { payload: null; response: { stats: RetentionStats } }

  'stats.system.trends': { payload: { window_hours?: number }; response: { stats: StatsTrends } }

  'stats.system.pricing': { payload: null; response: { stats: PricingBudgetStats } }

  'stats.fs.cache': { payload: null; response: { stats: CacheStats } }

  'stats.http.cache': { payload: null; response: { stats: CacheStats } }

  // Paired devices (Vaulthalla Desktop). The device's own side (device.pair.*, device.identity.rotate,
  // device.server.identity) only answers on the device listener (mutual TLS, port 36972); the console never sends it,
  // but every registered command is typed here.
  'device.pair.request': WsContract['device.pair.request']
  'device.pair.confirm': WsContract['device.pair.confirm']
  'device.pair.status': WsContract['device.pair.status']
  'device.identity.rotate': WsContract['device.identity.rotate']
  'device.server.identity': WsContract['device.server.identity']
  // Any signed-in user pairs devices to their own account: open a 10-minute window, then approve a request by picking
  // the one of its three code_choices the device shows (a wrong pick denies the request).
  'device.pairing.open': WsContract['device.pairing.open']
  'device.pairing.close': WsContract['device.pairing.close']
  'device.pairing.pending': WsContract['device.pairing.pending']
  'device.pairing.approve': { payload: WsContract['device.pairing.approve']['payload']; response: { device: Device } }
  'device.pairing.deny': WsContract['device.pairing.deny']
  // `all` (every user's devices) is for super admins.
  'device.list': { payload: WsContract['device.list']['payload']; response: { devices: Device[] } }
  'device.rename': { payload: WsContract['device.rename']['payload']; response: { device: Device } }
  'device.revoke': { payload: WsContract['device.revoke']['payload']; response: { device: Device } }
  // Super admins: whether devices on other hosts may connect (the listener is loopback-only otherwise).
  'device.remote.status': WsContract['device.remote.status']
  'device.remote.enable': WsContract['device.remote.enable']
  'device.remote.disable': WsContract['device.remote.disable']
}

export type WSCommandPayload<K extends keyof WebSocketCommandMap> = WebSocketCommandMap[K]['payload']
export type WSCommandResponse<K extends keyof WebSocketCommandMap> = WebSocketCommandMap[K]['response']
