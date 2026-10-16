// Readable names for RBAC permissions. The catalog groups permissions by their qualified-name prefix and turns the
// remaining segments into a label; descriptions always come from the server. A permission the catalog doesn't know
// still renders (grouped by its first segments, labelled from its name), so new core permissions never disappear.

import type { PermissionRecord } from '@/features/access/types'

export interface PermissionGroupDef {
  prefix: string
  label: string
  hint?: string
  section: string
}

const ADMIN_GROUPS: PermissionGroupDef[] = [
  { prefix: 'admin.identities.users', label: 'User accounts', section: 'Identities', hint: 'Accounts without admin permissions' },
  { prefix: 'admin.identities.admins', label: 'Admin accounts', section: 'Identities', hint: 'Accounts whose role grants admin permissions' },
  { prefix: 'admin.identities.groups', label: 'Groups', section: 'Identities' },
  { prefix: 'admin.vaults.self', label: 'Own vaults', section: 'Vaults', hint: 'Vaults the account owns' },
  { prefix: 'admin.vaults.user', label: 'Users’ vaults', section: 'Vaults', hint: 'Vaults owned by user accounts' },
  { prefix: 'admin.vaults.admin', label: 'Admins’ vaults', section: 'Vaults', hint: 'Vaults owned by admin accounts' },
  { prefix: 'admin.roles.admin', label: 'Admin roles', section: 'Roles' },
  { prefix: 'admin.roles.vault', label: 'Vault roles', section: 'Roles' },
  { prefix: 'admin.keys.api.self', label: 'Own provider credentials', section: 'Keys', hint: 'S3/R2 API keys the account owns' },
  { prefix: 'admin.keys.api.user', label: 'Users’ provider credentials', section: 'Keys' },
  { prefix: 'admin.keys.api.admin', label: 'Admins’ provider credentials', section: 'Keys' },
  { prefix: 'admin.keys.encryption', label: 'Encryption keys', section: 'Keys' },
  { prefix: 'admin.s3_gateway', label: 'S3 gateway', section: 'Services' },
  {
    prefix: 'admin.upstream',
    label: 'Upstream buckets',
    section: 'Services',
    hint: 'S3/R2 bucket administration: inventory, locks, lifecycle, event sync and cleanup',
  },
  { prefix: 'admin.settings', label: 'Settings', section: 'System' },
  { prefix: 'admin.stats', label: 'Health and stats', section: 'System', hint: 'Server, daemon and system telemetry (the Health area)' },
  { prefix: 'admin.audits', label: 'Audit logs', section: 'System' },
]

const VAULT_GROUPS: PermissionGroupDef[] = [
  { prefix: 'vault.fs.files', label: 'Files', section: 'Content' },
  { prefix: 'vault.fs.directories', label: 'Folders', section: 'Content' },
  { prefix: 'vault.sync', label: 'Sync', section: 'Operations' },
  { prefix: 'vault.roles', label: 'Access & roles', section: 'Governance', hint: 'Who can grant, change and revoke access in the vault' },
]

const LEAF_LABELS: Record<string, string> = {
  view: 'View',
  add: 'Add',
  edit: 'Edit',
  delete: 'Delete',
  remove: 'Delete',
  create: 'Create',
  'reset-password': 'Reset passwords',
  'add-member': 'Add members',
  'remove-member': 'Remove members',
  'view-members': 'View members',
  view_stats: 'View statistics',
  configure: 'Configure lifecycle and events',
  provision: 'Create and adopt buckets',
  protect: 'Protect buckets',
  unprotect: 'Remove bucket protection',
  destroy: 'Detach and delete buckets',
  export: 'Export',
  rotate: 'Rotate',
  consume: 'Use in vaults',
  manage_service: 'Manage the service',
  manage_credentials: 'Manage credentials',
  assign_principal: 'Assign credentials to others',
  manage_buckets: 'Manage bucket bindings',
  manage_budgets: 'Manage budgets',
  preview: 'Preview',
  upload: 'Upload',
  download: 'Download',
  overwrite: 'Overwrite',
  rename: 'Rename',
  move: 'Move',
  copy: 'Copy',
  list: 'List contents',
  touch: 'Create folders',
  'share.internal': 'Share with vault members',
  'share.public': 'Share by public link',
  'share.public_with_val': 'Share by verified link',
  'config.view': 'View sync settings',
  'config.edit': 'Edit sync settings',
  'action.trigger': 'Run a sync',
  'action.sign_waiver': 'Sign encryption waiver',
  'action.resolve_conflicts': 'Resolve sync conflicts',
  assign: 'Assign roles',
  modify: 'Change roles',
  revoke: 'Revoke roles',
  assign_override: 'Assign path overrides',
  modify_override: 'Change path overrides',
  revoke_override: 'Revoke path overrides',
  view_override: 'View path overrides',
}

const humanize = (value: string) => {
  const text = value.replace(/[._-]+/g, ' ').trim()
  return text.charAt(0).toUpperCase() + text.slice(1)
}

export const groupDefsFor = (type: 'admin' | 'vault') => (type === 'admin' ? ADMIN_GROUPS : VAULT_GROUPS)

const defFor = (type: 'admin' | 'vault', qualified: string): PermissionGroupDef => {
  let best: PermissionGroupDef | undefined
  for (const def of groupDefsFor(type))
    if ((qualified === def.prefix || qualified.startsWith(`${def.prefix}.`)) && (!best || def.prefix.length > best.prefix.length)) best = def
  if (best) return best
  const segments = qualified.split('.')
  const prefix = segments.slice(0, Math.max(1, segments.length - 1)).join('.')
  return { prefix, label: humanize(segments.slice(1, -1).join(' ') || prefix), section: 'Other' }
}

export const permissionLabel = (type: 'admin' | 'vault', qualified: string): string => {
  const def = defFor(type, qualified)
  const rest = qualified.slice(def.prefix.length + 1)
  // Settings permissions read "View websocket settings" rather than "Websocket view".
  if (def.prefix === 'admin.settings') {
    const [module, verb] = rest.split('.')
    return `${verb === 'edit' ? 'Edit' : 'View'} ${module} settings`
  }
  return LEAF_LABELS[rest] ?? humanize(rest)
}

export interface PermissionItem extends PermissionRecord {
  label: string
}

export interface PermissionGroup {
  key: string
  label: string
  hint?: string
  section: string
  items: PermissionItem[]
}

// Groups in catalog order (unknown groups last), items in the server's bit order.
export const groupPermissions = (type: 'admin' | 'vault', permissions: PermissionRecord[]): PermissionGroup[] => {
  const order = groupDefsFor(type).map(d => d.prefix)
  const groups = new Map<string, PermissionGroup>()
  for (const permission of permissions) {
    const def = defFor(type, permission.qualified)
    let group = groups.get(def.prefix)
    if (!group) {
      group = { key: def.prefix, label: def.label, hint: def.hint, section: def.section, items: [] }
      groups.set(def.prefix, group)
    }
    group.items.push({ ...permission, label: permissionLabel(type, permission.qualified) })
  }
  const rank = (key: string) => {
    const i = order.indexOf(key)
    return i === -1 ? order.length : i
  }
  return [...groups.values()]
    .map(g => ({ ...g, items: [...g.items].sort((a, b) => a.bit_position - b.bit_position) }))
    .sort((a, b) => rank(a.key) - rank(b.key) || a.label.localeCompare(b.label))
}
