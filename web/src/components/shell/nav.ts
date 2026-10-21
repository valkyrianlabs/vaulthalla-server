import type React from 'react'
import type { Requirement } from '@/lib/permissions'
import {
  CloudIcon,
  ArrowRightArrowLeftIcon,
  EnvelopeIcon,
  FolderIcon,
  GaugeHighIcon,
  KeySkeletonIcon,
  LinkIcon,
  PeopleGroupIcon,
  SackDollarIcon,
  ShareNodesIcon,
  ShieldKeyholeIcon,
  SlidersIcon,
  UsersIcon,
  VaultIcon,
} from '@/components/ui/icons'

export interface NavItem {
  label: string
  href: string
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>
  requires?: Requirement
  keywords?: string
  // Shown only while this live signal is on (e.g. there are open sync conflicts the account can resolve).
  shownWhen?: NavSignal
}

export type NavSignal = 'syncConflicts'

export interface NavSection {
  label?: string
  items: NavItem[]
}

// The whole console in one map. Items are filtered by the session's permissions (UI only; the server enforces).
export const NAV: NavSection[] = [
  {
    items: [
      { label: 'Files', href: '/files', icon: FolderIcon, keywords: 'browse upload download fs' },
      { label: 'Shares', href: '/shares', icon: ShareNodesIcon, keywords: 'links public' },
      {
        label: 'Vaults',
        href: '/vaults',
        icon: VaultIcon,
        requires: { anyOf: ['admin.vaults.self.view', 'admin.vaults.user.view', 'admin.vaults.admin.view'] },
        keywords: 'storage buckets local s3',
      },
      // Everyone pairs Vaulthalla Desktop to their own account; super admins also see /devices/all.
      { label: 'Devices', href: '/devices', icon: LinkIcon, keywords: 'pair paired desktop mac revoke remote' },
    ],
  },
  {
    label: 'Access',
    items: [
      { label: 'Users', href: '/users', icon: UsersIcon, requires: { permission: 'admin.identities.users.view' } },
      { label: 'Groups', href: '/groups', icon: PeopleGroupIcon, requires: { permission: 'admin.identities.groups.view' } },
      {
        label: 'Roles',
        href: '/roles',
        icon: ShieldKeyholeIcon,
        requires: { anyOf: ['admin.roles.admin.view', 'admin.roles.vault.view'] },
        keywords: 'permissions rbac',
      },
    ],
  },
  {
    label: 'Storage & cost',
    items: [
      {
        label: 'Provider credentials',
        href: '/credentials',
        icon: KeySkeletonIcon,
        requires: { prefix: 'admin.keys.api' },
        keywords: 'api keys s3 r2 aws',
      },
      { label: 'Cost control', href: '/cost', icon: SackDollarIcon, requires: { superAdmin: true }, keywords: 'budget pricing spend' },
      { label: 'S3 gateway', href: '/s3-gateway', icon: CloudIcon, requires: { permission: 'admin.s3_gateway.view' } },
    ],
  },
  {
    label: 'System',
    items: [
      {
        label: 'Sync Conflicts',
        href: '/sync-conflicts',
        icon: ArrowRightArrowLeftIcon,
        shownWhen: 'syncConflicts',
        keywords: 'sync conflict resolve keep local remote s3',
      },
      { label: 'Health', href: '/health', icon: GaugeHighIcon, requires: { permission: 'admin.stats.view' }, keywords: 'dashboard stats status' },
      { label: 'Notifications', href: '/notifications', icon: EnvelopeIcon, requires: { superAdmin: true }, keywords: 'operator email' },
      { label: 'Settings', href: '/settings', icon: SlidersIcon, requires: { superAdmin: true }, keywords: 'config' },
    ],
  },
]
