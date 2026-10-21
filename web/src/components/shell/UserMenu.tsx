'use client'

import React from 'react'
import { useRouter } from 'next/navigation'
import { useSession, logout } from '@/lib/session'
import { DropdownMenu } from '@/components/ui/Menu'
import { LinkIcon, RightFromBracketIcon, UserIcon } from '@/components/ui/icons'
import { titleCase } from '@/lib/format'

export const Avatar = ({ name, className = '' }: { name: string; className?: string }) => (
  <span
    aria-hidden
    className={`grid size-8 shrink-0 place-items-center rounded-full border border-accent-line bg-accent-soft text-[13px] font-semibold text-accent-text uppercase ${className}`}>
    {name.slice(0, 1)}
  </span>
)

export const UserMenu = () => {
  const user = useSession(state => state.user)
  const router = useRouter()
  if (!user) return null
  return (
    <DropdownMenu
      label="Account"
      className="w-64"
      header={
        <div className="flex items-center gap-3 px-2.5 py-2">
          <Avatar name={user.name} />
          <div className="min-w-0">
            <div className="truncate text-sm font-medium text-fg" title={user.name}>
              {user.name}
            </div>
            <div className="truncate text-xs text-fg-subtle">{user.admin_role?.name ? titleCase(user.admin_role.name) : 'User'}</div>
          </div>
        </div>
      }
      entries={[
        { key: 'account', label: 'Your account', icon: UserIcon, onSelect: () => router.push('/account') },
        { key: 'devices', label: 'Your devices', icon: LinkIcon, onSelect: () => router.push('/devices') },
        'separator',
        { key: 'logout', label: 'Log out', icon: RightFromBracketIcon, onSelect: () => void logout() },
      ]}
      trigger={
        <button type="button" aria-label={`Account menu for ${user.name}`} className="rounded-full p-0.5 transition-shadow hover:shadow-[0_0_0_2px_var(--accent-line)]">
          <Avatar name={user.name} />
        </button>
      }
    />
  )
}
