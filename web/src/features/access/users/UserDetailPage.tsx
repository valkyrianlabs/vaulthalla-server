'use client'

import React, { useCallback, useMemo, useState } from 'react'
import Link from 'next/link'
import dynamic from 'next/dynamic'
import { useParams, useRouter } from 'next/navigation'
import { useWs } from '@/lib/query'
import { useCan } from '@/lib/permissions'
import { useSession } from '@/lib/session'
import { formatDateTime } from '@/lib/format'
import { Button } from '@/components/ui/Button'
import { DefinitionList, PageHeader, Panel } from '@/components/ui/Panel'
import { QueryState } from '@/components/ui/State'
import { KeyIcon, TrashIcon } from '@/components/ui/icons'
import { Avatar } from '@/components/shell/UserMenu'
import type { UserRecord } from '@/features/access/types'
import { accountRules } from '@/features/access/rbac'
import { AccountBadges, BackLink, DeniedState, Notice, Reason, StatusBadge, WithReason, roleLabel, userHref } from '@/features/access/shared'
import { useAdminRoles } from '@/features/access/users/RoleSelect'
import { AccessPanel, GroupsPanel, ProfilePanel, VaultAccessPanel } from '@/features/access/users/UserSections'

// Radix dialogs load on first open, not with the page.
const ResetPasswordDialog = dynamic(() => import('@/features/access/users/UserDialogs').then(m => m.ResetPasswordDialog))
const DeleteUserDialog = dynamic(() => import('@/features/access/users/UserDialogs').then(m => m.DeleteUserDialog))
// #360: another account's MFA (status, require, reset); the server decides who may.
const MfaAdminPanel = dynamic(() => import('@/features/access/users/MfaAdminPanel').then(m => m.MfaAdminPanel))

const VIEW = ['admin.identities.users.view', 'admin.identities.admins.view']

export function UserDetailPage() {
  const params = useParams<{ name: string }>()
  const name = decodeURIComponent(params.name)
  const actor = useSession(state => state.user)
  const canView = useCan({ anyOf: VIEW }) || actor?.name === name
  const query = useWs('auth.user.get.byName', { name }, { enabled: canView })

  return (
    <>
      <BackLink href="/users">Users</BackLink>
      {!canView ? (
        <>
          <PageHeader title={name} />
          <DeniedState what="view users" />
        </>
      ) : (
        <QueryState query={query}>{data => <UserDetail user={data.user} />}</QueryState>
      )}
    </>
  )
}

const UserDetail = ({ user }: { user: UserRecord }) => {
  const router = useRouter()
  const actor = useSession(state => state.user)
  const { roles } = useAdminRoles()
  // The users list may carry a slim role; the catalog has the permissions the client-side rules need.
  const fullRole = useMemo(() => roles.find(r => r.id === user.admin_role?.id) ?? user.admin_role ?? null, [roles, user.admin_role])
  const rules = useMemo(() => accountRules(actor, user, fullRole), [actor, user, fullRole])
  const users = useWs('auth.users.list', null, { enabled: user.created_by !== undefined, staleTime: 60_000 })
  const createdBy = user.created_by !== undefined ? users.data?.users.find(u => u.id === user.created_by)?.name : undefined

  const [resetOpen, setResetOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)
  const onDeleted = useCallback(() => router.replace('/users'), [router])
  const onRenamed = useCallback((next: string) => router.replace(userHref(next)), [router])

  // One account-wide explanation when nothing (or almost nothing) here can be changed.
  const notice = user.is_protected
    ? {
        title: user.system_only ? 'System account' : 'Protected account',
        body: user.system_only
          ? 'The daemon uses this identity internally. It can’t sign in to the console and is changed only from the server.'
          : 'This account is bound to the server’s CLI operator. Change it from the server with the vh CLI.',
      }
    : !rules.self && !rules.profile.allowed
      ? { title: 'Read only', body: rules.profile.reason }
      : null

  return (
    <>
      <PageHeader
        title={
          <span className="flex min-w-0 items-center gap-3">
            <Avatar name={user.name} />
            <span className="truncate">{user.name}</span>
          </span>
        }
        description={
          <span className="mt-1 flex flex-wrap items-center gap-2">
            <StatusBadge active={user.is_active} />
            <span className="text-fg-muted">{roleLabel(user.admin_role?.name)}</span>
            <AccountBadges user={user} selfId={actor?.id} />
          </span>
        }
      />

      {notice ? <Notice title={notice.title} className="mb-5">{notice.body}</Notice> : null}
      {rules.self ? (
        <Notice className="mb-5" title="This is your account">
          You can edit your name and email here. Your role and status can only be changed by another administrator; change your
          password from <Link href="/account" className="text-accent-text hover:underline">your account page</Link>.
        </Notice>
      ) : null}

      <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_20rem]">
        <div className="min-w-0 space-y-5">
          <ProfilePanel user={user} rules={rules} onRenamed={onRenamed} quiet={Boolean(notice)} />
          <AccessPanel user={user} rules={rules} quiet={Boolean(notice)} />
          <GroupsPanel user={user} self={rules.self} />
          <VaultAccessPanel user={user} />
        </div>
        <div className="min-w-0 space-y-5">
          <Panel title="Details">
            <DefinitionList
              items={[
                ['User ID', <span key="id" className="tabular">{user.id}</span>],
                ['Created', <span key="c" className="tabular">{formatDateTime(user.created_at)}</span>],
                ...(createdBy ? ([['Created by', createdBy]] as [React.ReactNode, React.ReactNode][]) : []),
                ['Last login', user.last_login ? <span key="l" className="tabular">{formatDateTime(user.last_login)}</span> : 'Never'],
                // core doesn't persist password_changed_at yet (always null); show it only when it's known.
                ...(user.password_changed_at
                  ? ([['Password set', <span key="p" className="tabular">{formatDateTime(user.password_changed_at)}</span>]] as [React.ReactNode, React.ReactNode][])
                  : []),
                ...(!user.is_active && user.deactivated_at
                  ? ([['Deactivated', <span key="d" className="tabular">{formatDateTime(user.deactivated_at)}</span>]] as [React.ReactNode, React.ReactNode][])
                  : []),
                ['CLI login', user.linux_uid !== undefined ? <span key="u" className="tabular">Linux UID {user.linux_uid}</span> : 'Not bound'],
              ]}
            />
          </Panel>

          {!rules.self ? (
            <Panel title="Password" description="Set a new password for this account. Their open sessions end.">
              <WithReason reason={rules.password.allowed ? undefined : rules.password.reason}>
                <Button onClick={() => setResetOpen(true)} disabled={!rules.password.allowed}>
                  <KeyIcon aria-hidden />
                  Reset password…
                </Button>
              </WithReason>
              {!rules.password.allowed && !notice ? <Reason reason={rules.password.reason} className="mt-3" /> : null}
            </Panel>
          ) : null}

          {!rules.self && !user.is_protected && !user.system_only ? <MfaAdminPanel user={user} /> : null}

{!rules.self ? (
          <Panel title="Delete account" className="border-danger-line" description="Removes the account, its sessions and its memberships. Its vaults are destroyed unless you transfer them.">
            <WithReason reason={rules.remove.allowed ? undefined : rules.remove.reason}>
              <Button variant="danger" onClick={() => setDeleteOpen(true)} disabled={!rules.remove.allowed}>
                <TrashIcon aria-hidden />
                Delete user…
              </Button>
            </WithReason>
            {!rules.remove.allowed && !notice ? <Reason reason={rules.remove.reason} className="mt-3" /> : null}
          </Panel>
          ) : null}
        </div>
      </div>

      {resetOpen ? <ResetPasswordDialog user={user} open onOpenChange={setResetOpen} /> : null}
      {deleteOpen ? <DeleteUserDialog user={user} open onOpenChange={setDeleteOpen} onDeleted={onDeleted} /> : null}
    </>
  )
}
