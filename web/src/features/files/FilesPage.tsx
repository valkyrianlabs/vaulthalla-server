'use client'

import React, { useEffect, useMemo, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { useWs } from '@/lib/query'
import { Button } from '@/components/ui/Button'
import { DropdownMenu } from '@/components/ui/Menu'
import { EmptyState, ErrorState } from '@/components/ui/State'
import { PageSpinner } from '@/components/ui/Spinner'
import { ChevronDownIcon, CloudIcon, HardDriveIcon, VaultIcon, CheckIcon } from '@/components/ui/icons'
import { FileBrowser } from '@/features/files/FileBrowser'
import { authSource } from '@/features/files/source'
import { normalizePath, type Entry } from '@/features/files/entries'
import dynamic from 'next/dynamic'

const ShareDialog = dynamic(() => import('@/features/shares/ShareDialog').then(m => m.ShareDialog), { ssr: false })
const RecoveryHistorySheet = dynamic(() => import('@/features/recovery/RecoveryHistorySheet'), { ssr: false })
import { useCan } from '@/lib/permissions'
import { useSharingPolicy } from '@/features/shares/policy'
import Link from 'next/link'

const LAST_VAULT = 'vaulthalla-ui-last-vault'

const encodePath = (path: string) =>
  normalizePath(path)
    .split('/')
    .filter(Boolean)
    .map(encodeURIComponent)
    .join('/')

export const filesHref = (vaultId: number, path = '/') => {
  const encoded = encodePath(path)
  return `/files/${vaultId}${encoded ? `/${encoded}` : ''}`
}

export function FilesPage() {
  const router = useRouter()
  const params = useParams<{ slug?: string[] }>()
  const slug = useMemo(() => params.slug ?? [], [params.slug])
  const vaultParam = slug[0] ? Number(slug[0]) : null
  const path = useMemo(() => normalizePath(slug.slice(1).map(s => decodeURIComponent(s)).join('/')), [slug])
  const vaults = useWs('storage.vault.list', null, { staleTime: 60_000 })
  const canCreateVault = useCan({ anyOf: ['admin.vaults.self.create', 'admin.vaults.user.create', 'admin.vaults.admin.create'] })
  const [shareTarget, setShareTarget] = useState<Entry | null>(null)
  const [historyTarget, setHistoryTarget] = useState<Entry | null>(null)
  // No "Share link…" while the operator allows no kind of link (sharing.*); the daemon would refuse it.
  const canShare = useSharingPolicy().modes.length > 0

  const list = useMemo(() => vaults.data?.vaults ?? [], [vaults.data])
  const vault = list.find(v => v.id === vaultParam) ?? null

  // No vault in the URL (or an unknown one): go to the last used vault, else the first.
  useEffect(() => {
    if (!list.length || vault) return
    let last: number | null = null
    try {
      last = Number(localStorage.getItem(LAST_VAULT)) || null
    } catch {
      last = null
    }
    const fallback = list.find(v => v.id === last) ?? list[0]
    router.replace(filesHref(fallback.id))
  }, [list, vault, router])

  useEffect(() => {
    if (!vault) return
    try {
      localStorage.setItem(LAST_VAULT, String(vault.id))
    } catch {
      // Remembering the vault is a convenience.
    }
  }, [vault])

  const source = useMemo(() => (vault ? authSource({ id: vault.id, name: vault.name }) : null), [vault])

  if (vaults.isPending) return <PageSpinner />
  if (vaults.error) return <ErrorState error={vaults.error} onRetry={() => void vaults.refetch()} />
  if (!list.length)
    return (
      <EmptyState
        icon={VaultIcon}
        title="No vaults yet"
        description={canCreateVault ? 'Create a vault to start storing files.' : 'Ask an administrator to give you access to a vault.'}
        action={
          canCreateVault ? (
            <Button asChild variant="primary">
              <Link href="/vaults/new">Create a vault</Link>
            </Button>
          ) : undefined
        }
      />
    )
  if (!vault || !source) return <PageSpinner />

  const switcher = (
    <DropdownMenu
      label="Switch vault"
      align="start"
      entries={list.map(v => ({
        key: String(v.id),
        label: v.name,
        icon: v.id === vault.id ? CheckIcon : v.type === 's3' ? CloudIcon : HardDriveIcon,
        onSelect: () => router.push(filesHref(v.id)),
      }))}
      trigger={
        <Button variant="secondary" size="sm" className="max-w-[14rem]">
          {vault.type === 's3' ? <CloudIcon aria-hidden /> : <HardDriveIcon aria-hidden />}
          <span className="truncate">{vault.name}</span>
          <ChevronDownIcon aria-hidden className="!size-3 text-fg-subtle" />
        </Button>
      }
    />
  )

  return (
    <>
      <h1 className="sr-only">Files in {vault.name}</h1>
      <FileBrowser
        source={source}
        path={path}
        onNavigate={next => router.push(filesHref(vault.id, next))}
        leading={list.length > 1 ? switcher : null}
        onShare={canShare ? setShareTarget : undefined}
        onRecoveryHistory={setHistoryTarget}
      />
      {shareTarget ? <ShareDialog vaultId={vault.id} target={shareTarget} onClose={() => setShareTarget(null)} /> : null}
      {historyTarget ? (
        <RecoveryHistorySheet
          vaultId={vault.id}
          isS3={vault.type === 's3'}
          target={historyTarget}
          onClose={() => setHistoryTarget(null)}
        />
      ) : null}
    </>
  )
}
