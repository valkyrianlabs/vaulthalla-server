'use client'

import React, { useState } from 'react'
import dynamic from 'next/dynamic'
import Link from 'next/link'
import { useParams, useRouter } from 'next/navigation'
import { useWs, useWsMutation } from '@/lib/query'
import { formatDateTime, formatInt, formatRelative } from '@/lib/format'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { confirm } from '@/components/ui/Confirm'
import { DefinitionList, PageHeader, Panel } from '@/components/ui/Panel'
import { Meter } from '@/components/ui/Stat'
import { EmptyState, ErrorState, QueryState } from '@/components/ui/State'
import { notify } from '@/components/ui/Toast'
import {
  ArrowRightArrowLeftIcon,
  ArrowsRotateIcon,
  BanIcon,
  ChevronLeftIcon,
  CircleInfoIcon,
  ClockIcon,
  CopyIcon,
  FolderOpenIcon,
  ShieldHalvedIcon,
  TrashIcon,
  VaultIcon,
} from '@/components/ui/icons'
import { PeersGate, PeersUnavailable } from '@/features/peers/Gate'
import { healthText } from '@/features/peers/model'
import { PeerError } from '@/features/peers/parts'
import { MIRROR_COPY as C } from '@/features/mirrors/copy'
import {
  MIRROR_READS,
  actionsFor,
  adviceFor,
  cancelKind,
  cancelTarget,
  firstCopyProgress,
  isPeersOff,
  peerName,
  positionText,
  roleSentence,
  statusText,
  unconfirmed,
  type MirrorAction,
  type MirroredVault,
} from '@/features/mirrors/model'
import { MirrorStatus, RoleBadge, date } from '@/features/mirrors/parts'
import { DETAIL_POLL_MS, LIST_POLL_MS, linkUpOf, useHeld, usePeers } from '@/features/mirrors/queries'
import { HeldChanges } from '@/features/mirrors/HeldChanges'

// The action dialogs load only when someone opens one.
const EndMirrorDialog = dynamic(() => import('@/features/mirrors/EndMirrorDialog'), { ssr: false })
const SwitchDialog = dynamic(() => import('@/features/mirrors/SwitchDialog'), { ssr: false })
const DetachDialog = dynamic(() => import('@/features/mirrors/DetachDialog'), { ssr: false })
const VersionsDialog = dynamic(() => import('@/features/mirrors/VersionsDialog'), { ssr: false })
const TakeoverDialog = dynamic(() => import('@/features/mirrors/TakeoverDialog'), { ssr: false })
const DetachCopyDialog = dynamic(() => import('@/features/mirrors/DetachCopyDialog'), { ssr: false })

const useVaultParam = () => {
  const params = useParams<{ vaultId: string }>()
  const id = Number(params?.vaultId)
  return Number.isInteger(id) && id > 0 ? id : null
}

// /linked-servers/mirrors/[vaultId]: one vault's mirror (mirror.get), with what to do next and the actions that apply
// to this server's role and the vault's state; on the mirror side also what detaching would give (pending, held and
// missing files: mirror.detach.preview, which changes nothing) and the held changes.
export const MirrorDetailPage = () => {
  const id = useVaultParam()
  return <PeersGate denied={C.denied}>{id ? <MirrorDetail vaultId={id} /> : <ErrorState error={new Error(C.badVault)} />}</PeersGate>
}

const running = (row: MirroredVault | undefined) => row && (row.role === 'starting' || row.state === 'starting' || row.state === 'switching')

const BackLink = () => (
  <Link href="/linked-servers/mirrors" className="mb-3 inline-flex items-center gap-1.5 text-xs text-fg-subtle transition-colors hover:text-fg">
    <ChevronLeftIcon className="size-3" aria-hidden />
    {C.back}
  </Link>
)

const MirrorDetail = ({ vaultId }: { vaultId: number }) => {
  const get = useWs('mirror.get', { vault_id: vaultId }, {
    select: d => d.vault,
    refetchInterval: q => (running(q.state.data?.vault) ? DETAIL_POLL_MS : LIST_POLL_MS),
  })
  if (isPeersOff(get.error)) return <PeersUnavailable />
  return (
    <div className="min-w-0">
      <BackLink />
      <QueryState query={get}>{row => (row.role === 'none' ? <NotMirrored /> : <Loaded row={row} />)}</QueryState>
    </div>
  )
}

const NotMirrored = () => <EmptyState icon={VaultIcon} title={C.notMirroredTitle} description={C.notMirroredBody} />

type Open = Exclude<MirrorAction, 'held' | 'resync'> | null

const ACTION_ICON: Record<MirrorAction, React.ComponentType<React.SVGProps<SVGSVGElement>>> = {
  switch: ArrowRightArrowLeftIcon,
  takeover: ShieldHalvedIcon,
  resync: ArrowsRotateIcon,
  detach: FolderOpenIcon,
  copy: CopyIcon,
  versions: ClockIcon,
  cancel: BanIcon,
  held: CircleInfoIcon,
}

const Loaded = ({ row }: { row: MirroredVault }) => {
  const router = useRouter()
  const { byId } = usePeers()
  const linkUp = linkUpOf(byId, row.peer?.id)
  const held = useHeld(row.vault_id)
  const openHeld = (held.data?.held ?? []).filter(h => h.state === 'open').length
  const holdsCopy = row.role === 'mirror' || row.role === 'orphaned'
  const preview = useWs('mirror.detach.preview', { vault_id: row.vault_id }, {
    enabled: holdsCopy,
    retry: false,
    select: d => d.preview,
    refetchInterval: q => (q.state.data?.preview.first_copy.finished === false ? DETAIL_POLL_MS : LIST_POLL_MS),
  })
  const p = preview.data
  const [open, setOpen] = useState<Open>(null)
  const [error, setError] = useState<{ error: unknown; fallback: string } | null>(null)
  const peer = peerName(row)
  const actions = actionsFor(row, { firstCopyFinished: p?.first_copy.finished ?? null })
  const status = statusText(row, { linkUp, firstCopy: p?.first_copy ?? null, date })
  const advice = adviceFor(row, { linkUp, held: openHeld })
  const progress = p ? firstCopyProgress(p.first_copy) : null
  const onOpenChange = (next: boolean) => !next && setOpen(null)

  const cancel = useWsMutation<'mirror.cancel', void>('mirror.cancel', {
    toPayload: () => cancelTarget(row),
    invalidates: [...MIRROR_READS, 'storage.vault.list'],
  })
  const resync = useWsMutation<'mirror.resync', void>('mirror.resync', {
    toPayload: () => ({ vault_id: row.vault_id }),
    invalidates: [...MIRROR_READS],
    onSuccess: data => notify.success(C.resynced(row.vault_name), C.resyncedHint(data.held)),
  })

  const run = async (action: MirrorAction) => {
    setError(null)
    if (action === 'resync') {
      const ok = await confirm({ title: C.resyncTitle(row.vault_name), description: C.resyncBody(peer), confirmLabel: C.resyncConfirm, tone: 'primary' })
      if (ok) resync.mutate(undefined, { onError: e => setError({ error: e, fallback: C.resyncFailed }) })
      return
    }
    if (action === 'cancel' && cancelKind(row) !== 'end') {
      const orphan = cancelKind(row) === 'remove_orphan'
      const name = row.vault_name || row.start?.name || ''
      const ok = await confirm({
        title: orphan ? C.removeOrphanTitle(name) : C.cancelStartTitle(name),
        description: orphan ? C.removeOrphanBody : C.cancelStartBody(peer),
        confirmLabel: orphan ? C.removeOrphanConfirm : C.cancelStartConfirm,
        cancelLabel: C.keepGoing,
        tone: 'danger',
        ...(orphan ? { typeToConfirm: row.vault_name } : {}),
      })
      if (!ok) return
      cancel.mutate(undefined, {
        onSuccess: () => {
          notify.success(orphan ? C.orphanRemoved(name) : C.startCancelled)
          router.push('/linked-servers/mirrors')
        },
        onError: e => setError({ error: e, fallback: C.cancelFailed }),
      })
      return
    }
    if (action !== 'held') setOpen(action)
  }

  const actionLabel = (a: MirrorAction): { label: string; hint: string; danger?: boolean } => {
    switch (a) {
      case 'switch':
        return { label: 'Switch the core…', hint: row.role === 'core' ? `Make ${peer} the core; this server keeps a copy.` : `Make this server the core; ${peer} keeps a copy.` }
      case 'takeover':
        return { label: C.takeoverAction, hint: C.takeoverHint(peer), danger: true }
      case 'copy':
        return { label: C.copyAction, hint: C.copyHint }
      case 'resync':
        return { label: 'Resync…', hint: linkUp === false ? C.resyncNeedsLink : 'Start the copy over from the core’s files.' }
      case 'detach':
        return { label: 'Detach…', hint: 'Keep this copy as a standalone vault on this server.' }
      case 'versions':
        return { label: C.manageVersions, hint: 'Keep previous versions of what the core replaces or deletes.' }
      case 'cancel':
        return cancelKind(row) === 'end' ? { label: 'End the mirror…', hint: `Stop mirroring to ${peer}.`, danger: true }
          : cancelKind(row) === 'remove_orphan' ? { label: 'Remove the copy…', hint: 'Remove this copy and its keys from this server.', danger: true }
          : { label: 'Cancel the start…', hint: 'Stop before anything more is copied.', danger: true }
      default:
        return { label: '', hint: '' }
    }
  }
  const shown = actions.filter(a => a !== 'held')
  const busy = cancel.isPending || resync.isPending

  const facts: [React.ReactNode, React.ReactNode][] = [
    [
      C.detailServer,
      row.peer ?
        <span className="flex flex-wrap items-center gap-2">
          <span className="text-fg">{peer}</span>
          {byId.get(row.peer.id) ?
            <Badge tone={healthText(byId.get(row.peer.id)!, formatRelative).tone} dot className="h-5 px-2 text-[11px]">
              {row.peer.revoked ? C.linkGone : linkUp ? C.linkUp : linkUp === false ? C.linkDown : C.linkUnknown}
            </Badge>
          : null}
        </span>
      : C.noServer,
    ],
  ]
  if (row.role === 'core' || row.role === 'mirror') {
    const behind = unconfirmed(row)
    facts.push([C.detailPosition, <span key="pos" className="tabular">{positionText(row)}{behind ? ` · ${C.unconfirmed(behind)}` : ''}</span>])
  }
  if (p) {
    facts.push([C.detailDigest, p.digest_matched === null ? C.digestNotYet : p.digest_matched ? C.digestMatched : C.digestDiffered])
    facts.push([C.detailPending, <span key="pending" className="tabular" data-testid="mirror-pending">{formatInt(p.pending_changes)}</span>])
    facts.push([C.detailMissing, <span key="missing" className="tabular">{formatInt(p.missing_count)}</span>])
  }
  if (holdsCopy || row.role === 'detached') facts.push([C.detailHeld, <span key="held" className="tabular" data-testid="mirror-held-total">{formatInt(openHeld)}</span>])
  if (row.role === 'mirror')
    facts.push([C.detailGrant, row.grant ? `${C.grantBy(row.grant.role_name)} · ${formatDateTime(row.grant.granted_at)}` : C.grantNone])
  if (row.created_at) facts.push([C.detailSince, formatDateTime(row.created_at)])

  return (
    <>
      <PageHeader
        title={
          <span className="inline-flex min-w-0 items-center gap-2.5">
            <span className="truncate" data-testid="mirror-detail-name">
              {row.vault_name || row.start?.name}
            </span>
            <RoleBadge role={row.role} />
          </span>
        }
        description={roleSentence(row)}
        actions={
          row.role !== 'starting' && row.vault_id > 0 ?
            <Button variant="secondary" asChild>
              <Link href={`/vaults/${row.vault_id}`}>
                <VaultIcon aria-hidden />
                {C.openVault}
              </Link>
            </Button>
          : null
        }
      />

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_20rem]">
        <div className="min-w-0 space-y-6">
          <Panel>
            <MirrorStatus row={row} facts={{ linkUp, firstCopy: p?.first_copy ?? null }} className="gap-2 [&_[data-testid=mirror-status-sentence]]:text-sm" />
            {progress ?
              <div className="mt-3 space-y-1.5" data-testid="mirror-first-copy">
                <Meter ratio={progress.ratio} label={C.detailFirstCopy} />
                <p className="text-xs text-fg-subtle tabular">{progress.text}</p>
              </div>
            : null}
            {advice ?
              <p className="mt-4 flex items-start gap-2 rounded-control border border-line bg-surface-1 px-3 py-2.5 text-sm text-fg" data-testid="mirror-advice">
                <CircleInfoIcon className="mt-0.5 size-4 shrink-0 text-accent-text" aria-hidden />
                <span>
                  <span className="sr-only">{C.adviceLabel}: </span>
                  {advice}
                </span>
              </p>
            : null}
            {status.tone === 'danger' && row.start?.last_error ?
              <p className="mt-3 font-mono text-xs break-words text-fg-subtle">{row.start.last_error}</p>
            : null}
          </Panel>

          <Panel title={C.detailFacts}>
            <DefinitionList items={facts} />
            {preview.error && !isPeersOff(preview.error) ? <PeerError error={preview.error} fallback={C.loadFailed} className="mt-3" /> : null}
          </Panel>
        </div>

        <Panel title={C.detailActions} className="self-start">
          <PeerError error={error?.error} fallback={error?.fallback ?? ''} className="mb-3" />
          {shown.length ?
            <ul className="space-y-3" data-testid="mirror-actions">
              {shown.map(a => {
                const { label, hint, danger } = actionLabel(a)
                const Icon = a === 'cancel' && cancelKind(row) === 'remove_orphan' ? TrashIcon : ACTION_ICON[a]
                return (
                  <li key={a}>
                    <Button
                      variant={danger ? 'danger' : 'secondary'}
                      className="w-full justify-start"
                      disabled={busy || (a === 'resync' && linkUp === false)}
                      loading={(a === 'resync' && resync.isPending) || (a === 'cancel' && cancel.isPending)}
                      onClick={() => void run(a)}
                      data-testid={`mirror-action-${a}`}>
                      <Icon aria-hidden />
                      {label}
                    </Button>
                    <p className="mt-1 text-xs text-fg-subtle">{hint}</p>
                  </li>
                )
              })}
            </ul>
          : <p className="text-sm text-fg-subtle">{C.noActions}</p>}
        </Panel>
      </div>

      {actions.includes('held') ? <HeldChanges vaultId={row.vault_id} live={row.state === 'live' && linkUp !== false} /> : null}

      {open === 'cancel' ? <EndMirrorDialog row={row} open onOpenChange={onOpenChange} /> : null}
      {open === 'switch' ? <SwitchDialog row={row} open onOpenChange={onOpenChange} /> : null}
      {open === 'detach' ? <DetachDialog row={row} open onOpenChange={onOpenChange} /> : null}
      {open === 'versions' ? <VersionsDialog row={row} open onOpenChange={onOpenChange} /> : null}
      {open === 'takeover' ? <TakeoverDialog row={row} open onOpenChange={onOpenChange} /> : null}
      {open === 'copy' ? <DetachCopyDialog row={row} open onOpenChange={onOpenChange} /> : null}
    </>
  )
}
