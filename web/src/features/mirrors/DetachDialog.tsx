'use client'

import React, { useId, useState } from 'react'
import { useWs, useWsMutation } from '@/lib/query'
import { formatBytes } from '@/lib/format'
import { useSession } from '@/lib/session'
import { Button } from '@/components/ui/Button'
import { Dialog, DialogClose, DialogContent } from '@/components/ui/Dialog'
import { Field, Input, Select } from '@/components/ui/Field'
import { InlineError, Skeleton } from '@/components/ui/State'
import { notify } from '@/components/ui/Toast'
import { TriangleExclamationIcon } from '@/components/ui/icons'
import { useUserNames } from '@/features/vaults/hooks'
import { CopyButton, PeerError } from '@/features/peers/parts'
import { MIRROR_COPY as C } from '@/features/mirrors/copy'
import { MIRROR_READS, firstCopyProgress, peerName, type MirroredVault } from '@/features/mirrors/model'

// How many missing files the dialog lists; the copy button carries all of them.
const SHOWN_MISSING = 50

// Leave a mirror with its files (mirror.detach.preview, then mirror.detach {vault_id, owner, confirm_name}): what
// detaching gives first (the changes kept, the files whose contents never arrived), the owner here, then the vault's
// name typed. No step-up (the typed name is the confirmation). Loaded with next/dynamic, mounted while open.
export default function DetachDialog({
  row,
  open,
  onOpenChange,
}: {
  row: MirroredVault
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const ids = useId()
  const me = useSession(state => state.user)
  const { users, canList } = useUserNames()
  const preview = useWs('mirror.detach.preview', { vault_id: row.vault_id }, { enabled: open, staleTime: 0, select: d => d.preview })
  const [owner, setOwner] = useState('')
  const [typed, setTyped] = useState('')

  const detach = useWsMutation<'mirror.detach', void>('mirror.detach', {
    toPayload: () => ({ vault_id: row.vault_id, owner: owner || null, confirm_name: typed }),
    invalidates: [...MIRROR_READS, 'storage.vault.list', 'storage.vault.get'],
    onSuccess: () => {
      notify.success(C.detached(row.vault_name), C.detachedHint)
      onOpenChange(false)
    },
  })

  const p = preview.data
  const progress = p ? firstCopyProgress(p.first_copy) : null
  const missingList = p ? p.missing.map(m => m.path).join('\n') : ''
  const ready = Boolean(p) && typed === row.vault_name

  return (
    <Dialog open={open} onOpenChange={next => (detach.isPending ? undefined : onOpenChange(next))}>
      <DialogContent
        title={C.detachTitle(row.vault_name)}
        description={C.detachBody(peerName(row))}
        size="lg"
        data-testid="mirror-detach-dialog"
        footer={
          <>
            <DialogClose asChild>
              <Button variant="ghost">{C.keepGoing}</Button>
            </DialogClose>
            <Button variant="danger-solid" loading={detach.isPending} disabled={!ready} onClick={() => detach.mutate()} data-testid="mirror-detach-confirm">
              {C.detachConfirm}
            </Button>
          </>
        }>
        {!p ?
          preview.error ?
            <PeerError error={preview.error} fallback={C.detachFailed} />
          : <div className="space-y-2" aria-busy="true" aria-label={C.detachLoading}>
              <Skeleton />
              <Skeleton className="w-2/3" />
              <Skeleton className="w-1/2" />
            </div>

        : <div className="space-y-4" data-testid="mirror-detach-preview">
            <ul className="list-disc space-y-1 pl-5 text-sm text-fg-muted">
              {progress ? <li>{C.detachUnfinished(progress.text)}</li> : null}
              {p.pending_changes ? <li data-testid="mirror-detach-pending">{C.detachPending(p.pending_changes)}</li> : null}
              {p.held_changes ? <li>{C.detachHeld(p.held_changes)}</li> : null}
              <li>{C.detachRekey}</li>
            </ul>

            {p.missing_count ?
              <div className="rounded-control border border-warn-line bg-warn-soft p-3" data-testid="mirror-detach-missing">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="flex items-center gap-2 text-sm font-semibold text-warn">
                    <TriangleExclamationIcon className="size-4 shrink-0" aria-hidden />
                    {C.detachMissingTitle(p.missing_count)}
                  </p>
                  {p.missing.length ?
                    <CopyButton text={missingList} label={C.detachCopyList} />
                  : null}
                </div>
                <p className="mt-1 text-sm text-fg-muted">{C.detachMissingBody}</p>
                {p.missing.length ?
                  <ul className="mt-2 max-h-40 overflow-y-auto rounded-control border border-line bg-surface-1 px-3 py-2 font-mono text-xs text-fg-muted">
                    {p.missing.slice(0, SHOWN_MISSING).map(m => (
                      <li key={m.file_id} className="flex justify-between gap-3">
                        <span className="min-w-0 truncate" title={m.path}>
                          {m.path}
                        </span>
                        <span className="shrink-0 tabular">{formatBytes(m.size_bytes)}</span>
                      </li>
                    ))}
                    {p.missing.length > SHOWN_MISSING ?
                      <li className="pt-1 font-sans text-fg-subtle">{C.detachMissingMore(p.missing_count - SHOWN_MISSING)}</li>
                    : null}
                  </ul>
                : null}
              </div>
            : <p className="text-sm text-fg-muted">{C.detachAllHere}</p>}

            <Field label={C.detachOwner} htmlFor={`${ids}-owner`} hint={C.detachOwnerHint}>
              {canList ?
                <Select id={`${ids}-owner`} value={owner} onChange={e => setOwner(e.target.value)} data-testid="mirror-detach-owner">
                  <option value="">{C.detachOwnerMe(me?.name ?? '')}</option>
                  {users
                    .filter(u => u.name !== me?.name)
                    .map(u => (
                      <option key={u.id} value={u.name}>
                        {u.name}
                      </option>
                    ))}
                </Select>
              : <Input id={`${ids}-owner`} value={owner} placeholder={C.detachOwnerMe(me?.name ?? '')} onChange={e => setOwner(e.target.value)} />}
            </Field>
            <Field label={C.detachType(row.vault_name)} htmlFor={`${ids}-typed`}>
              <Input id={`${ids}-typed`} value={typed} autoComplete="off" onChange={e => setTyped(e.target.value)} data-testid="mirror-detach-typed" />
            </Field>
            <PeerError error={detach.error} fallback={C.detachFailed} />
          </div>
        }
        {preview.error && p ? <InlineError error={preview.error} className="mt-3" /> : null}
      </DialogContent>
    </Dialog>
  )
}
