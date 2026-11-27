'use client'

import React, { useEffect, useId, useState } from 'react'
import Link from 'next/link'
import { Dialog, DialogContent } from '@/components/ui/Dialog'
import { Button } from '@/components/ui/Button'
import { Checkbox } from '@/components/ui/Choice'
import { Field, Input } from '@/components/ui/Field'
import { InlineError, Skeleton } from '@/components/ui/State'
import { notify } from '@/components/ui/Toast'
import { TriangleExclamationIcon } from '@/components/ui/icons'
import { api } from '@/lib/session'
import { invalidate, useWs } from '@/lib/query'
import { isWsError } from '@/lib/ws/errors'
import type { VaultDeletion, VaultRemovalPlan } from '@/models/vaultDeletion'
import { cn } from '@/util/cn'
import { CommandCopy } from '@/features/vaults/CommandCopy'
import { usePeersAvailability } from '@/features/peers/signal'
import { MIRROR_COPY } from '@/features/mirrors/copy'
import { ChoiceCards } from '@/features/mirrors/parts'

// Safe deletion (#162), one dialog: what happens and for how long, the upstream choice for S3 vaults, the key
// warning, then Delete (restorable) or Delete now (one more typed confirmation). Keys are exported from a terminal
// only; the plan is re-read when the window regains focus, so exporting the key elsewhere clears the warning.
// A vault this server mirrors to a linked server also asks what happens to the copy there (mirror_copy: remove or
// leave), when mirror.get says it is this server's (core) or the server refuses with mirror_copy_choice_required; a
// copy held here can't be deleted (the server refuses vault_mirrored / vault_orphaned_copy), so the dialog says so.

const MIRROR_CHOICE_REQUIRED = 'mirror_copy_choice_required'

type MirrorCopy = 'remove' | 'leave'

const MirrorCopyChoice = ({ peer, value, onChange }: { peer: string | null; value: MirrorCopy | null; onChange: (v: MirrorCopy) => void }) => {
  const name = useId()
  const C = MIRROR_COPY
  return (
    <div className="mt-4">
      <ChoiceCards
        name={name}
        legend={peer ? C.deleteMirrorLegend(peer) : C.deleteMirrorLegendUnknown}
        value={value}
        onChange={onChange}
        testId="vault-delete-mirror-copy"
        options={[
          { value: 'leave', title: C.deleteMirrorLeave, hint: C.deleteMirrorLeaveHint },
          { value: 'remove', title: C.deleteMirrorRemove, hint: C.deleteMirrorRemoveHint },
        ]}
      />
      <p className="text-fg-subtle mt-2 text-xs">{C.deleteMirrorReadOnly}</p>
    </div>
  )
}

const UpstreamChoice = ({
  plan,
  deleteUpstream,
  onChange,
}: {
  plan: VaultRemovalPlan
  deleteUpstream: boolean
  onChange: (value: boolean) => void
}) => {
  const name = useId()
  const where = `${plan.bucket ?? 'the bucket'}${plan.provider ? ` (${plan.provider})` : ''}`
  const option = (value: boolean, title: string, hint: string) => (
    <label
      className={cn(
        'flex cursor-pointer items-start gap-3 rounded-control border px-3 py-2.5 transition-colors',
        deleteUpstream === value ? 'border-accent-line bg-accent-soft' : 'border-line hover:border-line-strong',
      )}>
      <input
        type="radio"
        name={name}
        className="mt-1"
        checked={deleteUpstream === value}
        onChange={() => onChange(value)}
      />
      <span className="min-w-0">
        <span className="text-fg block text-sm font-medium">{title}</span>
        <span className="text-fg-subtle block text-xs">{hint}</span>
      </span>
    </label>
  )
  return (
    <fieldset className="mt-4 space-y-2" data-testid="vault-delete-upstream">
      <legend className="text-fg mb-2 text-sm font-medium">This vault is backed by S3: what about the data in {where}?</legend>
      {option(false, 'Keep the upstream data', 'The bucket and its objects stay as they are.')}
      {option(
        true,
        'Delete the upstream data too',
        'Every object in the bucket is deleted when the vault is purged. This can’t be undone.',
      )}
    </fieldset>
  )
}

export const DeleteVaultDialog = ({
  vault,
  open,
  onOpenChange,
  onDeleted,
}: {
  vault: { id: number; name: string }
  open: boolean
  onOpenChange: (open: boolean) => void
  onDeleted?: (deletion: VaultDeletion | null) => void
}) => {
  const ids = useId()
  const plan = useWs(
    'storage.vault.remove.plan',
    { id: vault.id },
    { enabled: open, staleTime: 0, refetchOnWindowFocus: true, select: data => data.plan },
  )
  const [deleteUpstream, setDeleteUpstream] = useState(false)
  const [acceptKeyLoss, setAcceptKeyLoss] = useState(false)
  const [step, setStep] = useState<'choose' | 'now'>('choose')
  const [typed, setTyped] = useState('')
  const [busy, setBusy] = useState<null | 'delete' | 'now'>(null)
  const [error, setError] = useState<unknown>(null)
  const [mirrorCopy, setMirrorCopy] = useState<MirrorCopy | null>(null)
  const [choiceRequired, setChoiceRequired] = useState(false)
  // Whether the vault is mirrored (super admins on a server with linked servers on; anyone else learns it from the
  // refusal, which names the choice).
  const peers = usePeersAvailability()
  const mirror = useWs('mirror.get', { vault_id: vault.id }, { enabled: open && peers.enabled, retry: false, staleTime: 0, select: d => d.vault })

  useEffect(() => {
    if (!open) return
    setMirrorCopy(null)
    setChoiceRequired(false)
    setDeleteUpstream(false)
    setAcceptKeyLoss(false)
    setStep('choose')
    setTyped('')
    setError(null)
  }, [open])

  const p = plan.data
  const isS3 = p?.type === 's3'
  const keyAtRisk = Boolean(p && isS3 && p.encrypted_upstream && !deleteUpstream && !p.key_exported)
  const role = mirror.data?.role
  const mirrorPeer = mirror.data?.peer?.name || null
  const needsMirrorChoice = role === 'core' || choiceRequired
  const heldCopy = role === 'mirror' || role === 'orphaned'
  const blocked = !p || (keyAtRisk && !acceptKeyLoss) || (needsMirrorChoice && !mirrorCopy) || heldCopy

  const submit = async (now: boolean) => {
    if (!p) return
    setBusy(now ? 'now' : 'delete')
    setError(null)
    try {
      const res = await api.send('storage.vault.remove', {
        id: vault.id,
        now,
        confirm_now: now,
        ...(isS3 ? { delete_upstream: deleteUpstream } : {}),
        ...(keyAtRisk ? { accept_key_loss: acceptKeyLoss } : {}),
        ...(needsMirrorChoice && mirrorCopy ? { mirror_copy: mirrorCopy } : {}),
      })
      await invalidate('storage.vault.list', 'storage.vault.deleted.list', 'stats.system.storage')
      notify.success(
        now ? `“${vault.name}” deleted` : `“${vault.name}” deleted. You can restore it for ${p.retention_window}.`,
        now ? 'Its data is being purged now.' : 'Vaults → Deleted vaults lists it until it is purged.',
      )
      onDeleted?.(res.deletion)
      onOpenChange(false)
    } catch (e) {
      // The facts changed underneath (a key export, another admin): show the server's reason with fresh facts.
      if (isWsError(e, 'needs_confirmation')) void plan.refetch()
      if (isWsError(e) && e.code === MIRROR_CHOICE_REQUIRED) {
        // The vault is mirrored after all: ask, then the person sends it again.
        setChoiceRequired(true)
        void mirror.refetch()
      }
      setError(e)
      if (now) setStep('choose')
    } finally {
      setBusy(null)
    }
  }

  const footer =
    step === 'choose' ?
      <>
        <Button variant="ghost" onClick={() => onOpenChange(false)}>
          Cancel
        </Button>
        <Button variant="danger" disabled={blocked || busy !== null} onClick={() => setStep('now')} data-testid="vault-delete-now">
          Delete now
        </Button>
        <Button
          variant="danger-solid"
          disabled={blocked || busy !== null}
          loading={busy === 'delete'}
          onClick={() => void submit(false)}
          data-testid="vault-delete-confirm">
          Delete
        </Button>
      </>
    : <>
        <Button variant="ghost" disabled={busy !== null} onClick={() => setStep('choose')}>
          Back
        </Button>
        <Button
          variant="danger-solid"
          disabled={typed !== vault.name || busy !== null}
          loading={busy === 'now'}
          onClick={() => void submit(true)}
          data-testid="vault-delete-now-confirm">
          Delete now
        </Button>
      </>

  return (
    <Dialog open={open} onOpenChange={next => (busy ? undefined : onOpenChange(next))}>
      <DialogContent title={`Delete “${vault.name}”?`} size="md" footer={footer} data-testid="vault-delete-dialog">
        {!p ?
          plan.error ?
            <InlineError error={plan.error} />
          : <div className="space-y-2">
              <Skeleton />
              <Skeleton className="w-2/3" />
            </div>

        : step === 'now' ?
          <div className="space-y-4">
            <p className="text-danger text-sm">
              Delete “{vault.name}” now? Its data is removed within moments{deleteUpstream ? ', including the objects in the bucket,' : ''} and it can’t be
              restored. Its encryption key is still kept for {p.key_retention_window}.
            </p>
            <Field label={`Type “${vault.name}” to confirm`} htmlFor={`${ids}-typed`}>
              <Input id={`${ids}-typed`} value={typed} autoComplete="off" onChange={e => setTyped(e.target.value)} autoFocus />
            </Field>
          </div>
        : <div>
            <p className="text-fg-muted text-sm">
              It disappears now. You can restore it from <span className="text-fg">Vaults → Deleted vaults</span> for{' '}
              <span className="text-fg tabular">{p.retention_window}</span>; then its data is purged. Its encryption key is
              kept for <span className="text-fg tabular">{p.key_retention_window}</span> either way.
            </p>

            {isS3 ? <UpstreamChoice plan={p} deleteUpstream={deleteUpstream} onChange={setDeleteUpstream} /> : null}

            {heldCopy ?
              <div className="border-warn-line bg-warn-soft mt-4 rounded-control border p-3 text-sm" role="alert" data-testid="vault-delete-mirror-held">
                <p className="text-fg-muted">
                  {role === 'orphaned' ? MIRROR_COPY.deleteOrphan : MIRROR_COPY.deleteHeldCopy(mirrorPeer ?? MIRROR_COPY.unnamedServer)}
                </p>
                <Link href={`/linked-servers/mirrors/${vault.id}`} className="text-accent-text mt-1.5 inline-block text-sm hover:underline">
                  {MIRROR_COPY.deleteOpenMirror}
                </Link>
              </div>
            : needsMirrorChoice ?
              <MirrorCopyChoice peer={mirrorPeer} value={mirrorCopy} onChange={setMirrorCopy} />
            : null}

            {keyAtRisk ?
              <div className="border-danger-line bg-danger-soft mt-4 rounded-control border p-3" data-testid="vault-delete-key-loss" role="alert">
                <div className="text-danger flex items-center gap-2 text-sm font-semibold">
                  <TriangleExclamationIcon className="size-4 shrink-0" aria-hidden />
                  You will lose the ability to decrypt the data in {p.bucket ?? 'the bucket'}
                </div>
                <p className="text-fg-muted mt-1.5 text-sm">
                  Its objects are encrypted with this vault’s key, and that key has never been exported. Export it from a terminal on
                  the server before deleting. It stays exportable with the same command for {p.key_retention_window} after the
                  deletion, then it is destroyed.
                </p>
                <CommandCopy command={p.export_command} label="Copy key export command" />
                <label className="text-fg mt-3 flex items-start gap-2.5 text-sm">
                  <Checkbox className="mt-0.5" checked={acceptKeyLoss} onCheckedChange={setAcceptKeyLoss} data-testid="vault-delete-accept-key-loss" />
                  <span>I understand the data in this bucket can never be decrypted without the key.</span>
                </label>
              </div>
            : !p.key_exported ?
              <div className="border-warn-line bg-warn-soft mt-4 rounded-control border p-3" data-testid="vault-delete-key-note">
                <p className="text-fg-muted text-sm">
                  <span className="text-warn font-medium">No export of this vault’s key has been recorded.</span> Encrypted backups of
                  its contents can’t be read without it. Export it from a terminal on the server first:
                </p>
                <CommandCopy command={p.export_command} label="Copy key export command" />
              </div>
            : null}

            <InlineError error={error} className="mt-4" />
          </div>
        }
      </DialogContent>
    </Dialog>
  )
}

export default DeleteVaultDialog
