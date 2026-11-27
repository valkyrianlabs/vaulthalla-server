'use client'

import React, { useId, useState } from 'react'
import { useWsMutation } from '@/lib/query'
import type { Response } from '@/lib/ws/client'
import { formatBytes } from '@/lib/format'
import { Button } from '@/components/ui/Button'
import { SwitchRow } from '@/components/ui/Choice'
import { Dialog, DialogClose, DialogContent } from '@/components/ui/Dialog'
import { Field, Input } from '@/components/ui/Field'
import { notify } from '@/components/ui/Toast'
import { PeerError } from '@/features/peers/parts'
import { MIRROR_COPY as C } from '@/features/mirrors/copy'
import { parseLimit, type MirroredVault } from '@/features/mirrors/model'

type Versions = Response<'mirror.versions.set'>['versions']

const limitText = (v: number | null, unit: (n: number) => string) => (v === null || v === 0 ? C.noLimit : unit(v))

// Versions kept on the mirror of what its core replaces or deletes (mirror.versions.set). There is no read of the
// current setting, so the form starts off and blank (the server's defaults) and shows what the answer says was set.
// Loaded with next/dynamic and mounted only while open.
export default function VersionsDialog({
  row,
  open,
  onOpenChange,
}: {
  row: MirroredVault
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const ids = useId()
  const [enabled, setEnabled] = useState(false)
  const [keepLast, setKeepLast] = useState('')
  const [maxAge, setMaxAge] = useState('')
  const [quota, setQuota] = useState('')
  const [saved, setSaved] = useState<Versions | null>(null)
  const parsed = { keepLast: parseLimit(keepLast), maxAge: parseLimit(maxAge), quota: parseLimit(quota) }
  const valid = !enabled || Object.values(parsed).every(p => p.ok)

  const save = useWsMutation<'mirror.versions.set', void>('mirror.versions.set', {
    toPayload: () => {
      const value = (p: ReturnType<typeof parseLimit>) => (p.ok ? p.value : null)
      return enabled ?
          { vault_id: row.vault_id, enabled, keep_last: value(parsed.keepLast), max_age_days: value(parsed.maxAge), quota_bytes: value(parsed.quota) }
        : { vault_id: row.vault_id, enabled }
    },
    onSuccess: data => {
      setSaved(data.versions)
      notify.success(C.versionsSaved(data.versions.enabled))
    },
  })
  const err = (p: ReturnType<typeof parseLimit>) => (enabled && !p.ok ? p.error : undefined)

  return (
    <Dialog open={open} onOpenChange={next => (save.isPending ? undefined : onOpenChange(next))}>
      <DialogContent
        title={C.versionsTitle}
        description={C.versionsBody}
        size="md"
        data-testid="mirror-versions-dialog"
        footer={
          <>
            <DialogClose asChild>
              <Button variant="ghost">Close</Button>
            </DialogClose>
            <Button type="submit" form={`${ids}-form`} variant="primary" loading={save.isPending} disabled={!valid} data-testid="mirror-versions-save">
              {C.versionsSave}
            </Button>
          </>
        }>
        <form
          id={`${ids}-form`}
          noValidate
          className="space-y-4"
          onSubmit={event => {
            event.preventDefault()
            if (valid) save.mutate()
          }}>
          <p className="text-xs text-fg-subtle">{C.versionsUnknown}</p>
          <SwitchRow id={`${ids}-on`} label={C.versionsKeep} checked={enabled} onCheckedChange={setEnabled} />
          {enabled ?
            <div className="grid gap-3 sm:grid-cols-3">
              <Field label={C.versionsKeepLast} htmlFor={`${ids}-keep`} error={err(parsed.keepLast)}>
                <Input id={`${ids}-keep`} inputMode="numeric" value={keepLast} placeholder="10" onChange={e => setKeepLast(e.target.value)} />
              </Field>
              <Field label={C.versionsMaxAge} htmlFor={`${ids}-age`} error={err(parsed.maxAge)}>
                <Input id={`${ids}-age`} inputMode="numeric" value={maxAge} placeholder="30" onChange={e => setMaxAge(e.target.value)} />
              </Field>
              <Field label={C.versionsQuota} htmlFor={`${ids}-quota`} error={err(parsed.quota)}>
                <Input id={`${ids}-quota`} inputMode="numeric" value={quota} placeholder="0" onChange={e => setQuota(e.target.value)} />
              </Field>
              <p className="text-xs text-fg-subtle sm:col-span-3">{C.versionsLimitHint}</p>
            </div>
          : null}
          {saved ?
            <p className="text-sm text-fg-muted" role="status" data-testid="mirror-versions-now">
              {C.versionsNow(
                saved.enabled,
                limitText(saved.keep_last, n => `${n} versions`),
                limitText(saved.max_age_days, n => `${n} days`),
                limitText(saved.quota_bytes, n => formatBytes(n)),
              )}
            </p>
          : null}
          <PeerError error={save.error} fallback={C.versionsFailed} />
        </form>
      </DialogContent>
    </Dialog>
  )
}
