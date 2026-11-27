'use client'

import React, { useState } from 'react'
import { useWsMutation } from '@/lib/query'
import type { Response } from '@/lib/ws/client'
import { formatRelative } from '@/lib/format'
import { Button } from '@/components/ui/Button'
import { Dialog, DialogClose, DialogContent } from '@/components/ui/Dialog'
import { Segmented } from '@/components/ui/Tabs'
import { notify } from '@/components/ui/Toast'
import { peerLabel, type LinkedPeer } from '@/features/peers/model'
import { PeerError } from '@/features/peers/parts'
import { MIRROR_COPY as C } from '@/features/mirrors/copy'

type Setting = Response<'mirror.accept_all.set'>

// One linked server's mirror settings (mirror.accept_all.set, mirror.keep_removed.set). The server reports a setting
// only in the answer to setting it (no read exists), so each starts unchosen and shows what was set once it is.
// Loaded with next/dynamic and mounted only while open.
export default function LinkSettingsDialog({
  peer,
  open,
  onOpenChange,
}: {
  peer: LinkedPeer
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const name = peerLabel(peer)
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        title={C.settingsDialogTitle(name)}
        description={C.settingsUnknown}
        size="md"
        data-testid="mirror-settings-dialog"
        footer={
          <DialogClose asChild>
            <Button variant="secondary">Done</Button>
          </DialogClose>
        }>
        <div className="space-y-3">
          <SettingRow peer={peer} command="mirror.accept_all.set" label={C.acceptAllLabel(name)} hint={C.acceptAllHint(name)} testId="mirror-accept-all" />
          <SettingRow
            peer={peer}
            command="mirror.keep_removed.set"
            label={C.keepRemovedLabel(name)}
            hint={C.keepRemovedHint(name)}
            testId="mirror-keep-removed"
          />
        </div>
      </DialogContent>
    </Dialog>
  )
}

const SettingRow = ({
  peer,
  command,
  label,
  hint,
  testId,
}: {
  peer: LinkedPeer
  command: 'mirror.accept_all.set' | 'mirror.keep_removed.set'
  label: string
  hint: string
  testId: string
}) => {
  const [set, setSet] = useState<Setting | null>(null)
  const mutation = useWsMutation(command, {
    toPayload: (enabled: boolean) => ({ peer: String(peer.id), enabled }),
    onSuccess: data => {
      setSet(data)
      notify.success(`${label}: ${data.enabled ? C.turnOn : C.turnOff}`)
    },
  })
  const value = mutation.isPending ? (mutation.variables ? 'on' : 'off') : set ? (set.enabled ? 'on' : 'off') : ('' as 'on' | 'off')
  return (
    <div className="rounded-control border border-line bg-surface-1 px-3 py-2.5" data-testid={testId}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium text-fg">{label}</p>
          <p className="mt-0.5 text-xs text-fg-subtle">{hint}</p>
        </div>
        <Segmented
          label={label}
          value={value}
          onChange={next => mutation.mutate(next === 'on')}
          options={[
            { value: 'off', label: C.turnOff },
            { value: 'on', label: C.turnOn },
          ]}
        />
      </div>
      {set ?
        <p className="mt-2 text-xs text-fg-muted" data-testid={`${testId}-now`}>
          {C.settingIs(set.enabled, formatRelative(set.set_at ?? Date.now() / 1000))}
        </p>
      : null}
      <PeerError error={mutation.error} fallback={C.settingFailed} className="mt-2" />
    </div>
  )
}
