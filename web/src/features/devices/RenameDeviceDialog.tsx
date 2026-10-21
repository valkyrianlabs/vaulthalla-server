'use client'

import React, { useState } from 'react'
import { useWsMutation } from '@/lib/query'
import { Button } from '@/components/ui/Button'
import { Dialog, DialogClose, DialogContent } from '@/components/ui/Dialog'
import { Field, Input } from '@/components/ui/Field'
import { InlineError } from '@/components/ui/State'
import { notify } from '@/components/ui/Toast'
import type { Device } from '@/models/device'
import { DEVICE_READS, deviceLabel } from '@/features/devices/model'

// core device::normalizeDeviceName: 1-64 characters, no control characters.
const MAX_NAME = 64

// Loaded with next/dynamic and mounted only while open.
export default function RenameDeviceDialog({
  device,
  open,
  onOpenChange,
}: {
  device: Device
  open: boolean
  onOpenChange: (open: boolean) => void
}) {
  const [name, setName] = useState(device.name)
  const trimmed = name.trim()
  const rename = useWsMutation('device.rename', {
    toPayload: (next: string) => ({ device_id: device.device_id, name: next }),
    invalidates: [...DEVICE_READS],
    onSuccess: data => {
      notify.success(`Renamed to ${deviceLabel(data.device)}`)
      onOpenChange(false)
    },
  })
  const tooLong = [...trimmed].length > MAX_NAME
  const unchanged = trimmed === device.name

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        size="sm"
        title={`Rename ${deviceLabel(device)}`}
        description="The name shows in this list, in vh device list and in audit lines."
        data-testid="device-rename-dialog"
        footer={
          <>
            <DialogClose asChild>
              <Button variant="ghost">Cancel</Button>
            </DialogClose>
            <Button
              type="submit"
              form="device-rename-form"
              variant="primary"
              loading={rename.isPending}
              disabled={!trimmed || tooLong || unchanged}>
              Rename
            </Button>
          </>
        }>
        <form
          id="device-rename-form"
          noValidate
          onSubmit={event => {
            event.preventDefault()
            if (trimmed && !tooLong && !unchanged) rename.mutate(trimmed)
          }}
          className="space-y-3">
          <Field label="Name" htmlFor="device-rename-name" error={tooLong ? `At most ${MAX_NAME} characters` : undefined}>
            <Input
              id="device-rename-name"
              value={name}
              autoFocus
              maxLength={MAX_NAME * 2}
              onChange={event => setName(event.target.value)}
              aria-invalid={tooLong || undefined}
            />
          </Field>
          <InlineError error={rename.error} />
        </form>
      </DialogContent>
    </Dialog>
  )
}
