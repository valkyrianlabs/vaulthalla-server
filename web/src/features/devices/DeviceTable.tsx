'use client'

import React, { useMemo, useState } from 'react'
import dynamic from 'next/dynamic'
import { useWsMutation } from '@/lib/query'
import { formatDateTime, formatRelative } from '@/lib/format'
import { DataTable, type Column } from '@/components/ui/DataTable'
import { Badge } from '@/components/ui/Badge'
import { Checkbox } from '@/components/ui/Choice'
import { IconButton } from '@/components/ui/IconButton'
import { Label } from '@/components/ui/Field'
import { confirm } from '@/components/ui/Confirm'
import { notify } from '@/components/ui/Toast'
import { BanIcon, CheckIcon, CopyIcon, PenIcon } from '@/components/ui/icons'
import type { Device } from '@/models/device'
import { DEVICE_READS, byStatus, deviceLabel, shortDeviceId } from '@/features/devices/model'

// Mounted only while renaming (Radix Dialog stays out of the route's first load).
const RenameDeviceDialog = dynamic(() => import('@/features/devices/RenameDeviceDialog'), { ssr: false })

const CopyDeviceId = ({ deviceId }: { deviceId: string }) => {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(deviceId)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      notify.info('Copy it manually', 'Clipboard access isn’t available here.')
    }
  }
  return (
    <span className="inline-flex items-center gap-1">
      <code className="font-mono text-xs text-fg-muted" title={deviceId} data-testid="device-id">
        {shortDeviceId(deviceId)}
      </code>
      <IconButton
        label={copied ? 'Copied' : 'Copy device id'}
        icon={copied ? CheckIcon : CopyIcon}
        size="icon-sm"
        className="size-7"
        onClick={copy}
        data-testid="device-copy-id"
      />
    </span>
  )
}

const thisDevice = (device: Device) => (/mac/i.test(device.platform) ? 'This Mac' : 'This device')

// One table for "your devices" and a super admin's "all devices" (`showOwner`): rename, revoke, copyable id.
export const DeviceTable = ({
  devices,
  showOwner = false,
  empty,
  toolbar,
}: {
  devices: Device[]
  showOwner?: boolean
  empty?: React.ReactNode
  toolbar?: React.ReactNode
}) => {
  const [showRevoked, setShowRevoked] = useState(false)
  const [renaming, setRenaming] = useState<Device | null>(null)
  const revokedCount = devices.filter(d => d.revoked).length
  const rows = useMemo(() => [...devices].filter(d => showRevoked || !d.revoked).sort(byStatus), [devices, showRevoked])

  const revoke = useWsMutation('device.revoke', {
    toPayload: (device: Device) => ({ device_id: device.device_id }),
    invalidates: [...DEVICE_READS],
    onSuccess: data => notify.success(`Revoked ${deviceLabel(data.device)}`, 'Its connections were closed.'),
  })

  const askRevoke = async (device: Device) => {
    const ok = await confirm({
      title: `Revoke ${deviceLabel(device)}?`,
      description: (
        <>
          {thisDevice(device)} loses access immediately and must pair again.
          {showOwner ? ` It belongs to ${device.user_name}.` : ''} Its open connections close now and its key is never
          accepted again.
        </>
      ),
      confirmLabel: 'Revoke',
      tone: 'danger',
    })
    if (!ok) return
    revoke.mutate(device, { onError: error => notify.error(error, 'The device was not revoked') })
  }

  const columns: Column<Device>[] = [
    {
      key: 'name',
      header: 'Name',
      sortValue: d => d.name.toLowerCase(),
      cell: d => (
        <span className="flex min-w-0 items-center gap-2">
          <span className="truncate font-medium text-fg" data-testid="device-name">
            {deviceLabel(d)}
          </span>
          {d.revoked ? (
            <Badge tone="neutral" className="h-5 px-2 text-[11px]" title={`Revoked ${formatDateTime(d.revoked_at)}`}>
              Revoked
            </Badge>
          ) : null}
        </span>
      ),
    },
    ...(showOwner
      ? [{ key: 'owner', header: 'Owner', sortValue: (d: Device) => d.user_name, cell: (d: Device) => d.user_name } satisfies Column<Device>]
      : []),
    { key: 'platform', header: 'Platform', sortValue: d => d.platform, cell: d => d.platform || '—', hideBelow: 'sm' },
    {
      key: 'version',
      header: 'App version',
      sortValue: d => d.app_version,
      cell: d => <span className="tabular">{d.app_version || '—'}</span>,
      hideBelow: 'lg',
    },
    {
      key: 'paired',
      header: 'Paired',
      sortValue: d => d.created_at,
      cell: d => (
        <span className="tabular text-fg-muted" title={formatDateTime(d.created_at)}>
          {formatRelative(d.created_at)}
        </span>
      ),
      hideBelow: 'md',
    },
    {
      key: 'seen',
      header: 'Last seen',
      sortValue: d => d.last_seen_at ?? 0,
      cell: d => (
        <span className="tabular text-fg-muted" title={d.last_seen_at ? formatDateTime(d.last_seen_at) : undefined}>
          {d.last_seen_at ? formatRelative(d.last_seen_at) : 'Never'}
        </span>
      ),
    },
    {
      key: 'ip',
      header: 'Last IP',
      sortValue: d => d.last_ip,
      cell: d => <span className="font-mono text-xs text-fg-muted">{d.last_ip || '—'}</span>,
      hideBelow: 'md',
    },
    { key: 'id', header: 'Device id', cell: d => <CopyDeviceId deviceId={d.device_id} />, hideBelow: 'xl' },
  ]

  return (
    <>
      <DataTable
        rows={rows}
        columns={columns}
        rowKey={d => d.id}
        empty={empty}
        filter={(d, q) =>
          [d.name, d.platform, d.app_version, d.last_ip ?? '', d.device_id, showOwner ? d.user_name : '']
            .some(v => v.toLowerCase().includes(q))
        }
        filterPlaceholder="Filter devices…"
        toolbar={
          <>
            {revokedCount ? (
              <span className="flex items-center gap-2">
                <Checkbox id="devices-show-revoked" checked={showRevoked} onCheckedChange={setShowRevoked} data-testid="devices-show-revoked" />
                <Label htmlFor="devices-show-revoked" className="text-fg-muted">
                  Show revoked ({revokedCount})
                </Label>
              </span>
            ) : null}
            {toolbar}
          </>
        }
        rowActions={d =>
          d.revoked ? null : (
            <span className="inline-flex items-center gap-0.5">
              <IconButton
                label={`Rename ${deviceLabel(d)}`}
                icon={PenIcon}
                size="icon-sm"
                onClick={() => setRenaming(d)}
                data-testid={`device-rename-${d.id}`}
              />
              <IconButton
                label={`Revoke ${deviceLabel(d)}`}
                icon={BanIcon}
                size="icon-sm"
                className="hover:text-danger"
                disabled={revoke.isPending && revoke.variables?.id === d.id}
                onClick={() => void askRevoke(d)}
                data-testid={`device-revoke-${d.id}`}
              />
            </span>
          )
        }
      />
      {renaming ? <RenameDeviceDialog device={renaming} open onOpenChange={open => !open && setRenaming(null)} /> : null}
    </>
  )
}
