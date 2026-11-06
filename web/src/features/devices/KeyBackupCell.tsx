'use client'

import React from 'react'
import { useWsMutation } from '@/lib/query'
import { formatDateTime, formatRelative } from '@/lib/format'
import { Badge } from '@/components/ui/Badge'
import { IconButton } from '@/components/ui/IconButton'
import { confirm } from '@/components/ui/Confirm'
import { notify } from '@/components/ui/Toast'
import { BanIcon, ShieldCheckIcon } from '@/components/ui/icons'
import { GRANT_READS, type KeyBackupGrant } from '@/features/devices/model'

const vaultCount = (g: KeyBackupGrant) => `${g.vault_ids.length} vault${g.vault_ids.length === 1 ? '' : 's'}`

// A device's automatic key backup (#362): Vaulthalla Desktop exports the keys of the vaults its grant names to
// 1Password with no prompt. A migrated grant (from before grants existed) asks to be confirmed or turned off; a
// suspended one (more than 60 exports in an hour) to be confirmed again. Confirming needs a fresh passkey or
// password + authenticator check (the Step-up dialog); turning it off needs none.
export const KeyBackupCell = ({ grant, deviceName }: { grant?: KeyBackupGrant; deviceName: string }) => {
  const confirmGrant = useWsMutation('device.backup.grant.confirm', {
    toPayload: (g: KeyBackupGrant) => ({ grant_id: g.id }),
    invalidates: [...GRANT_READS],
    onSuccess: () => notify.success('Automatic key backup confirmed', `${deviceName} keeps backing up its vault keys.`),
  })
  const revokeGrant = useWsMutation('device.backup.grant.revoke', {
    toPayload: (g: KeyBackupGrant) => ({ grant_id: g.id }),
    invalidates: [...GRANT_READS],
    onSuccess: () => notify.success('Automatic key backup turned off', `${deviceName} asks before exporting keys now.`),
  })

  if (!grant || grant.revoked_at !== null) return <span className="text-fg-muted">Off</span>

  const askOff = async () => {
    const ok = await confirm({
      title: `Turn off automatic key backup on ${deviceName}?`,
      description: (
        <>
          It stops backing up vault keys to 1Password without asking. Each key export from it then needs your approval,
          and turning it back on needs one too.
        </>
      ),
      confirmLabel: 'Turn off',
      tone: 'danger',
    })
    if (ok) revokeGrant.mutate(grant, { onError: error => notify.error(error, 'Key backup stayed on') })
  }

  const pending = grant.origin === 'migrated' || grant.suspended_at !== null
  const used = grant.last_used_at ? `Last backup ${formatRelative(grant.last_used_at)}` : 'No backup yet'
  return (
    <span className="inline-flex items-center gap-1" data-testid="device-key-backup">
      {grant.suspended_at !== null ? (
        <Badge tone="warn" className="h-5 px-2 text-[11px]" title={`Paused ${formatDateTime(grant.suspended_at)}: too many exports in an hour`}>
          Paused
        </Badge>
      ) : grant.origin === 'migrated' ? (
        <Badge tone="info" className="h-5 px-2 text-[11px]" title={`${vaultCount(grant)}. ${used}. Confirm or turn it off.`}>
          Confirm
        </Badge>
      ) : (
        <Badge tone="ok" className="h-5 px-2 text-[11px]" title={used}>
          On · {vaultCount(grant)}
        </Badge>
      )}
      {pending ? (
        <IconButton
          label={`Confirm automatic key backup on ${deviceName}`}
          icon={ShieldCheckIcon}
          size="icon-sm"
          disabled={confirmGrant.isPending}
          onClick={() => confirmGrant.mutate(grant, { onError: error => notify.error(error, 'Not confirmed') })}
          data-testid={`grant-confirm-${grant.id}`}
        />
      ) : null}
      <IconButton
        label={`Turn off automatic key backup on ${deviceName}`}
        icon={BanIcon}
        size="icon-sm"
        className="hover:text-danger"
        disabled={revokeGrant.isPending}
        onClick={() => void askOff()}
        data-testid={`grant-revoke-${grant.id}`}
      />
    </span>
  )
}
