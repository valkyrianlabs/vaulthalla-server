'use client'

import React from 'react'
import { api } from '@/lib/session'
import { SwitchRow } from '@/components/ui/Choice'
import { COPY } from '@/features/managedStorage/copy'
import { useCloudView, useManagedStorageCapability, useManagedStorageStatus } from '@/features/managedStorage/queries'

// The new-vault page's switch (design/cloud/managed-remotes.md, "The console page"): shown for a local vault with the
// capability, the view permission and storage available, on when the server's default is on. `checked` null: follow
// the default.
export const useNewVaultManagedStorage = () => {
  const canView = useCloudView()
  const capable = useManagedStorageCapability(canView)
  const status = useManagedStorageStatus(canView && capable)
  const shown = canView && capable && !!status.data?.available
  return { shown, defaultOn: status.data?.new_vaults ?? true }
}

export const NewVaultManagedStorageSwitch = ({
  checked,
  onCheckedChange,
}: {
  checked: boolean
  onCheckedChange: (on: boolean) => void
}) => (
  <SwitchRow
    id="new-vault-managed-storage"
    label={COPY.newVaultSwitchLabel}
    hint={checked ? COPY.switchHintOn : COPY.switchHintOff}
    checked={checked}
    onCheckedChange={onCheckedChange}
  />
)

// After the vault is created: only a choice that differs from the server's default is sent (the default needs nothing).
export const applyNewVaultChoice = async (vaultId: number, on: boolean, defaultOn: boolean) => {
  if (on === defaultOn) return
  await api.send('cloud.storage.switch', { vault_id: vaultId, enabled: on, confirm: null })
}
