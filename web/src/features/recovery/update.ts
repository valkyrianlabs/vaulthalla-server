'use client'

import { api } from '@/lib/session'
import { invalidate } from '@/lib/query'
import { confirm } from '@/components/ui/Confirm'
import { RECOVERY_CODES, type RecoveryStatus, type RecoveryUpdate } from '@/models/recovery'
import { needsCode } from '@/features/recovery/shared'

export const refreshRecovery = () => invalidate('vault.recovery.status', 'recovery.costs', 'recovery.list')

// vault.recovery.update with the questions the daemon may ask on the way (the CLI asks the same ones): a shorter
// retention and adopting the vault's own unmanaged bucket each need a person's explicit yes, then the same update is
// resent with the acceptance. A "no" rethrows the refusal. Disclosure/unpriced refusals go back to the caller, which
// owns the cost disclosure.
export const sendRecoveryUpdate = async (vaultId: number, update: RecoveryUpdate): Promise<RecoveryStatus> => {
  const req: RecoveryUpdate = { ...update }
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      const data = await api.send('vault.recovery.update', { vault_id: vaultId, ...req })
      await refreshRecovery()
      return data.status
    } catch (error) {
      if (needsCode(error, RECOVERY_CODES.retentionShorten) && !req.accept_retention_shortening) {
        const ok = await confirm({
          title: 'Shorten version retention?',
          description: `${error.message} The provider permanently deletes versions older than the new retention; they can’t be recovered afterwards.`,
          confirmLabel: 'Shorten retention',
          tone: 'danger',
        })
        if (!ok) throw error
        req.accept_retention_shortening = true
        continue
      }
      if (needsCode(error, RECOVERY_CODES.bucketAdoption) && !req.accept_adoption) {
        const ok = await confirm({
          title: 'Let Vaulthalla manage this bucket?',
          description: `${error.message} Vaulthalla then manages the bucket’s versioning and its own lifecycle rule; rules other applications added are kept as they are.`,
          confirmLabel: 'Adopt the bucket',
          tone: 'primary',
        })
        if (!ok) throw error
        req.accept_adoption = true
        continue
      }
      throw error
    }
  }
  throw new Error('The server kept asking for another confirmation. Try again.')
}
