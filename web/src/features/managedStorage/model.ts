// Managed storage's view of cloud.storage.status (design/cloud/managed-remotes.md, "The console page"): which vaults
// are shown, how far an upload is, and what state reads as. Pure: see model.test.ts.
import type { Response } from '@/lib/ws/client'

export type StorageStatus = Response<'cloud.storage.status'>
export type StorageVault = StorageStatus['vaults'][number]

// meta.hello capability for this page and the new-vault switch (listed in WS_CAPABILITIES).
export const MANAGED_STORAGE_CAPABILITY = 'cloud.storage.managed_remotes'

export type Tone = 'ok' | 'info' | 'warn' | 'danger' | 'neutral'

// The vault's state as the server words it, with a tone that only follows the server's state.
export const stateTone = (v: Pick<StorageVault, 'state' | 'access' | 'reason'>): Tone => {
  if (v.state === 'active') return v.access === 'full' ? 'ok' : 'warn'
  if (v.state === 'failed' || v.state === 'moved') return 'danger'
  if (v.state === 'attaching' || v.state === 'detaching' || v.state === 'keyed' || v.state === 'registered') return 'info'
  if (v.state === 'waiting') return 'warn'
  return 'neutral'
}

// Upload or conversion progress, 0..1, or null while unknown.
export const progressRatio = (v: Pick<StorageVault, 'progress'>): number | null => {
  const p = v.progress
  if (!p || !p.bytes_total) return null
  return Math.min(1, p.bytes_done / p.bytes_total)
}

// Usage against the quota, 0..1, or null without a figure.
export const usageRatio = (s: Pick<StorageStatus, 'used_bytes' | 'quota_bytes'>): number | null =>
  s.used_bytes == null || !s.quota_bytes ? null : Math.min(1, s.used_bytes / s.quota_bytes)

// The vaults the page lists under "Vaults": every vault but the offered ones (they are in the offer banner).
export const listedVaults = (s: Pick<StorageStatus, 'vaults'>): StorageVault[] => s.vaults.filter(v => v.switch !== 'offered')

// Whether the switch can be flipped from here: a vault on its own storage, one that left, and a moved one being kept
// can't.
export const switchable = (v: Pick<StorageVault, 'storage' | 'state'>): boolean =>
  v.storage !== 'own' && v.state !== 'ejected' && v.state !== 'detaching'

// Switching off a vault that has a bucket needs the vault's name typed (the server checks it too).
export const offNeedsConfirm = (v: Pick<StorageVault, 'state'>): boolean =>
  v.state === 'active' || v.state === 'attaching' || v.state === 'moved'

// The ejection portal, when the server knows it (the service returns it with the account's state).
export const leaveUrl = (s: Pick<StorageStatus, 'ejection'>): string | null => {
  const e = s.ejection as { portal_url?: unknown } | null | undefined
  return e && typeof e.portal_url === 'string' && e.portal_url.startsWith('https://') ? e.portal_url : null
}
