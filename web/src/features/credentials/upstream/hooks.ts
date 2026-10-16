'use client'

import { useWs } from '@/lib/query'
import { useCan } from '@/lib/permissions'
import { confirm, type ConfirmRequest } from '@/components/ui/Confirm'
import { isWsError } from '@/lib/ws/errors'
import type { Tone } from '@/lib/tone'
import type { BucketState } from '@/models/upstream'

// UI gating only: ops::upstream checks admin.upstream.* plus the key's own keys.api permission on every call, and
// the pages render the typed denial when the daemon refuses.
export const useUpstreamPerms = () => ({
  view: useCan({ permission: 'admin.upstream.view' }),
  configure: useCan({ permission: 'admin.upstream.configure' }),
  provision: useCan({ permission: 'admin.upstream.provision' }),
  protect: useCan({ permission: 'admin.upstream.protect' }),
  unprotect: useCan({ permission: 'admin.upstream.unprotect' }),
  destroy: useCan({ permission: 'admin.upstream.destroy' }),
})

export const useAdminStatus = (apiKeyId: number, enabled = true) =>
  useWs(
    'upstream.admin.status',
    { api_key_id: apiKeyId },
    { enabled: enabled && apiKeyId > 0, retry: false, select: d => d.admin },
  )

export const useEventStatus = (vaultId: number, enabled = true) =>
  useWs(
    'upstream.events.status',
    { vault_id: vaultId },
    { enabled: enabled && vaultId > 0, retry: false, refetchInterval: 30_000, select: d => d.events?.[0] ?? null },
  )

// The daemon refuses an operation that a person must accept first with data.code `code` (NeedsConfirmation). Show
// its text, resend accepted only on an explicit yes, rethrow the refusal on a no (callers report it).
export const withConfirmation = async <T>(
  code: string,
  send: (accepted: boolean) => Promise<T>,
  ask: (message: string) => ConfirmRequest,
): Promise<T> => {
  try {
    return await send(false)
  } catch (error) {
    if (!isWsError(error, 'needs_confirmation') || error.code !== code) throw error
    if (!(await confirm(ask(error.message)))) throw error
    return send(true)
  }
}

export const bucketStateTone: Record<BucketState, Tone> = {
  managed: 'accent',
  adopted: 'info',
  unmanaged: 'neutral',
  protected: 'warn',
}

export const bucketStateLabel: Record<BucketState, string> = {
  managed: 'Managed',
  adopted: 'Adopted',
  unmanaged: 'Unmanaged',
  protected: 'Protected',
}

// Subscription/channel states as the daemon reports them; unknown values stay "unknown", never healthy.
export const eventStateTone = (state: string | null | undefined): Tone => {
  switch (state) {
    case 'active':
      return 'ok'
    case 'pending':
    case 'provisioning':
    case 'removing':
      return 'info'
    case 'degraded':
      return 'warn'
    case 'failed':
      return 'danger'
    case 'none':
    case 'removed':
      return 'neutral'
    default:
      return 'unknown'
  }
}

export const isBound = (vaultId: number | null | undefined) => typeof vaultId === 'number' && vaultId > 0
