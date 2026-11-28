'use client'

import { queryClient, useWs, useWsMutation, wsKey } from '@/lib/query'
import type { Response } from '@/lib/ws/client'
import { useHealthPush } from '@/features/health/findings/push'
import { FINDINGS_PAYLOAD, mergeAnswer, severityOf, type HealthFindings } from '@/features/health/findings/model'

export const FINDINGS_POLL_MS = 15_000

// health.findings.list for the health views: polled every 15 s, or only on health.changed while subscribed.
export const useHealthFindings = (enabled = true) => {
  const pushed = useHealthPush(enabled)
  return useWs('health.findings.list', FINDINGS_PAYLOAD, {
    enabled,
    staleTime: pushed ? Infinity : 5_000,
    refetchInterval: pushed ? false : FINDINGS_POLL_MS,
    select: data => data.health,
  })
}

// Each change answers with the whole HealthFindings: it replaces the cached list (keeping the catalog, which change
// answers leave out) and the top bar's severity, so nothing waits for the next event or poll.
const writeAnswer = (data: { health: HealthFindings }) => {
  queryClient.setQueryData<Response<'health.findings.list'>>(wsKey('health.findings.list', FINDINGS_PAYLOAD), previous => ({
    health: mergeAnswer(previous?.health, data.health),
  }))
  queryClient.setQueryData(wsKey('stats.dashboard.severity', null), {
    stats: severityOf(data.health),
  } as Response<'stats.dashboard.severity'>)
}

export const useAcknowledge = () => useWsMutation('health.finding.acknowledge', { onSuccess: writeAnswer })
export const useSilence = () => useWsMutation('health.finding.silence', { onSuccess: writeAnswer })
export const useTurnBackOn = () => useWsMutation('health.finding.unsilence', { onSuccess: writeAnswer })
