'use client'

// health.changed by push (design/health/findings.md §6), the same pattern as fs.changed: while any health view or the
// top bar badge is mounted, this session follows health.subscribe, and each event (which carries no findings) makes
// the mounted reads ask again. While subscribed nothing polls; when the server has no push (no `health.push`
// capability), the socket drops, or the server ends the subscription ({"subscribed": false}), the reads poll again.

import { useEffect, useSyncExternalStore } from 'react'
import { api } from '@/lib/session'
import { queryClient } from '@/lib/query'
import { useHelloCapability } from '@/lib/hello'
import type { ConnectionStatus } from '@/lib/ws/client'
import { PUSH_CAPABILITY } from '@/features/health/findings/model'

let holders = 0
let subscribed = false
// Bumped on every release and every socket change, so a late subscribe answer for an older socket is ignored.
let generation = 0
let detach: (() => void) | null = null
const listeners = new Set<() => void>()

const setSubscribed = (next: boolean) => {
  if (subscribed === next) return
  subscribed = next
  for (const listener of listeners) listener()
}

// Ask again: the findings and the severity rollup, wherever they are mounted.
const refresh = () =>
  Promise.all([
    queryClient.invalidateQueries({ queryKey: ['health.findings.list'] }),
    queryClient.invalidateQueries({ queryKey: ['stats.dashboard.severity'] }),
  ])

const start = async () => {
  const mine = ++generation
  try {
    await api.send('health.subscribe', null)
    if (mine !== generation || holders === 0) return
    setSubscribed(true)
    // Anything that changed before the subscription began was never pushed.
    void refresh()
  } catch {
    if (mine === generation) setSubscribed(false)
  }
}

const onMessage = (message: Record<string, unknown>) => {
  if (message.command !== 'health.changed') return
  const data = message.data && typeof message.data === 'object' ? (message.data as Record<string, unknown>) : {}
  if (data.subscribed === false) {
    // The account can no longer see the findings: no more events on this socket, so poll (and be refused) again.
    generation++
    setSubscribed(false)
    void refresh()
    return
  }
  void refresh()
}

// A subscription ends with its socket; a new socket subscribes again.
const onStatus = (status: ConnectionStatus) => {
  if (status === 'open') {
    if (holders > 0) void start()
    return
  }
  generation++
  setSubscribed(false)
}

const acquire = () => {
  holders++
  if (holders === 1) {
    const offMessage = api.onMessage(onMessage)
    const offStatus = api.subscribe(onStatus)
    detach = () => {
      offMessage()
      offStatus()
    }
    void start()
  }
  return () => {
    holders--
    if (holders > 0) return
    detach?.()
    detach = null
    generation++
    setSubscribed(false)
    api.send('health.unsubscribe', null).catch(() => undefined)
  }
}

const subscribeStore = (listener: () => void) => {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

// Follows health.changed while mounted and enabled on a server with the capability. Returns whether the session is
// subscribed right now: callers poll only while it is false.
export const useHealthPush = (enabled: boolean) => {
  const capable = useHelloCapability(PUSH_CAPABILITY, enabled)
  const active = enabled && capable
  useEffect(() => (active ? acquire() : undefined), [active])
  return useSyncExternalStore(subscribeStore, () => subscribed, () => false) && active
}
