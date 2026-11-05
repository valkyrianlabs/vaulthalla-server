// Idle sign-out (#319): tell the server when a person actually uses the console, so its idle clock only counts real
// interaction. Background traffic (polling, refreshes, reconnects) never reports activity. The server stamps its own
// time on each report; nothing here sends a timestamp. Dependency-free so it can be unit tested under node --test.

// Real input. pointermove and scroll fire constantly; the reporter below drops all but one per interval.
export const ACTIVITY_EVENTS = ['pointerdown', 'pointermove', 'keydown', 'wheel', 'scroll', 'touchstart'] as const

// At most one report per minute: the server writes at most every 30 s and its timeout is in minutes.
export const REPORT_INTERVAL_MS = 60_000

export interface ActivityReporter {
  // Call on any user input. Sends at most one report per interval, never two at once.
  onActivity: () => void
}

export const createActivityReporter = ({
  send,
  now = () => Date.now(),
  intervalMs = REPORT_INTERVAL_MS,
}: {
  send: () => Promise<unknown>
  now?: () => number
  intervalMs?: number
}): ActivityReporter => {
  let lastSent = Number.NEGATIVE_INFINITY
  let inFlight = false
  return {
    onActivity: () => {
      const t = now()
      if (inFlight || t - lastSent < intervalMs) return
      lastSent = t
      inFlight = true
      send()
        .catch(() => {
          // Not delivered (socket down, or the session already ended): let the next input try again. A session that
          // has ended is handled by the session gate, not here.
          lastSent = Number.NEGATIVE_INFINITY
        })
        .finally(() => {
          inFlight = false
        })
    },
  }
}

// Listens for input on `target` (the window) and feeds the reporter; returns the cleanup.
export const trackActivity = (target: EventTarget, reporter: ActivityReporter): (() => void) => {
  const handler = () => reporter.onActivity()
  const options: AddEventListenerOptions = { capture: true, passive: true }
  for (const type of ACTIVITY_EVENTS) target.addEventListener(type, handler, options)
  return () => {
    for (const type of ACTIVITY_EVENTS) target.removeEventListener(type, handler, options)
  }
}
