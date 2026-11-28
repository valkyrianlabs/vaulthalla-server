// Every sentence of the health findings controls (design/health/findings.md §11): the state of each finding, the
// Acknowledge / Silence / Turn back on controls, the Silenced list and the top bar's health badge. In one place so
// copy.test.ts can hold it to the design's rules. Pure (no React).

export const FINDINGS_COPY = {
  attentionTitle: 'Needs attention',
  attentionAllSilenced: 'Nothing new needs attention. The findings below are silenced and still count in the health status.',
  silencedTitle: 'Silenced',
  silencedDescription:
    'You are not told about these: they are left out of the top bar badge and notifications. They still count in the health status above.',
  notActiveNow: 'Not active now',
  activeNow: 'Active now',
  loadFailed: 'The findings could not be loaded',

  // A finding's state.
  active: 'Not acknowledged',
  acknowledged: (who: string, when: string) => `Acknowledged by ${who} ${when}`,
  silencedUntil: (who: string, until: string) => `Silenced by ${who} until ${until}`,
  silencedForever: (who: string) => `Silenced by ${who} until turned back on`,
  silencedAt: (when: string) => `Silenced ${when}`,
  someone: 'someone',
  note: (text: string) => `Note: ${text}`,

  // Controls.
  acknowledge: 'Acknowledge',
  acknowledgeHint: 'Mark this as seen. It needs attention again if it clears and comes back, or gets worse.',
  silence: 'Silence…',
  turnBackOn: 'Turn back on',
  acknowledgedToast: 'Acknowledged',
  silencedToast: (title: string) => `${title} is silenced`,
  turnedBackOnToast: (title: string) => `${title} is turned back on`,
  acknowledgeFailed: 'The finding was not acknowledged',
  silenceFailed: 'The finding was not silenced',
  turnBackOnFailed: 'The finding was not turned back on',

  // The silence dialog.
  silenceTitle: (title: string) => `Silence “${title}”`,
  silenceBody:
    'You stop being told about this kind of finding, now and when it comes back: it leaves the top bar badge and notifications and is listed under Silenced. It still counts in the health status. If it gets worse, you are told again.',
  silenceFor: 'For how long',
  noteLabel: 'Note (optional)',
  noteHint: (max: number) => `Up to ${max} characters. Other operators see it next to the silence.`,
  noteTooLong: (max: number, length: number) => `At most ${max} characters (${length} now).`,
  silenceConfirm: 'Silence',
  cancel: 'Cancel',

  // The top bar badge counts only what nobody has acknowledged or silenced; the health pages keep the true counts.
  badgeUnknown: 'Health unknown',
  badgeStale: 'The last health check failed',
  badgeAllSeen: 'Nothing new',
  badgeAllSeenTitle: (counts: string) => `System health: ${counts}, all acknowledged or silenced`,
  badgeTitle: (label: string) => `System health: ${label}`,
} as const

// The silence lengths an operator can choose (§3: a silence lasts for a time, or until someone turns it back on).
export const SILENCE_LABELS = {
  hour: '1 hour',
  day: '24 hours',
  week: '7 days',
  forever: 'Until turned back on',
} as const

// Every string here, for copy.test.ts.
export const allCopy = (): string[] => {
  const out: string[] = Object.values(SILENCE_LABELS)
  for (const value of Object.values(FINDINGS_COPY)) {
    if (typeof value === 'string') out.push(value)
    else out.push((value as (...args: (string | number)[]) => string)('X', 'Y'))
  }
  return out
}
