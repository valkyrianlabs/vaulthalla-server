// The cloud relay panel's sentences (design/cloud/relay.md); the device pages' words are in labels.ts. The claims lint
// (tools/contracts/encryption_claims.py, RELAY_MENTION) allows the service's name only as "Vaulthalla Cloud's relay"
// and the device label, never next to recovery, custody or availability; the panel says in its own sentence that the
// service isn't offered to the public yet. Keep each sentence that names it on one line: the lint judges console
// strings line by line. Pure (no React): see copy.test.ts.

export const RELAY_COPY = {
  title: 'Relay for web browsers',
  description: 'Lets a web browser you pair reach this server from anywhere, read-only, without opening a port.',
  what: "Switched on, this server opens one outbound connection to Vaulthalla Cloud's relay. A web browser its owner pairs under Devices can then browse and download through it, read-only: it can't upload, change or delete anything.",
  sees: "The relay passes encrypted bytes it can't read. It can see which account and server a connection is for, the browser's key, the browser's and this server's network addresses, and when and how much data passes.",
  notOffered: "Vaulthalla Cloud isn't offered to the public yet. The relay also needs a linked account whose holder has switched it on there too.",
  switchLabel: 'Allow web browsers through the relay',
  switchHintOn: 'On: paired web browsers can browse and download, read-only.',
  switchHintOff: 'Off: nothing connects to the relay.',
  superAdminOnly: 'Only a super admin can switch the relay.',
  enableTitle: 'Switch the relay on?',
  enableBody: "This server opens one outbound connection to Vaulthalla Cloud's relay, and web browsers you pair can browse and download through it, read-only. You'll confirm it's you first.",
  enableConfirm: 'Switch on',
  disableTitle: 'Switch the relay off?',
  disableBody: 'The connection to the relay closes and every relayed browser session ends now. Paired browsers stay paired; revoke one under Devices to unpair it.',
  disableConfirm: 'Switch off',
  enabledToast: 'The relay is on',
  disabledToast: 'The relay is off',
  retry: 'Try again',
  retryHint: 'Switching it on again is how a stopped relay tries again.',
} as const

export type RelayState =
  | 'off'
  | 'not_linked'
  | 'listener_off'
  | 'connecting'
  | 'connected'
  | 'backoff'
  | 'waiting'
  | 'stopped'

export type RelayTone = 'ok' | 'info' | 'warn' | 'danger' | 'neutral'

// The service's state in words: a badge label, its tone, and one sentence. `when` formats Unix seconds.
export const relayStateText = (
  s: { state: RelayState; connected_since: number | null; next_attempt_at: number | null },
  when: (seconds: number) => string,
): { label: string; tone: RelayTone; detail: string } => {
  const next = s.next_attempt_at ? ` Next attempt ${when(s.next_attempt_at)}.` : ''
  switch (s.state) {
    case 'off':
      return { label: 'Off', tone: 'neutral', detail: 'Switched off on this server. Nothing connects to the relay.' }
    case 'not_linked':
      return { label: 'Not linked', tone: 'neutral', detail: "This server isn't linked to an account, so the relay can't be switched on." }
    case 'listener_off':
      return {
        label: 'Device listener off',
        tone: 'warn',
        detail: 'Switched on, but the device listener is turned off in config.yaml (device_server.enabled). Relayed browsers reach this server through it, so nothing connects.',
      }
    case 'connecting':
      return { label: 'Connecting', tone: 'info', detail: 'Opening the connection to the relay.' }
    case 'connected':
      return {
        label: 'Connected',
        tone: 'ok',
        detail: s.connected_since ? `Connected since ${when(s.connected_since)}.` : 'Connected.',
      }
    case 'backoff':
      return { label: 'Retrying', tone: 'warn', detail: `The last attempt failed.${next}` }
    case 'waiting':
      return {
        label: 'Waiting',
        tone: 'warn',
        detail: `The account doesn't accept this server on the relay right now: its holder's relay switch may be off, or the service isn't ready. This server asks again every 5 minutes.${next}`,
      }
    case 'stopped':
      return {
        label: 'Stopped',
        tone: 'danger',
        detail: 'The relay service refused this server. It stays stopped until the relay is switched on again.',
      }
  }
}

// "Switched on by ada on <date>", only while on (the server keeps who switched it on, not who switched it off).
export const relaySwitchedBy = (s: { enabled: boolean; enabled_by: string | null; enabled_at: number | null }, when: (seconds: number) => string) =>
  s.enabled && s.enabled_by ? `Switched on by ${s.enabled_by}${s.enabled_at ? ` on ${when(s.enabled_at)}` : ''}` : null

// The switch can be turned on only on a linked server; it can always be turned off.
export const relaySwitchable = (s: { enabled: boolean; state: RelayState }) => s.enabled || s.state !== 'not_linked'
