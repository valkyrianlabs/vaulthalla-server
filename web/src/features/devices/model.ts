import type { Response } from '@/lib/ws/client'
import type { Device, DeviceScope } from '@/models/device'
import { RELAY_LABELS } from '@/features/cloudRelay/labels'

// Paired devices (Vaulthalla Desktop). Normative protocol: docs/pairing.md in valkyrianlabs/vaulthalla-desktop (§3 number matching,
// §6 revocation); the daemon side is ops::devices (ws device.*).

export type PairingWindow = Response<'device.pairing.open'>['window']
export type PendingRequest = Response<'device.pairing.pending'>['requests'][number]
export type ListenerStatus = Response<'device.remote.status'>['status']
// A device's key-backup grant (#362): no-prompt 1Password backup of the vault keys it names.
export type KeyBackupGrant = Response<'device.backup.grant.list'>['grants'][number]

// Every read a device change can affect.
export const DEVICE_READS = ['device.list', 'device.backup.grant.list'] as const
export const GRANT_READS = ['device.backup.grant.list'] as const

// "482913" → "482 913", the way Desktop shows it (spec §3). Anything that isn't six digits is shown as sent.
export const formatCode = (code: string) => (/^\d{6}$/.test(code) ? `${code.slice(0, 3)} ${code.slice(3)}` : code)

// The device id is the SHA-256 of the device key (64 hex digits); the CLI accepts 8+ leading digits, so 12 is plenty
// to tell devices apart and to type into `vh device revoke`.
export const shortDeviceId = (deviceId: string) => deviceId.slice(0, 12)

// A key fingerprint in groups of four for reading aloud or comparing by eye.
export const groupHex = (hex: string) => hex.match(/.{1,4}/g)?.join(' ') ?? hex

export const deviceLabel = (device: Pick<Device, 'name'>) => device.name || 'Unnamed device'

export const platformLabel = (platform: string, appVersion?: string | null) =>
  [platform || 'Unknown platform', appVersion ? `Desktop ${appVersion}` : null].filter(Boolean).join(' · ')

// A pairing request or a device that came through the cloud relay (a web browser, read-only), from the server's
// `via` / `paired_via`, never from the platform string.
export const requestViaRelay = (request: Pick<PendingRequest, 'via'>) => request.via === 'relay'
export const pairedViaRelay = (device: Pick<Device, 'paired_via'>) => device.paired_via === 'relay'

// What a request is, in the dialog's subtitle.
export const requestLabel = (request: Pick<PendingRequest, 'via' | 'platform' | 'app_version'>) =>
  requestViaRelay(request) ? RELAY_LABELS.viaRelay : platformLabel(request.platform, request.app_version)

// The platform column: a relay-paired device is a web browser via the relay whatever it calls itself.
export const devicePlatform = (device: Pick<Device, 'paired_via' | 'platform'>) =>
  pairedViaRelay(device) ? RELAY_LABELS.viaRelay : device.platform || '—'

// Scoped devices: what a device may do, in the console's words (absent: a server before scopes, no limit).
export const SCOPE_LABELS: Readonly<Record<DeviceScope, string>> = {
  read: 'Read only',
  write: 'Read and change',
  destructive: 'Full access',
}
export const scopeLabel = (scope: DeviceScope | undefined) => SCOPE_LABELS[scope ?? 'destructive']
const SCOPE_RANK: Readonly<Record<DeviceScope, number>> = { read: 1, write: 2, destructive: 3 }
// The scopes an approval may give: what the request asked for or less (anything, when it asked for none).
export const scopesUpTo = (asked: DeviceScope | undefined): DeviceScope[] =>
  (['read', 'write', 'destructive'] as const).filter(s => SCOPE_RANK[s] <= SCOPE_RANK[asked ?? 'destructive'])

// Live devices first (newest pairing first), revoked ones after.
export const byStatus = (a: Device, b: Device) => Number(a.revoked) - Number(b.revoked) || b.created_at - a.created_at
