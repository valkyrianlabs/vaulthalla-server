import type { Response } from '@/lib/ws/client'
import type { Device } from '@/models/device'

// Paired devices (Vaulthalla Desktop). Normative protocol: docs/pairing.md in valkyrianlabs/vaulthalla-desktop (§3 number matching,
// §6 revocation); the daemon side is ops::devices (ws device.*).

export type PairingWindow = Response<'device.pairing.open'>['window']
export type PendingRequest = Response<'device.pairing.pending'>['requests'][number]
export type ListenerStatus = Response<'device.remote.status'>['status']

// Every read a device change can affect.
export const DEVICE_READS = ['device.list'] as const

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

// Live devices first (newest pairing first), revoked ones after.
export const byStatus = (a: Device, b: Device) => Number(a.revoked) - Number(b.revoked) || b.created_at - a.created_at
