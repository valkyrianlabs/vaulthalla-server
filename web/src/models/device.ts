// A paired device (Vaulthalla Desktop): what core's device::Device serializes (ws device.list / rename / revoke /
// device.pairing.approve). Times are Unix seconds. device_id is the SHA-256 of the device certificate's
// SubjectPublicKeyInfo (64 lowercase hex digits); `id` is the row number, stable across key rotations.
export interface Device {
  id: number
  device_id: string
  user_id: number
  user_name: string
  name: string
  platform: string
  app_version: string
  previous_device_id: string | null
  approved_by: number | null
  created_at: number
  last_seen_at: number | null
  last_ip: string | null
  revoked_at: number | null
  revoked: boolean
}
