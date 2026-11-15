// The device pages' words for a pairing request or a device that came through the cloud relay (design/cloud/relay.md),
// apart from copy.ts so /devices loads only these. The claims lint allows the label below (encryption_claims.py,
// RELAY_MENTION). Pure: see copy.test.ts.

export const RELAY_LABELS = {
  viaRelay: 'Web browser via Vaulthalla Cloud',
  readOnly: 'Read-only',
  readOnlyHint: 'Paired through the relay: it can browse and download, never change anything.',
  requestReadOnly: 'It will be read-only: it can browse and download, never upload, change or delete anything.',
} as const
