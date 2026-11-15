// The device pages' words for a pairing request or a device that came through the cloud relay (design/cloud/relay.md),
// apart from copy.ts so /devices loads only these. They never name the service (see copy.ts). Pure: see copy.test.ts.

export const RELAY_LABELS = {
  viaRelay: 'Web browser (relay)',
  readOnly: 'Read-only',
  readOnlyHint: 'Paired through the relay: it can browse and download, never change anything.',
  pairBrowser: "While this server's relay is on, a web browser is paired from your account's web page: open pairing here, then start it there.",
  requestReadOnly: 'It will be read-only: it can browse and download, never upload, change or delete anything.',
} as const
