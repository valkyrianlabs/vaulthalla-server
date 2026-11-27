// Every sentence of the Linked servers page (design/peers/link.md), in one place so copy.test.ts can hold it to what a
// link is: an authenticated connection between two servers. PURPOSE is the one sentence that names what it carries
// (mirrored vaults, whose own words are in features/mirrors/copy.ts); nothing else here says or implies that vaults
// are synced or backed up. Pure (no React).

export const PEERS_COPY = {
  title: 'Linked servers',
  description:
    'Other Vaulthalla servers this one keeps a pinned, mutually authenticated connection with. Linking two servers takes a super admin on each.',
  purpose: 'A link is the trusted connection mirrored vaults travel over; it carries nothing else.',
  denied: 'Only super admins can see and link servers.',

  acceptAction: 'Accept a link',
  linkAction: 'Link a server',
  emptyTitle: 'No linked servers',
  emptyBody:
    'To link two servers, choose Accept a link on one of them and Link a server on the other, then compare the code.',
  showUnlinked: (n: number) => `Show unlinked (${n})`,
  filter: 'Filter servers…',

  unlinkTitle: (name: string) => `Unlink ${name}?`,
  unlinkBody: (name: string) =>
    `The link closes now and this server refuses ${name}’s key from then on, so ${name} keeps nothing it can use to reconnect. If it is connected it is told, and it unlinks this server too. Linking them again takes a new pairing with a new code. No files, vaults or accounts change on either server.`,
  unlinkConfirm: 'Unlink',
  unlinked: (name: string) => `Unlinked ${name}`,
  unlinkedHint: 'Linking it again needs a new pairing.',
  unlinkFailed: 'The server was not unlinked',

  renameTitle: (name: string) => `Rename ${name}`,
  renameBody: 'The name is this server’s own label for it: it shows here, in vh peer list and in audit lines. The other server keeps its own name.',
  renamed: (name: string) => `Renamed to ${name}`,
  renameFailed: 'The server was not renamed',

  // Accept a link (this server opens the window; the other one dials).
  acceptTitle: 'Accept a link',
  acceptDescription: 'Let another Vaulthalla server link with this one by matching the code it shows.',
  opening: 'Opening a window for linking…',
  thisServer: 'This server',
  thisKey: 'Key',
  thisAddresses: 'Addresses the other server can use',
  noAddresses: 'The device listener advertises no address yet.',
  acceptSteps: [
    'On the other server, choose Linked servers › Link a server (or run vh peer link <address>) and give it one of the addresses above.',
    'To trust nothing but this server, also give it this server’s key. Without the key, the code you compare is the check.',
    'It shows a six-digit code. Click the same code on its request below; a wrong code declines the request.',
  ],
  remoteOff:
    'Remote connections are off, so only a server on this machine can reach this one.',
  remoteOffLink: 'Turn them on',
  remoteOffAfter: 'to link a server on your network, or link from this server to the other one instead.',
  notListening: 'The device listener isn’t listening, so no other server can reach this one.',
  waiting: 'Waiting for another server to ask…',
  windowLeft: 'Open for',
  windowClosedTitle: 'The window closed',
  windowClosedBody: 'Requests that weren’t approved expired with it. Open it again to keep waiting.',
  openAgain: 'Open again',
  conflictTitle: 'Another pairing window is open',
  conflictBody:
    'A device or a server is being paired on this server, and only one window can be open at a time. Try again when it’s done.',
  tryAgain: 'Try again',
  requestFrom: (ip: string) => `from ${ip}`,
  whichCode: 'Which code does the other server show?',
  codesFor: (name: string) => `Codes for ${name}`,
  checking: 'Checking…',
  deny: 'Deny',
  wrongCode: 'That code didn’t match, so the request was declined. Start the link again on the other server.',
  expiredRequest: 'That request expired before it was approved. Start the link again on the other server.',
  notApproved: 'The request was not approved',
  declined: (name: string) => `Declined the request from ${name}.`,
  notDenied: 'The request was not declined',
  linkedTitle: 'Linked',
  linkedBody: (name: string) => `${name} is now linked with this server. The two connect on their own.`,
  done: 'Done',
  close: 'Close',

  // Link a server (this server dials the other one).
  linkTitle: 'Link a server',
  linkDescription: 'Connect to another Vaulthalla server that has Accept a link open, then compare the code on both.',
  addressLabel: 'Address',
  addressHint: 'A host name or IP address of the other server, as its Accept a link window lists them. host:port works too.',
  portLabel: 'Port',
  portHint: 'Its device listener’s port; this server’s own is the default.',
  fingerprintLabel: 'Its key (optional)',
  fingerprintHint:
    'The key its Accept a link window shows. With it, this server completes the connection with no other key; without it, the code you compare is the check.',
  start: 'Connect',
  connecting: (address: string) => `Connecting to ${address}…`,
  codeIntro: 'This server computed the code',
  codeStep: (name: string) => `On ${name}, click this code on this server’s request. If no request shows this code there, deny it.`,
  theirKey: 'Its key',
  linkedWith: (name: string) => `Linked with ${name}. The two connect on their own.`,
  linkDenied: 'The other server declined the request, or a different code was picked there. Nothing was linked.',
  linkExpired: 'The request expired before the other server approved it. Nothing was linked.',
  linkFailed: 'Couldn’t link',
  linkCancelled: 'Cancelled. Nothing was linked.',
  cancel: 'Cancel',
  startOver: 'Start again',
  otherServer: 'the other server',
  closeStops: 'Closing this window stops the attempt.',
  notStarted: 'The link was not started',
} as const

// Who compared the code (the row's compared_by, from the channel of the call that made the link here): a person in the
// console or at the terminal, or Vaulthalla Desktop brokering the link over its device sessions.
export const COMPARED_BY: Readonly<Record<'person' | 'desktop', string>> = {
  person: 'A person',
  desktop: 'Desktop',
}

// Every sentence above, flattened (functions called with a sample name), for copy.test.ts.
export const allCopy = (): string[] =>
  Object.values(PEERS_COPY).flatMap(v =>
    typeof v === 'function' ? [String((v as (s: never) => string)('server-b' as never))] : Array.isArray(v) ? [...v] : [String(v)],
  )
