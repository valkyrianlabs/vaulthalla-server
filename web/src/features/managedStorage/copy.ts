// Every sentence the console shows about managed storage, in one module. Until the service opens, nothing here names
// it or ties it to key recovery (tools/contracts/encryption_claims.py); the launch change edits this file only.
// Pure (no React): see model.test.ts.

export const COPY = {
  navLabel: 'Managed storage',
  title: 'Managed storage',
  description:
    "Each vault can be kept in a bucket of its own that your account provides. Vaults stay encrypted on this server, which holds their keys; nothing unencrypted leaves it.",
  offerTitle: (n: number) => `${n} existing vault${n === 1 ? '' : 's'} can use managed storage`,
  offerBody: 'Nothing is uploaded until you choose. Each vault keeps its own switch afterwards.',
  acceptAll: 'Use for all',
  decline: 'Keep them local',
  manageBilling: 'Manage billing',
  choosePlan: 'Choose a plan',
  leave: 'Leave managed storage',
  leaveConfirm:
    'Leaving moves the buckets to an account of your own with the provider; your vaults keep working in place with your own credentials.',
  newVaultsLabel: 'Use managed storage for new vaults',
  newVaultsHint: 'New vaults are uploaded once they hold their first file.',
  switchLabel: 'Managed storage',
  switchHintOn: 'Uploaded to a bucket of its own once it holds a file.',
  switchHintOff: 'Stays on this server only.',
  newVaultSwitchLabel: 'Keep this vault in managed storage',
  turnOffTitle: 'Make this vault local again?',
  turnOffBody:
    "Every file is fetched and checked on this server first; then the vault stops using its bucket. The bucket and its history are left in place.",
  turnOffConfirm: 'Make local',
  endedTitle: 'The plan has ended',
  endedBody: (convertsAt: string) =>
    `Managed vaults are kept attached without access until ${convertsAt}, or until you confirm. Then they become local in place; files held only in their buckets are listed as lost, and nothing on this server is deleted.`,
  endedConfirm: 'Make them local now',
  unavailable: {
    unlinked: 'This server isn’t linked to an account.',
    unconfirmed: "The account key's fingerprint hasn't been confirmed on this server yet.",
    tampered: 'The pinned account key failed its integrity check.',
    noPlan: 'The account has no storage plan.',
  },
  usageCaption: (day: string | null) => (day ? `Account usage as of ${day}` : 'Account usage'),
  localCaption: 'Held on this server in managed vaults',
  lastChecked: (when: string) => `Last confirmed ${when}`,
} as const

// A plan state as one sentence (`entitlement` from cloud.storage.status).
export const planSentence = (entitlement: string | null | undefined, plan: string | null | undefined): string => {
  const p = plan ? ` (${plan})` : ''
  switch (entitlement) {
    case 'active': return `Your plan${p} is active.`
    case 'past_due': return `Payment for your plan${p} is overdue; storage keeps full access for now.`
    case 'restricted': return 'Your plan is restricted: vaults are read-only in their buckets, and local changes are kept until it is active again.'
    case 'suspended': return 'Your plan is suspended: buckets are out of reach, local copies keep working, and the data is kept for now.'
    case 'ended': return 'Your plan has ended.'
    default: return 'There is no storage plan on this account.'
  }
}
