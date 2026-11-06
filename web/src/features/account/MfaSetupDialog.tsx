'use client'

import React from 'react'
import { Dialog, DialogContent } from '@/components/ui/Dialog'
import { PASSKEY_LABEL } from '@/models/mfa'
import { PasskeySetup, RecoveryCodes, TotpSetup, type Enrolled } from '@/features/auth/mfa/setup'
import type { Open } from './MfaPanel'

// Account → Security: adding a factor, and saving the recovery codes a first factor or a new batch comes with. The
// codes step can't be dismissed: they are shown once, and only the acknowledgement puts them in force.
export const MfaSetupDialog = ({
  open,
  onClose,
  onEnrolled,
  onAcknowledged,
}: {
  open: NonNullable<Open>
  onClose: () => void
  onEnrolled: (result: Enrolled) => void
  onAcknowledged: (batchId: string) => Promise<void>
}) => (
  <Dialog open onOpenChange={value => !value && open.at !== 'codes' && onClose()}>
    <DialogContent
      title={open.at === 'codes' ? 'Save your recovery codes' : open.at === 'passkey' ? `Add a ${PASSKEY_LABEL.toLowerCase()}` : 'Add an authenticator app'}
      hideClose={open.at === 'codes'}>
      {open.at === 'passkey' ? <PasskeySetup onEnrolled={onEnrolled} cta="Add passkey" /> : null}
      {open.at === 'totp' ? <TotpSetup onEnrolled={onEnrolled} /> : null}
      {open.at === 'codes' ? <RecoveryCodes batch={open.batch} onAcknowledged={onAcknowledged} /> : null}
    </DialogContent>
  </Dialog>
)
