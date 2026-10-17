'use client'

import React, { useEffect, useId, useState } from 'react'
import { Dialog, DialogContent } from '@/components/ui/Dialog'
import { Button } from '@/components/ui/Button'
import { Checkbox } from '@/components/ui/Choice'
import { DefinitionList } from '@/components/ui/Panel'
import { InlineError } from '@/components/ui/State'
import { Spinner } from '@/components/ui/Spinner'
import { notify } from '@/components/ui/Toast'
import { TriangleExclamationIcon } from '@/components/ui/icons'
import { useWs } from '@/lib/query'
import { DASH } from '@/lib/format'
import { RECOVERY_CODES, type RecoveryDisclosure } from '@/models/recovery'
import {
  Accumulation,
  Assumptions,
  ConfidenceAndCatalog,
  CurrentStorage,
  FigureValue,
  NotModelled,
  ObservationList,
  RecoveryOperations,
  ScenarioTable,
} from '@/features/recovery/costParts'
import { BulletList, needsCode, Notice, retentionChoiceLabel, SubHeading, timeText } from '@/features/recovery/shared'
import { sendRecoveryUpdate } from '@/features/recovery/update'

// What each acknowledgement says. Every code the daemon lists in required_acknowledgements gets its own checkbox;
// the disclosure itself is always acknowledged, and unpriced costs always need their own, separate one.
const ACK_TEXT: Record<string, string> = {
  [RECOVERY_CODES.versioningDisclosure]:
    'I have read this disclosure. Versioning adds recurring storage charges billed by the provider, and these figures are estimates, not a provider invoice.',
  [RECOVERY_CODES.versioningUnpriced]:
    'I accept recurring charges for retained versions that Vaulthalla cannot estimate for this bucket.',
  [RECOVERY_CODES.bucketAdoption]:
    'Vaulthalla may adopt this bucket and manage its versioning and its own lifecycle rule.',
  [RECOVERY_CODES.retentionShorten]: 'I understand the shorter retention permanently deletes older versions sooner.',
}

const FALLBACK_CONSEQUENCES = [
  'On AWS S3, versioning can’t be turned off again once enabled; it can only be suspended. Versions already kept stay until retention or a person removes them.',
  'AWS can take up to 15 minutes before versioning applies to every write.',
  'Retention permanently deletes versions once they are older than the chosen period.',
]

const requiredAcks = (d: RecoveryDisclosure) => {
  const codes = [RECOVERY_CODES.versioningDisclosure as string]
  for (const c of d.required_acknowledgements) if (!codes.includes(c)) codes.push(c)
  if (!d.report.priced && !codes.includes(RECOVERY_CODES.versioningUnpriced))
    codes.push(RECOVERY_CODES.versioningUnpriced)
  return codes
}

// The cost disclosure (lazy): shown before provider versioning can be enabled. Nothing here can be skipped: the enable
// button stays off until every acknowledgement is ticked, and the update carries the disclosure's token.
const DisclosureDialog = ({
  vaultId,
  retention,
  onClose,
  onEnabled,
}: {
  vaultId: number
  retention: string
  onClose: () => void
  onEnabled?: () => void
}) => {
  const ids = useId()
  const query = useWs(
    'vault.recovery.disclosure',
    { vault_id: vaultId, provider_retention: retention },
    { retry: false, staleTime: 0, gcTime: 0, select: d => d.disclosure },
  )
  const disclosure = query.data ?? null
  const [acks, setAcks] = useState<Record<string, boolean>>({})
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const [refreshed, setRefreshed] = useState(false)

  // A new disclosure (new token) needs fresh acknowledgements.
  const token = disclosure?.token
  useEffect(() => setAcks({}), [token])

  const codes = disclosure ? requiredAcks(disclosure) : []
  const allAcked = codes.length > 0 && codes.every(c => acks[c])

  const refetch = async () => {
    setRefreshed(true)
    await query.refetch()
  }

  const enable = async () => {
    if (!disclosure) return
    setError(null)
    if (disclosure.expires_at && Date.parse(disclosure.expires_at) < Date.now()) {
      await refetch()
      return
    }
    setBusy(true)
    try {
      await sendRecoveryUpdate(vaultId, {
        mode: 'provider_versioning',
        provider_retention: retention,
        disclosure_token: disclosure.token,
        ...(acks[RECOVERY_CODES.versioningUnpriced] ? { accept_unpriced: true } : {}),
        ...(acks[RECOVERY_CODES.bucketAdoption] ? { accept_adoption: true } : {}),
        ...(acks[RECOVERY_CODES.retentionShorten] ? { accept_retention_shortening: true } : {}),
      })
      notify.success('Provider versioning enabled', 'It can take up to 15 minutes to apply to every write.')
      onEnabled?.()
      onClose()
    } catch (e) {
      if (needsCode(e, RECOVERY_CODES.versioningDisclosure) || needsCode(e, RECOVERY_CODES.versioningUnpriced))
        await refetch()
      else setError(e)
    } finally {
      setBusy(false)
    }
  }

  const report = disclosure?.report ?? null
  const headline =
    report ?
      report.phase === 'active' ?
        report.projected_monthly
      : report.pre_activation_monthly
    : null

  return (
    <Dialog open onOpenChange={o => !o && !busy && onClose()}>
      <DialogContent
        size="xl"
        title="Provider Versioning — Estimated Monthly Cost"
        description="Read this before turning versioning on. The provider bills for every version it keeps, not Vaulthalla."
        data-testid="recovery-disclosure"
        footer={
          <>
            <Button variant="ghost" onClick={onClose} disabled={busy}>
              Cancel
            </Button>
            <Button
              variant="primary"
              disabled={!disclosure || !allAcked || query.isFetching}
              loading={busy}
              onClick={() => void enable()}
              data-testid="disclosure-enable">
              Enable provider versioning
            </Button>
          </>
        }>
        {query.isPending ?
          <div className="flex justify-center py-12">
            <Spinner className="size-6" label="Estimating costs" />
          </div>
        : query.error || !disclosure || !report ?
          <div className="space-y-3">
            <InlineError error={query.error ?? new Error('The disclosure is not available.')} />
            <Button onClick={() => void query.refetch()}>Try again</Button>
          </div>
        : <div className="space-y-6">
            {refreshed ?
              <Notice tone="info" role="status">
                The disclosure expired or its figures changed, so it was fetched again. Review it and acknowledge again.
              </Notice>
            : null}

            {!report.priced ?
              <Notice
                tone="danger"
                icon={TriangleExclamationIcon}
                title="Costs cannot be estimated"
                role="alert"
                testId="disclosure-unpriced">
                <p>{report.unpriced_reason ?? 'No price catalog entry applies to this bucket.'}</p>
                <p className="mt-1">The provider will still bill for every version it keeps.</p>
              </Notice>
            : null}

            <section className="grid gap-4 md:grid-cols-2">
              <div className="rounded-control border-line bg-surface-1 border px-4 py-3">
                <SubHeading>Estimated additional storage per month</SubHeading>
                <FigureValue figure={headline} large testId="disclosure-headline" />
                <p className="text-fg-subtle mt-2 text-xs">
                  The versioning surcharge only: storage for replaced and deleted versions kept by the provider, with
                  retention {retentionChoiceLabel(retention).toLowerCase()}.
                </p>
              </div>
              <DefinitionList
                items={[
                  ['Provider', report.provider ?? DASH],
                  [
                    'Bucket',
                    <span key="b" className="font-mono text-xs">
                      {report.bucket ?? DASH}
                    </span>,
                  ],
                  ['Region', report.region ?? DASH],
                  ['Storage class', report.storage_class ?? DASH],
                  ['Retention', retentionChoiceLabel(retention)],
                  ['Valid until', timeText(disclosure.expires_at)],
                ]}
              />
            </section>

            <section>
              <SubHeading>Your data and write traffic (measured)</SubHeading>
              <div className="space-y-3">
                <CurrentStorage report={report} />
                <ObservationList report={report} />
              </div>
            </section>

            <section>
              <SubHeading>What the estimate assumes</SubHeading>
              <Assumptions report={report} />
            </section>

            <section>
              <SubHeading>Projected version history over 12 months</SubHeading>
              <Accumulation points={report.accumulation} />
            </section>

            <section>
              <SubHeading>Retention scenarios</SubHeading>
              <ScenarioTable scenarios={report.scenarios} chosen={retention} />
            </section>

            <section>
              <SubHeading>Confidence</SubHeading>
              <ConfidenceAndCatalog report={report} />
            </section>

            <section>
              <SubHeading>Recovery operations (charged when you restore)</SubHeading>
              <RecoveryOperations report={report} />
            </section>

            <section>
              <SubHeading>Not included in these estimates</SubHeading>
              <NotModelled report={report} />
            </section>

            <section>
              <SubHeading>What enabling does</SubHeading>
              <BulletList
                items={disclosure.consequences.length ? disclosure.consequences : FALLBACK_CONSEQUENCES}
                className="text-fg-muted"
              />
            </section>

            <section
              className="rounded-control border-accent-line bg-accent-soft space-y-2.5 border px-4 py-3"
              data-testid="disclosure-acks">
              <SubHeading className="mb-1">Acknowledge to continue</SubHeading>
              {codes.map(code => (
                <label key={code} htmlFor={`${ids}-${code}`} className="text-fg flex items-start gap-2.5 text-sm">
                  <Checkbox
                    id={`${ids}-${code}`}
                    className="mt-0.5"
                    checked={Boolean(acks[code])}
                    onCheckedChange={v => setAcks(a => ({ ...a, [code]: v }))}
                    data-testid={`disclosure-ack-${code}`}
                  />
                  <span>{ACK_TEXT[code] ?? `I acknowledge: ${code}`}</span>
                </label>
              ))}
            </section>

            <InlineError error={error} />
          </div>
        }
      </DialogContent>
    </Dialog>
  )
}

export default DisclosureDialog
