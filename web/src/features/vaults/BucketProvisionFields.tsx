'use client'

import React, { useId, useState } from 'react'
import dynamic from 'next/dynamic'
import { useFormContext, useWatch } from 'react-hook-form'
import { api } from '@/lib/session'
import { useWs } from '@/lib/query'
import { Button } from '@/components/ui/Button'
import { Checkbox, SwitchRow } from '@/components/ui/Choice'
import { Field, Input, Select } from '@/components/ui/Field'
import { Segmented } from '@/components/ui/Tabs'
import { InlineError } from '@/components/ui/State'
import { isBound } from '@/features/credentials/upstream/hooks'
import type { AdmissionReport, BucketMode, Provision } from '@/models/upstream'

const AdmissionReportView = dynamic(() => import('@/features/credentials/upstream/AdmissionReportView'), { ssr: false })

// What the new-vault form adds for #237 (admin-enabled credentials). Lives in the form's values under these names.
export interface ProvisionFormValues {
  bucket_mode: BucketMode
  bucket: string
  generate_name: boolean
  region: string
  abort_multipart_days: string
  events: boolean
  events_prefix: string
  adoption_reviewed: boolean
  encrypt_upstream: boolean
}

// S3 bucket naming (the strict, cross-provider subset: AWS rules minus dotted names, which R2 also refuses).
export const BUCKET_NAME_PATTERN = /^(?!xn--)(?!.*-s3alias$)[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/

export const provisionDefaults = {
  generate_name: false,
  region: '',
  abort_multipart_days: '7',
  events: false,
  events_prefix: '',
  adoption_reviewed: false,
}

// The storage.vault.add `provision` object for the chosen mode (undefined = today's behaviour).
export const provisionPayload = (values: ProvisionFormValues, accepted: boolean): Provision | undefined => {
  if (values.bucket_mode === 'existing') return undefined
  const events =
    values.events ?
      { events: true, ...(values.events_prefix.trim() ? { events_prefix: values.events_prefix.trim() } : {}) }
    : {}
  if (values.bucket_mode === 'adopt')
    return { mode: 'adopt', ...events, ...(accepted || values.adoption_reviewed ? { accept_adoption: true } : {}) }
  const days = Number(values.abort_multipart_days.trim())
  return {
    mode: 'create',
    ...(values.generate_name ? { generate_name: true } : {}),
    ...(values.region.trim() ? { region: values.region.trim() } : {}),
    ...(values.abort_multipart_days.trim() && Number.isInteger(days) && days > 0 ?
      { lifecycle: { abort_incomplete_multipart_days: days } }
    : {}),
    ...events,
  }
}

export const BucketModeSelector = ({
  value,
  onChange,
  canProvision,
}: {
  value: BucketMode
  onChange: (m: BucketMode) => void
  canProvision: boolean
}) =>
  canProvision ?
    <Segmented<BucketMode>
      label="Bucket"
      value={value}
      onChange={onChange}
      options={[
        { value: 'create', label: 'Create a new bucket' },
        { value: 'adopt', label: 'Adopt an existing bucket' },
        { value: 'existing', label: 'Use a bucket name (manual)' },
      ]}
    />
  : null

export const CreateBucketFields = ({ regionHint }: { regionHint?: string }) => {
  const ids = useId()
  const { register, control, setValue, formState } = useFormContext<ProvisionFormValues>()
  const generate = useWatch({ control, name: 'generate_name' })
  const events = useWatch({ control, name: 'events' })
  return (
    <div className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2">
        <Field
          label="New bucket name"
          htmlFor={`${ids}-bucket`}
          required={!generate}
          error={formState.errors.bucket?.message}
          hint={
            generate ?
              'Vaulthalla picks an available name from the vault name.'
            : '3–63 lowercase letters, digits or hyphens. An existing bucket is never taken over: adopt it instead.'
          }>
          <Input
            id={`${ids}-bucket`}
            className="font-mono"
            autoComplete="off"
            spellCheck={false}
            disabled={generate}
            placeholder={generate ? '(generated)' : 'my-vault-bucket'}
            aria-invalid={Boolean(formState.errors.bucket)}
            {...register('bucket', {
              validate: (v, all) =>
                all.bucket_mode !== 'create'
                || all.generate_name
                || BUCKET_NAME_PATTERN.test(v.trim())
                || 'Use 3–63 lowercase letters, digits or hyphens',
            })}
          />
        </Field>
        <Field
          label="Region"
          htmlFor={`${ids}-region`}
          hint="Empty uses the credential’s region (R2: a location hint such as wnam).">
          <Input
            id={`${ids}-region`}
            className="font-mono"
            autoComplete="off"
            spellCheck={false}
            placeholder={regionHint || 'credential default'}
            {...register('region')}
          />
        </Field>
      </div>
      <label className="text-fg-muted flex items-center gap-2 text-sm">
        <Checkbox checked={generate} onCheckedChange={v => setValue('generate_name', v)} />
        Generate a bucket name
      </label>
      <details className="group rounded-card border-line border">
        <summary className="text-fg-muted hover:text-fg cursor-pointer list-none px-4 py-2.5 text-sm select-none">
          <span className="mr-1.5 inline-block transition-transform group-open:rotate-90">›</span>
          Bucket options
        </summary>
        <div className="border-line space-y-4 border-t px-4 py-4">
          <Field
            label="Abort incomplete uploads after (days)"
            htmlFor={`${ids}-abort`}
            hint="A Vaulthalla-owned lifecycle rule that frees storage held by abandoned multipart uploads. Empty for none."
            error={formState.errors.abort_multipart_days?.message}>
            <Input
              id={`${ids}-abort`}
              inputMode="numeric"
              className="tabular w-32"
              {...register('abort_multipart_days', {
                validate: v => !v.trim() || (/^\d+$/.test(v.trim()) && Number(v) <= 36500) || 'Whole days, up to 36500',
              })}
            />
          </Field>
          <EventsFields events={events} onEvents={v => setValue('events', v)} />
        </div>
      </details>
    </div>
  )
}

const EventsFields = ({ events, onEvents }: { events: boolean; onEvents: (v: boolean) => void }) => {
  const ids = useId()
  const { register } = useFormContext<ProvisionFormValues>()
  return (
    <>
      <SwitchRow
        id={`${ids}-events`}
        label="Event-driven sync"
        hint="The bucket notifies Vaulthalla of every upload and delete, so changes made directly in the bucket sync within seconds without listing it. AWS uses an SQS queue; R2 needs a Cloudflare API token on the credential."
        checked={events}
        onCheckedChange={onEvents}
      />
      {events ?
        <Field label="Only keys under this prefix" htmlFor={`${ids}-prefix`} hint="Empty watches the whole bucket.">
          <Input
            id={`${ids}-prefix`}
            className="font-mono"
            autoComplete="off"
            spellCheck={false}
            {...register('events_prefix')}
          />
        </Field>
      : null}
    </>
  )
}

export const AdoptBucketFields = ({ apiKeyId }: { apiKeyId: number }) => {
  const ids = useId()
  const { register, control, setValue, formState } = useFormContext<ProvisionFormValues>()
  const bucket = useWatch({ control, name: 'bucket' })
  const events = useWatch({ control, name: 'events' })
  const reviewed = useWatch({ control, name: 'adoption_reviewed' })
  const inventory = useWs(
    'upstream.bucket.list',
    { api_key_id: apiKeyId, max: 1000, state: 'unmanaged' },
    {
      enabled: apiKeyId > 0,
      retry: false,
      select: d => d.inventory.buckets.filter(b => !b.is_protected && !isBound(b.vault_id)),
    },
  )
  const [report, setReport] = useState<{ bucket: string; data: AdmissionReport } | null>(null)
  const [checking, setChecking] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const current = report && report.bucket === bucket ? report.data : null

  const check = async () => {
    setChecking(true)
    setError(null)
    setValue('adoption_reviewed', false)
    try {
      const res = await api.send('upstream.bucket.adopt.preflight', { api_key_id: apiKeyId, bucket })
      setReport({ bucket, data: res.report })
      if (typeof res.report.recommended_encrypt_upstream === 'boolean')
        setValue('encrypt_upstream', res.report.recommended_encrypt_upstream, { shouldDirty: true })
    } catch (e) {
      setError(e)
    } finally {
      setChecking(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end gap-3">
        <Field
          label="Existing bucket"
          htmlFor={`${ids}-bucket`}
          required
          className="min-w-64 flex-1"
          error={formState.errors.bucket?.message}
          hint={
            inventory.isError ?
              'Could not list the account’s buckets.'
            : 'Unmanaged, unprotected buckets that no vault uses.'
          }>
          <Select
            id={`${ids}-bucket`}
            className="font-mono"
            {...register('bucket', {
              validate: (v, all) => all.bucket_mode !== 'adopt' || Boolean(v) || 'Choose a bucket',
            })}>
            <option value="">{inventory.isPending ? 'Loading…' : 'Choose…'}</option>
            {/* A bucket named by a link (inventory → "Create a vault from this bucket") stays selectable; the daemon
                re-checks it at creation either way. */}
            {bucket && inventory.data && !inventory.data.some(b => b.name === bucket) ?
              <option value={bucket}>{bucket}</option>
            : null}
            {(inventory.data ?? []).map(b => (
              <option key={b.name} value={b.name}>
                {b.name}
                {b.region ? ` · ${b.region}` : ''}
              </option>
            ))}
          </Select>
        </Field>
        <Button onClick={check} loading={checking} disabled={!bucket}>
          Check bucket
        </Button>
      </div>
      <InlineError error={error} />
      {current ?
        <div className="rounded-card border-line bg-surface-1 border p-4">
          <AdmissionReportView report={current} />
          {current.blockers.length === 0 ?
            <label className="text-fg-muted mt-4 flex items-start gap-2 text-sm">
              <Checkbox className="mt-0.5" checked={reviewed} onCheckedChange={v => setValue('adoption_reviewed', v)} />
              I reviewed this report. Adopt the bucket into the new vault without changing what is in it.
            </label>
          : null}
        </div>
      : bucket ?
        <p className="text-fg-subtle text-xs">
          Check the bucket before creating the vault. Nothing is changed by the check.
        </p>
      : null}
      <EventsFields events={events} onEvents={v => setValue('events', v)} />
    </div>
  )
}
