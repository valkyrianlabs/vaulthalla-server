'use client'

import React, { useEffect, useId } from 'react'
import Link from 'next/link'
import { useRouter, useSearchParams } from 'next/navigation'
import { FormProvider, useForm, useWatch } from 'react-hook-form'
import { PageHeader, Panel } from '@/components/ui/Panel'
import { Button } from '@/components/ui/Button'
import { Field, Input, Select, Textarea } from '@/components/ui/Field'
import { SwitchRow } from '@/components/ui/Choice'
import { EmptyState, InlineError } from '@/components/ui/State'
import { notify } from '@/components/ui/Toast'
import { CloudIcon, HardDriveIcon, KeySkeletonIcon } from '@/components/ui/icons'
import { api, useSession } from '@/lib/session'
import { invalidate } from '@/lib/query'
import { useCan, useIsAdmin } from '@/lib/permissions'
import { cn } from '@/util/cn'
import { useCredentials, useUserNames, VAULT_CREATE } from '@/features/vaults/hooks'
import type { VaultType } from '@/features/vaults/model'
import { syncFormDefaults, syncPayload, type SyncFormValues } from '@/features/vaults/syncPolicy'
import { RequestGuardrailFields, SyncPolicyFields } from '@/features/vaults/sync/SyncPolicyFields'
import { QuotaInput, quotaBytes, SLUG_PATTERN, storageTierOptions, validateFuseName, type QuotaUnit } from '@/features/vaults/fields'
import { withEncryptionWaiver } from '@/features/vaults/waiver'
import { useServerPolicy } from '@/lib/serverPolicy'
import { useUpstreamPerms, withConfirmation } from '@/features/credentials/upstream/hooks'
import {
  AdoptBucketFields,
  BucketModeSelector,
  CreateBucketFields,
  provisionDefaults,
  provisionPayload,
} from '@/features/vaults/BucketProvisionFields'
import { UPSTREAM_CODES, type BucketMode } from '@/models/upstream'

interface NewVaultValues {
  type: VaultType
  name: string
  description: string
  owner_id: string
  quota_amount: string
  quota_unit: QuotaUnit
  slug: string
  fuse_name: string
  api_key_id: string
  bucket: string
  storage_tier_id: string
  encrypt_upstream: boolean
  sync: SyncFormValues
  // #237 bucket provisioning (admin-enabled credentials only); 'existing' = bind the named bucket as before.
  bucket_mode: BucketMode
  generate_name: boolean
  region: string
  abort_multipart_days: string
  events: boolean
  events_prefix: string
  adoption_reviewed: boolean
}

const BUCKET_MODES: BucketMode[] = ['existing', 'create', 'adopt']

export const NewVaultPage = () => {
  const canCreate = useCan(VAULT_CREATE)
  if (!canCreate)
    return (
      <>
        <PageHeader title="New vault" />
        <div className="panel">
          <EmptyState title="You can’t create vaults" description="Your role doesn’t include a vault create permission. Ask an administrator." />
        </div>
      </>
    )
  return <NewVaultForm />
}

const TYPE_CHOICES: { value: VaultType; title: string; text: string; icon: React.ComponentType<React.SVGProps<SVGSVGElement>> }[] = [
  { value: 'local', title: 'Local disk', text: 'Files live on this server, encrypted at rest.', icon: HardDriveIcon },
  { value: 's3', title: 'S3 bucket', text: 'Files live in an S3 or R2 bucket, with an encrypted local cache.', icon: CloudIcon },
]

const NewVaultForm = () => {
  const router = useRouter()
  const ids = useId()
  const isAdmin = useIsAdmin()
  const me = useSession(state => state.user)
  const credentials = useCredentials()
  const { users } = useUserNames()
  const upstream = useUpstreamPerms()
  // Deep links from the bucket inventory: /vaults/new?type=s3&api_key_id=…&bucket=…&bucket_mode=adopt
  const params = useSearchParams()
  const linkedMode = BUCKET_MODES.find(m => m === params?.get('bucket_mode'))
  const linkedKey = params?.get('api_key_id') ?? ''

  const form = useForm<NewVaultValues>({
    defaultValues: {
      type: params?.get('type') === 's3' ? 's3' : 'local',
      name: '',
      description: '',
      owner_id: '',
      quota_amount: '',
      quota_unit: 'GiB',
      slug: '',
      fuse_name: '',
      api_key_id: /^\d+$/.test(linkedKey) ? linkedKey : '',
      bucket: params?.get('bucket') ?? '',
      storage_tier_id: '',
      encrypt_upstream: true,
      sync: syncFormDefaults(null),
      bucket_mode: linkedMode ?? 'existing',
      ...provisionDefaults,
    },
  })
  const { register, handleSubmit, control, setValue, formState, getFieldState, resetField } = form
  const errors = formState.errors
  const type = useWatch({ control, name: 'type' })
  const apiKeyId = useWatch({ control, name: 'api_key_id' })
  const encrypt = useWatch({ control, name: 'encrypt_upstream' })
  const credential = credentials.data?.find(c => String(c.api_key_id) === apiKeyId)
  const tiers = storageTierOptions(credential?.provider)
  const bucketMode = useWatch({ control, name: 'bucket_mode' })
  // Creating or adopting needs a credential with provider administration and admin.upstream.provision; anything else
  // binds a bucket by name as before.
  const canProvision = Boolean(credential?.admin_enabled) && upstream.provision
  const mode: BucketMode = canProvision ? bucketMode : 'existing'

  // An admin-enabled credential starts in "create a new bucket", unless a link or the user already chose a mode.
  useEffect(() => {
    if (!canProvision || linkedMode || getFieldState('bucket_mode').isDirty) return
    setValue('bucket_mode', 'create')
  }, [canProvision, linkedMode, getFieldState, setValue])

  // New S3 vaults start from the operator's defaults (config vaults.s3.*), unless the user already chose.
  const remoteDefaults = useServerPolicy().data?.policy?.vaults?.s3
  useEffect(() => {
    if (!remoteDefaults) return
    if (!getFieldState('sync.strategy').isDirty)
      resetField('sync.strategy', { defaultValue: remoteDefaults.default_remote_sync_strategy })
    if (!getFieldState('sync.conflict_policy').isDirty)
      resetField('sync.conflict_policy', { defaultValue: remoteDefaults.default_remote_conflict_policy })
  }, [remoteDefaults, getFieldState, resetField])

  // A single credential is the obvious choice.
  useEffect(() => {
    if (type === 's3' && !apiKeyId && credentials.data?.length === 1) setValue('api_key_id', String(credentials.data[0].api_key_id))
  }, [type, apiKeyId, credentials.data, setValue])

  const [submitError, setSubmitError] = React.useState<unknown>(null)

  const onSubmit = async (values: NewVaultValues) => {
    setSubmitError(null)
    const common = {
      name: values.name.trim(),
      ...(values.description.trim() ? { description: values.description.trim() } : {}),
      ...(quotaBytes(values) > 0 ? { quota: quotaBytes(values) } : {}),
      ...(values.owner_id ? { owner_id: Number(values.owner_id) } : {}),
      ...(values.slug.trim() ? { slug: values.slug.trim() } : {}),
      ...(values.fuse_name.trim() ? { fuse_name: values.fuse_name.trim() } : {}),
    }
    try {
      const effective = { ...values, bucket_mode: mode }
      const sendS3 = (adopted: boolean) =>
        withEncryptionWaiver(accept => {
          const provision = provisionPayload(effective, adopted)
          return api.send('storage.vault.add', {
            ...common,
            type: 's3',
            api_key_id: Number(values.api_key_id),
            bucket: mode === 'create' && values.generate_name ? '' : values.bucket.trim(),
            storage_tier_id: values.storage_tier_id || null,
            encrypt_upstream: values.encrypt_upstream,
            sync: syncPayload(values.sync),
            ...(accept ? { accept_encryption_waiver: true } : {}),
            ...(provision ? { provision } : {}),
          })
        })
      const res =
        values.type === 'local'
          ? await api.send('storage.vault.add', { ...common, type: 'local' })
          : mode === 'adopt'
            ? await withConfirmation(UPSTREAM_CODES.adoption, sendS3, message => ({
                title: 'Adopt this bucket?',
                description: message,
                confirmLabel: 'Adopt and create the vault',
                tone: 'primary',
              }))
            : await sendS3(false)
      await invalidate('storage.vault.list', 'stats.system.storage')
      notify.success(`Vault “${common.name}” created`)
      const id = (res.vault as { id?: number } | undefined)?.id
      router.push(id ? `/vaults/${id}` : '/vaults')
    } catch (error) {
      setSubmitError(error)
    }
  }

  return (
    <FormProvider {...form}>
      <PageHeader eyebrow={<Link href="/vaults" className="hover:text-accent-text">Vaults</Link>} title="New vault" description="Pick where the files live, then name it. Everything except the storage type can be changed later." />
      <form onSubmit={handleSubmit(onSubmit)} className="max-w-3xl space-y-4" noValidate>
        <Panel title="Storage">
          <div role="radiogroup" aria-label="Vault type" className="grid gap-3 sm:grid-cols-2">
            {TYPE_CHOICES.map(choice => {
              const active = type === choice.value
              return (
                <button
                  key={choice.value}
                  type="button"
                  role="radio"
                  aria-checked={active}
                  onClick={() => setValue('type', choice.value)}
                  className={cn(
                    'flex items-start gap-3 rounded-card border border-line bg-surface-1 p-4 text-left transition-colors hover:border-line-strong',
                    active && 'border-accent-line bg-accent-soft',
                  )}>
                  <span className={cn('grid size-9 shrink-0 place-items-center rounded-control border border-line bg-surface-2 [&_svg]:size-4', active ? 'text-accent-text' : 'text-fg-subtle')}>
                    <choice.icon aria-hidden />
                  </span>
                  <span>
                    <span className={cn('block text-sm font-medium', active ? 'text-accent-text' : 'text-fg')}>{choice.title}</span>
                    <span className="mt-0.5 block text-xs text-fg-subtle">{choice.text}</span>
                  </span>
                </button>
              )
            })}
          </div>

          {type === 's3' ? (
            <div className="mt-5 space-y-4">
              {credentials.isPending && credentials.fetchStatus !== 'idle' ? null : !credentials.data?.length ? (
                <div className="flex flex-wrap items-center gap-3 rounded-card border border-line bg-surface-1 px-4 py-3">
                  <KeySkeletonIcon className="size-4 text-fg-subtle" aria-hidden />
                  <p className="min-w-0 flex-1 text-sm text-fg-muted">An S3 vault needs a provider credential (endpoint and access key) first.</p>
                  <Button asChild size="sm" variant="subtle">
                    <Link href="/credentials">Add a credential</Link>
                  </Button>
                </div>
              ) : null}
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Provider credential" htmlFor={`${ids}-key`} required error={errors.api_key_id?.message}>
                  <Select id={`${ids}-key`} aria-invalid={Boolean(errors.api_key_id)} {...register('api_key_id', { validate: v => type !== 's3' || Boolean(v) || 'Choose a credential' })}>
                    <option value="">Choose…</option>
                    {(credentials.data ?? []).map(c => (
                      <option key={c.api_key_id} value={c.api_key_id}>
                        {c.name}
                        {c.provider ? ` · ${c.provider}` : ''}
                      </option>
                    ))}
                  </Select>
                </Field>
                {mode === 'existing' ? (
                  <Field label="Bucket" htmlFor={`${ids}-bucket`} required error={errors.bucket?.message}>
                    <Input id={`${ids}-bucket`} className="font-mono" autoComplete="off" spellCheck={false} aria-invalid={Boolean(errors.bucket)} {...register('bucket', { validate: (v, all) => all.type !== 's3' || (canProvision && all.bucket_mode !== 'existing') || Boolean(v.trim()) || 'Enter the bucket name' })} />
                  </Field>
                ) : null}
                <Field label="Storage tier" htmlFor={`${ids}-tier`} hint={tiers ? undefined : credential ? 'This provider uses its default tier.' : 'Leave empty for the provider default.'}>
                  {tiers ? (
                    <Select id={`${ids}-tier`} {...register('storage_tier_id')}>
                      {tiers.map(t => (
                        <option key={t.value || 'default'} value={t.value}>
                          {t.label}
                        </option>
                      ))}
                    </Select>
                  ) : (
                    <Input id={`${ids}-tier`} placeholder="Provider default" disabled={Boolean(credential)} {...register('storage_tier_id')} />
                  )}
                </Field>
              </div>
              {canProvision ? (
                <div className="space-y-4 rounded-card border border-line p-4">
                  <BucketModeSelector value={mode} onChange={m => setValue('bucket_mode', m, { shouldDirty: true })} canProvision={canProvision} />
                  {mode === 'create' ? <CreateBucketFields regionHint={credential?.region} /> : null}
                  {mode === 'adopt' ? <AdoptBucketFields apiKeyId={Number(apiKeyId)} /> : null}
                  {mode === 'existing' ? (
                    <p className="text-xs text-fg-subtle">Binds a bucket by name without any provider administration, as for any other credential.</p>
                  ) : null}
                </div>
              ) : null}
              <SwitchRow
                id={`${ids}-encrypt`}
                label="Encrypt objects before upload"
                hint={encrypt ? 'The bucket only ever sees ciphertext. Recommended.' : 'Objects are stored in the bucket as plain files.'}
                checked={encrypt}
                onCheckedChange={value => setValue('encrypt_upstream', value)}
              />
            </div>
          ) : null}
        </Panel>

        <Panel title="Details">
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Name" htmlFor={`${ids}-name`} required error={errors.name?.message} className="sm:col-span-2">
              <Input id={`${ids}-name`} autoFocus autoComplete="off" aria-invalid={Boolean(errors.name)} {...register('name', { validate: v => Boolean(v.trim()) || 'Give the vault a name' })} />
            </Field>
            <Field label="Description" htmlFor={`${ids}-description`} className="sm:col-span-2">
              <Textarea id={`${ids}-description`} rows={2} {...register('description')} />
            </Field>
            <Field label="Quota" htmlFor={`${ids}-quota`} hint="Empty means no quota." error={errors.quota_amount?.message}>
              <QuotaInput id={`${ids}-quota`} />
            </Field>
            {isAdmin && users.length ? (
              <Field label="Owner" htmlFor={`${ids}-owner`} hint="Defaults to you.">
                <Select id={`${ids}-owner`} {...register('owner_id')}>
                  <option value="">{me ? `${me.name} (you)` : 'You'}</option>
                  {users
                    .filter(u => u.id !== me?.id)
                    .map(u => (
                      <option key={u.id} value={u.id}>
                        {u.name}
                      </option>
                    ))}
                </Select>
              </Field>
            ) : null}
          </div>
          <details className="group mt-5 rounded-card border border-line">
            <summary className="cursor-pointer list-none px-4 py-2.5 text-sm text-fg-muted select-none hover:text-fg">
              <span className="mr-1.5 inline-block transition-transform group-open:rotate-90">›</span>
              Names on disk and over S3
            </summary>
            <div className="grid gap-4 border-t border-line px-4 py-4 sm:grid-cols-2">
              <Field label="Slug" htmlFor={`${ids}-slug`} hint="3–63 lowercase letters, digits or hyphens. Derived from the name when empty." error={errors.slug?.message}>
                <Input id={`${ids}-slug`} className="font-mono" placeholder="my-photos" spellCheck={false} {...register('slug', { validate: v => !v.trim() || SLUG_PATTERN.test(v.trim()) || 'Use 3–63 lowercase letters, digits or hyphens' })} />
              </Field>
              <Field label="FUSE folder name" htmlFor={`${ids}-fuse`} hint="The folder under the FUSE mount. Defaults to the slug." error={errors.fuse_name?.message}>
                <Input id={`${ids}-fuse`} className="font-mono" placeholder="(slug)" spellCheck={false} {...register('fuse_name', { validate: validateFuseName })} />
              </Field>
            </div>
          </details>
        </Panel>

        {type === 's3' ? (
          <>
            <Panel title="Sync" description="How the vault and the bucket stay in step.">
              <SyncPolicyFields />
            </Panel>
            <Panel title="Request guardrails" description="Per-run S3 request limits that keep a sync from running up the bill.">
              <RequestGuardrailFields />
            </Panel>
          </>
        ) : null}

        <InlineError error={submitError} />
        <div className="flex justify-end gap-2 pt-1 pb-8">
          <Button asChild variant="ghost">
            <Link href="/vaults">Cancel</Link>
          </Button>
          <Button type="submit" variant="primary" loading={formState.isSubmitting}>
            Create vault
          </Button>
        </div>
      </form>
    </FormProvider>
  )
}
