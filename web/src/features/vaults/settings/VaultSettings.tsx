'use client'

import React, { useEffect, useId, useMemo } from 'react'
import dynamic from 'next/dynamic'
import { useRouter } from 'next/navigation'
import { FormProvider, useForm, useWatch } from 'react-hook-form'
import { api } from '@/lib/session'
import { invalidate } from '@/lib/query'
import { useCan, useIsAdmin } from '@/lib/permissions'
import { Panel } from '@/components/ui/Panel'
import { Button } from '@/components/ui/Button'
import { Field, Input, Select, Textarea } from '@/components/ui/Field'
import { SwitchRow } from '@/components/ui/Choice'
import { confirm } from '@/components/ui/Confirm'
import { InlineError } from '@/components/ui/State'
import { notify } from '@/components/ui/Toast'
import { TrashIcon } from '@/components/ui/icons'
import { useCurrentVault } from '@/features/vaults/VaultShell'
import { useCredentials, useUserNames, VAULT_EDIT, VAULT_REMOVE } from '@/features/vaults/hooks'
import { vaultTypeLabel, type VaultDetail } from '@/features/vaults/model'
import { QuotaInput, quotaBytes, quotaDefaults, SLUG_PATTERN, storageTierOptions, validateFuseName, type QuotaUnit } from '@/features/vaults/fields'
import { withEncryptionWaiver } from '@/features/vaults/waiver'

const DeleteVaultDialog = dynamic(() => import('@/features/vaults/DeleteVaultDialog'), { ssr: false })
const EventSyncPanel = dynamic(() => import('@/features/vaults/settings/EventSyncPanel'), { ssr: false })

export const VaultSettings = () => {
  const vault = useCurrentVault()
  return (
    <div className="max-w-3xl space-y-4">
      <GeneralForm vault={vault} />
      {vault.type === 's3' ? <BucketForm vault={vault} /> : null}
      {vault.type === 's3' ? <EventSyncPanel vault={vault} /> : null}
      <DangerZone vault={vault} />
    </div>
  )
}

// Saves refresh the vault everywhere it is shown (header, list, file browser vault switcher).
const refreshVault = () => invalidate('storage.vault.get', 'storage.vault.list', 'stats.system.storage', 'stats.vault.storage')

interface GeneralValues {
  name: string
  description: string
  owner_id: string
  quota_amount: string
  quota_unit: QuotaUnit
  slug: string
  fuse_name: string
  is_active: boolean
}

const generalDefaults = (vault: VaultDetail): GeneralValues => ({
  name: vault.name,
  description: vault.description ?? '',
  owner_id: String(vault.owner_id || ''),
  ...quotaDefaults(vault.quota),
  slug: vault.slug ?? '',
  fuse_name: vault.fuse_name ?? '',
  is_active: vault.is_active,
})

const GeneralForm = ({ vault }: { vault: VaultDetail }) => {
  const ids = useId()
  const canEdit = useCan(VAULT_EDIT)
  // Ownership transfer is for administrators; the server refuses it for anyone else.
  const isAdmin = useIsAdmin()
  const { users, names } = useUserNames()
  const defaults = useMemo(() => generalDefaults(vault), [vault])
  const form = useForm<GeneralValues>({ defaultValues: defaults })
  const { register, handleSubmit, reset, formState, setValue, control } = form
  const errors = formState.errors
  const active = useWatch({ control, name: 'is_active' })
  const [error, setError] = React.useState<unknown>(null)

  useEffect(() => {
    if (!formState.isDirty) reset(defaults)
  }, [defaults, formState.isDirty, reset])

  const onSubmit = async (values: GeneralValues) => {
    setError(null)
    const dirty = formState.dirtyFields
    // Only what changed: the update is a patch, and an unchanged owner must not trip the admin-only transfer check.
    const payload: Parameters<typeof api.send<'storage.vault.update'>>[1] = { id: vault.id }
    if (dirty.name) payload.name = values.name.trim()
    if (dirty.description) payload.description = values.description.trim()
    if (dirty.quota_amount || dirty.quota_unit) payload.quota = quotaBytes(values)
    if (dirty.owner_id && values.owner_id) payload.owner_id = Number(values.owner_id)
    if (dirty.slug) payload.slug = values.slug.trim()
    if (dirty.fuse_name) payload.fuse_name = values.fuse_name.trim() || null
    if (dirty.is_active) payload.is_active = values.is_active
    if (dirty.owner_id && values.owner_id) {
      const ok = await confirm({
        title: 'Transfer ownership?',
        description: `${names.get(Number(values.owner_id)) ?? 'The new owner'} becomes the owner of “${vault.name}”.`,
        confirmLabel: 'Transfer',
        tone: 'primary',
      })
      if (!ok) return
    }
    try {
      await api.send('storage.vault.update', payload)
      await refreshVault()
      reset(values)
      notify.success('Vault settings saved')
    } catch (e) {
      setError(e)
    }
  }

  const ownerOptions = useMemo(() => {
    const list = users.map(u => ({ id: u.id, name: u.name }))
    if (vault.owner_id && !list.some(u => u.id === vault.owner_id)) list.unshift({ id: vault.owner_id, name: vault.owner || `User #${vault.owner_id}` })
    return list
  }, [users, vault.owner_id, vault.owner])

  return (
    <FormProvider {...form}>
      <form onSubmit={handleSubmit(onSubmit)} noValidate>
        <Panel title="General" description={canEdit ? undefined : 'Your role can view these settings but not change them.'}>
          <fieldset disabled={!canEdit || formState.isSubmitting} className="grid gap-4 sm:grid-cols-2">
            <Field label="Name" htmlFor={`${ids}-name`} required error={errors.name?.message} className="sm:col-span-2">
              <Input id={`${ids}-name`} aria-invalid={Boolean(errors.name)} {...register('name', { validate: v => Boolean(v.trim()) || 'A vault needs a name' })} />
            </Field>
            <Field label="Description" htmlFor={`${ids}-description`} className="sm:col-span-2">
              <Textarea id={`${ids}-description`} rows={2} {...register('description')} />
            </Field>
            <Field label="Quota" htmlFor={`${ids}-quota`} hint="Empty means no quota." error={errors.quota_amount?.message}>
              <QuotaInput id={`${ids}-quota`} />
            </Field>
            <Field
              label="Owner"
              htmlFor={`${ids}-owner`}
              hint={isAdmin ? 'Transferring ownership is limited to administrators.' : 'Only administrators can transfer ownership.'}>
              {isAdmin && ownerOptions.length ? (
                <Select id={`${ids}-owner`} data-testid="vault-owner-select" {...register('owner_id')}>
                  {vault.owner_id ? null : <option value="">No owner</option>}
                  {ownerOptions.map(u => (
                    <option key={u.id} value={u.id}>
                      {u.name}
                    </option>
                  ))}
                </Select>
              ) : (
                <Input id={`${ids}-owner`} readOnly disabled value={vault.owner || names.get(vault.owner_id) || (vault.owner_id ? `User #${vault.owner_id}` : 'No owner')} />
              )}
            </Field>
            <Field label="Slug" htmlFor={`${ids}-slug`} hint="Used for S3 gateway and default folder names." error={errors.slug?.message}>
              <Input id={`${ids}-slug`} className="font-mono" spellCheck={false} {...register('slug', { validate: v => SLUG_PATTERN.test(v.trim()) || 'Use 3–63 lowercase letters, digits or hyphens' })} />
            </Field>
            <Field label="FUSE folder name" htmlFor={`${ids}-fuse`} hint={`The folder under the FUSE mount, now “${vault.effective_fuse_name || vault.slug}”. Empty = the slug.`} error={errors.fuse_name?.message}>
              <Input id={`${ids}-fuse`} className="font-mono" placeholder={vault.slug} spellCheck={false} {...register('fuse_name', { validate: validateFuseName })} />
            </Field>
            <div className="sm:col-span-2">
              <SwitchRow
                id={`${ids}-active`}
                label="Active"
                hint={active ? 'The vault is mounted and usable.' : 'An inactive vault is not mounted and refuses file access.'}
                checked={active}
                disabled={!canEdit}
                onCheckedChange={value => setValue('is_active', value, { shouldDirty: true })}
              />
            </div>
            <div className="grid gap-1 text-xs text-fg-subtle sm:col-span-2">
              <span>
                Storage type: <span className="text-fg-muted">{vaultTypeLabel(vault.type)}</span> — fixed when the vault was created.
              </span>
            </div>
          </fieldset>
          <InlineError error={error} className="mt-4" />
          {canEdit ? (
            <div className="mt-5 flex items-center justify-end gap-2">
              {formState.isDirty ? <span className="mr-auto text-xs text-fg-subtle">Unsaved changes</span> : null}
              <Button variant="ghost" disabled={!formState.isDirty || formState.isSubmitting} onClick={() => reset(defaults)}>
                Discard
              </Button>
              <Button type="submit" variant="primary" disabled={!formState.isDirty} loading={formState.isSubmitting}>
                Save changes
              </Button>
            </div>
          ) : null}
        </Panel>
      </form>
    </FormProvider>
  )
}

interface BucketValues {
  api_key_id: string
  bucket: string
  storage_tier_id: string
  encrypt_upstream: boolean
}

const BucketForm = ({ vault }: { vault: VaultDetail }) => {
  const ids = useId()
  const canEdit = useCan(VAULT_EDIT)
  const credentials = useCredentials()
  const defaults = useMemo<BucketValues>(
    () => ({
      api_key_id: vault.api_key_id ? String(vault.api_key_id) : '',
      bucket: vault.bucket ?? '',
      storage_tier_id: vault.storage_tier_id ?? '',
      encrypt_upstream: vault.encrypt_upstream ?? true,
    }),
    [vault],
  )
  const form = useForm<BucketValues>({ defaultValues: defaults })
  const { register, handleSubmit, reset, formState, control, setValue } = form
  const errors = formState.errors
  const apiKeyId = useWatch({ control, name: 'api_key_id' })
  const encrypt = useWatch({ control, name: 'encrypt_upstream' })
  const credential = credentials.data?.find(c => String(c.api_key_id) === apiKeyId)
  const tiers = storageTierOptions(credential?.provider)
  const [error, setError] = React.useState<unknown>(null)

  useEffect(() => {
    if (!formState.isDirty) reset(defaults)
  }, [defaults, formState.isDirty, reset])

  const onSubmit = async (values: BucketValues) => {
    setError(null)
    const dirty = formState.dirtyFields
    try {
      await withEncryptionWaiver(accept =>
        api.send('storage.vault.update', {
          id: vault.id,
          ...(dirty.api_key_id ? { api_key_id: Number(values.api_key_id) } : {}),
          ...(dirty.bucket ? { bucket: values.bucket.trim() } : {}),
          ...(dirty.storage_tier_id ? { storage_tier_id: values.storage_tier_id || null } : {}),
          ...(dirty.encrypt_upstream ? { encrypt_upstream: values.encrypt_upstream } : {}),
          ...(accept ? { accept_encryption_waiver: true } : {}),
        }),
      )
      await refreshVault()
      reset(values)
      notify.success('Bucket settings saved')
    } catch (e) {
      setError(e)
    }
  }

  const credentialMissing = vault.api_key_id && credentials.data && !credentials.data.some(c => c.api_key_id === vault.api_key_id)

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate>
      <Panel title="Bucket" description="Where this vault’s objects live. Changing these points the vault at different storage; existing objects don’t move.">
        <fieldset disabled={!canEdit || formState.isSubmitting} className="grid gap-4 sm:grid-cols-2">
          <Field label="Provider credential" htmlFor={`${ids}-key`} required error={errors.api_key_id?.message}>
            <Select id={`${ids}-key`} {...register('api_key_id', { validate: v => Boolean(v) || 'Choose a credential' })}>
              {credentialMissing || !credentials.data ? <option value={String(vault.api_key_id ?? '')}>Credential #{vault.api_key_id}</option> : null}
              {(credentials.data ?? []).map(c => (
                <option key={c.api_key_id} value={c.api_key_id}>
                  {c.name}
                  {c.provider ? ` · ${c.provider}` : ''}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Bucket" htmlFor={`${ids}-bucket`} required error={errors.bucket?.message}>
            <Input id={`${ids}-bucket`} className="font-mono" spellCheck={false} {...register('bucket', { validate: v => Boolean(v.trim()) || 'Enter the bucket name' })} />
          </Field>
          <Field label="Storage tier" htmlFor={`${ids}-tier`}>
            {tiers ? (
              <Select id={`${ids}-tier`} {...register('storage_tier_id')}>
                {tiers.map(t => (
                  <option key={t.value || 'default'} value={t.value}>
                    {t.label}
                  </option>
                ))}
              </Select>
            ) : (
              <Input id={`${ids}-tier`} placeholder="Provider default" {...register('storage_tier_id')} />
            )}
          </Field>
          <div className="sm:col-span-2">
            <SwitchRow
              id={`${ids}-encrypt`}
              label="Encrypt objects before upload"
              hint="Turning this on or off over a bucket that already holds objects asks you to accept a waiver first."
              checked={encrypt}
              disabled={!canEdit}
              onCheckedChange={value => setValue('encrypt_upstream', value, { shouldDirty: true })}
            />
          </div>
        </fieldset>
        <InlineError error={error} className="mt-4" />
        {canEdit ? (
          <div className="mt-5 flex items-center justify-end gap-2">
            <Button variant="ghost" disabled={!formState.isDirty || formState.isSubmitting} onClick={() => reset(defaults)}>
              Discard
            </Button>
            <Button type="submit" disabled={!formState.isDirty} loading={formState.isSubmitting}>
              Save bucket settings
            </Button>
          </div>
        ) : null}
      </Panel>
    </form>
  )
}

// Deleting is a schedule (#162): the vault disappears at once, stays restorable for the retention window, then is
// purged. The dialog (lazy) asks about upstream data and an unexported key, and offers "delete now".
const DangerZone = ({ vault }: { vault: VaultDetail }) => {
  const router = useRouter()
  const canRemove = useCan(VAULT_REMOVE)
  const [open, setOpen] = React.useState(false)
  if (!canRemove) return null

  return (
    <section className="panel border-danger-line/60">
      <div className="flex flex-wrap items-center justify-between gap-4 px-5 py-4">
        <div className="min-w-0">
          <h2 className="text-[15px] font-semibold text-danger">Delete this vault</h2>
          <p className="mt-0.5 text-sm text-fg-subtle">
            It disappears at once and can be restored for a while; then its data is purged. Its encryption key is kept longer.
          </p>
        </div>
        <Button variant="danger" onClick={() => setOpen(true)} data-testid="vault-delete-open">
          <TrashIcon aria-hidden />
          Delete vault
        </Button>
      </div>
      {open ?
        <DeleteVaultDialog vault={vault} open={open} onOpenChange={setOpen} onDeleted={() => router.push('/vaults')} />
      : null}
    </section>
  )
}
