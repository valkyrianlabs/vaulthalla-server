'use client'

import React, { useState } from 'react'
import Link from 'next/link'
import dynamic from 'next/dynamic'
import { useRouter } from 'next/navigation'
import { useForm, useWatch } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { api } from '@/lib/session'
import { invalidate } from '@/lib/query'
import { DASH, formatDateTime } from '@/lib/format'
import { Button } from '@/components/ui/Button'
import { Field, Input, Select } from '@/components/ui/Field'
import { DefinitionList, PageHeader, Panel } from '@/components/ui/Panel'
import { InlineError, QueryState } from '@/components/ui/State'
import { notify } from '@/components/ui/Toast'
import { ArrowLeftIcon, EyeIcon, EyeSlashIcon, TrashIcon } from '@/components/ui/icons'
import { PROVIDERS, PROVIDER_HINTS, type ProviderCredential } from '@/features/credentials/types'
import {
  updateCredential,
  useCredential,
  useCredentialPerms,
  useCredentialUsage,
  type VaultRef,
} from '@/features/credentials/useCredentials'
import { deleteCredential } from '@/features/credentials/deleteCredential'

// Provider administration (#237): its own chunk, loaded with the credential.
const AdminPanel = dynamic(() => import('@/features/credentials/upstream/AdminPanel'), { ssr: false })

const schema = (editing: boolean) =>
  z.object({
    name: z.string().trim().min(1, 'Give the credential a name'),
    provider: z.string().min(1, 'Pick a provider'),
    endpoint: z
      .string()
      .trim()
      .min(1, 'The endpoint URL is required')
      .refine(value => /^https?:\/\/\S+$/i.test(value), 'Use a full URL, e.g. https://s3.us-east-1.amazonaws.com'),
    region: z.string().trim(),
    access_key: z.string().trim().min(1, 'The access key ID is required'),
    secret_access_key: editing ? z.string() : z.string().min(1, 'The secret access key is required'),
  })

type FormValues = z.infer<ReturnType<typeof schema>>

const BackLink = () => (
  <Button asChild variant="ghost" size="sm" className="mb-3 -ml-2">
    <Link href="/credentials">
      <ArrowLeftIcon aria-hidden />
      Provider credentials
    </Link>
  </Button>
)

const CredentialFields = ({
  initial,
  usedBy,
  onDone,
}: {
  initial: ProviderCredential | null
  usedBy: VaultRef[] | null
  onDone: () => void
}) => {
  const editing = Boolean(initial)
  const can = useCredentialPerms()
  const readOnly = editing && !can.edit
  const [error, setError] = useState<unknown>(null)
  const [showSecret, setShowSecret] = useState(false)
  const {
    register,
    handleSubmit,
    control,
    formState: { errors, isSubmitting, isDirty },
  } = useForm<FormValues>({
    resolver: zodResolver(schema(editing)),
    defaultValues: {
      name: initial?.name ?? '',
      provider: initial?.provider ?? '',
      endpoint: initial?.endpoint ?? '',
      region: initial?.region ?? '',
      access_key: initial?.access_key ?? '',
      secret_access_key: '',
    },
  })
  const provider = useWatch({ control, name: 'provider' })
  const hint = PROVIDER_HINTS[provider]

  const submit = async (values: FormValues) => {
    setError(null)
    try {
      if (initial) {
        // Send only what changed: the daemon keeps everything left out, and an empty secret keeps the stored one.
        const payload: Parameters<typeof updateCredential>[0] = { id: initial.api_key_id }
        if (values.name.trim() !== initial.name) payload.name = values.name.trim()
        if (values.provider !== initial.provider) payload.provider = values.provider
        if (values.endpoint.trim() !== initial.endpoint) payload.endpoint = values.endpoint.trim()
        if (values.region.trim() !== initial.region) payload.region = values.region.trim()
        if (values.access_key.trim() !== initial.access_key) payload.access_key = values.access_key.trim()
        if (values.secret_access_key) payload.secret_access_key = values.secret_access_key
        if (Object.keys(payload).length === 1) {
          notify.info('Nothing to save', 'No field changed.')
          return
        }
        await updateCredential(payload)
        await invalidate('storage.apiKey.list', 'storage.apiKey.get')
        notify.success('Credential updated', values.name.trim())
      } else {
        await api.send('storage.apiKey.add', {
          name: values.name.trim(),
          provider: values.provider,
          endpoint: values.endpoint.trim(),
          region: values.region.trim() || 'auto',
          access_key: values.access_key.trim(),
          secret_access_key: values.secret_access_key,
        })
        await invalidate('storage.apiKey.list')
        notify.success('Credential added', values.name.trim())
      }
      onDone()
    } catch (err) {
      setError(err)
    }
  }

  return (
    <form onSubmit={handleSubmit(submit)} noValidate className="space-y-5">
      <fieldset disabled={readOnly || isSubmitting} className="min-w-0 space-y-5">
        <Panel
          title="Credential"
          description={editing ? 'Changes apply in place: vaults that use this credential keep working.' : undefined}>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Name" htmlFor="cred-name" error={errors.name?.message} required>
              <Input id="cred-name" autoComplete="off" aria-invalid={Boolean(errors.name)} {...register('name')} />
            </Field>
            <Field label="Provider" htmlFor="cred-provider" error={errors.provider?.message} required>
              <Select id="cred-provider" aria-invalid={Boolean(errors.provider)} {...register('provider')}>
                <option value="" disabled>
                  Choose a provider…
                </option>
                {PROVIDERS.map(p => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </Select>
            </Field>
            <Field
              label="Endpoint URL"
              htmlFor="cred-endpoint"
              error={errors.endpoint?.message}
              hint="The provider's S3 API endpoint, including https://"
              required
              className="sm:col-span-2">
              <Input
                id="cred-endpoint"
                inputMode="url"
                autoComplete="off"
                spellCheck={false}
                placeholder={hint?.endpoint ?? 'https://'}
                className="font-mono"
                aria-invalid={Boolean(errors.endpoint)}
                {...register('endpoint')}
              />
            </Field>
            <Field
              label="Region"
              htmlFor="cred-region"
              hint={editing ? undefined : 'Leave empty for “auto” (Cloudflare R2).'}>
              <Input
                id="cred-region"
                autoComplete="off"
                spellCheck={false}
                placeholder={hint?.region ?? 'auto'}
                className="font-mono"
                {...register('region')}
              />
            </Field>
          </div>
        </Panel>

        <Panel
          title="Access key"
          description={
            editing ?
              'The secret is never shown again after it is saved. Leave it empty to keep the stored secret.'
            : 'The server checks the key against the provider before saving it.'
          }>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Access key ID" htmlFor="cred-access" error={errors.access_key?.message} required>
              <Input
                id="cred-access"
                autoComplete="off"
                spellCheck={false}
                className="font-mono"
                aria-invalid={Boolean(errors.access_key)}
                {...register('access_key')}
              />
            </Field>
            <Field
              label={editing ? 'New secret access key' : 'Secret access key'}
              htmlFor="cred-secret"
              error={errors.secret_access_key?.message}
              hint={editing ? 'Only to rotate the secret.' : undefined}
              required={!editing}>
              <div className="relative">
                <Input
                  id="cred-secret"
                  type={showSecret ? 'text' : 'password'}
                  autoComplete="new-password"
                  spellCheck={false}
                  placeholder={editing ? 'Unchanged' : undefined}
                  className="pr-10 font-mono"
                  aria-invalid={Boolean(errors.secret_access_key)}
                  {...register('secret_access_key')}
                />
                <button
                  type="button"
                  onClick={() => setShowSecret(v => !v)}
                  aria-label={showSecret ? 'Hide secret' : 'Show secret'}
                  className="text-fg-subtle hover:text-fg absolute top-1/2 right-2 -translate-y-1/2 rounded p-1 [&_svg]:size-4">
                  {showSecret ?
                    <EyeSlashIcon aria-hidden />
                  : <EyeIcon aria-hidden />}
                </button>
              </div>
            </Field>
          </div>
        </Panel>
      </fieldset>

      {error ?
        <InlineError error={error} />
      : null}

      {readOnly ?
        <p className="text-fg-subtle text-sm">You can view this credential but not change it.</p>
      : <div className="flex flex-wrap items-center justify-end gap-2">
          <Button asChild variant="ghost">
            <Link href="/credentials">Cancel</Link>
          </Button>
          <Button type="submit" variant="primary" loading={isSubmitting} disabled={editing && !isDirty}>
            {isSubmitting ?
              editing ?
                'Saving…'
              : 'Checking with the provider…'
            : editing ?
              'Save changes'
            : 'Add credential'}
          </Button>
        </div>
      }

      {editing && initial ?
        <UsagePanel credential={initial} usedBy={usedBy} />
      : null}
    </form>
  )
}

const UsagePanel = ({ credential, usedBy }: { credential: ProviderCredential; usedBy: VaultRef[] | null }) => {
  const router = useRouter()
  const can = useCredentialPerms()
  return (
    <>
      <Panel title="Details">
        <DefinitionList
          items={[
            [
              'ID',
              <span key="id" className="tabular font-mono">
                {credential.api_key_id}
              </span>,
            ],
            [
              'Added',
              <span key="added" className="tabular">
                {formatDateTime(credential.created_at)}
              </span>,
            ],
            [
              'Used by',
              usedBy === null ?
                <span key="u" className="text-fg-faint">
                  {DASH}
                </span>
              : usedBy.length === 0 ?
                <span key="u" className="text-fg-subtle">
                  No vaults
                </span>
              : <span key="u" className="flex flex-wrap gap-x-3 gap-y-1">
                  {usedBy.map(vault => (
                    <Link key={vault.id} href={`/vaults/${vault.id}`} className="text-accent-text hover:underline">
                      {vault.name}
                    </Link>
                  ))}
                </span>,
            ],
          ]}
        />
      </Panel>
      {can.remove ?
        <Panel
          title="Delete credential"
          description="Destroys the stored key. Vaults that still use it must be moved or deleted first.">
          <Button
            variant="danger"
            onClick={async () => {
              if (await deleteCredential(credential, usedBy)) router.push('/credentials')
            }}>
            <TrashIcon aria-hidden />
            Delete credential
          </Button>
        </Panel>
      : null}
    </>
  )
}

export const NewCredentialPage = () => {
  const router = useRouter()
  const can = useCredentialPerms()
  return (
    <div className="mx-auto max-w-3xl">
      <BackLink />
      <PageHeader
        title="Add provider credential"
        description="An access key for your upstream S3-compatible storage account."
      />
      {can.create ?
        <CredentialFields initial={null} usedBy={null} onDone={() => router.push('/credentials')} />
      : <Panel>
          <p className="text-fg-subtle text-sm">You don&apos;t have permission to add provider credentials.</p>
        </Panel>
      }
    </div>
  )
}

export const EditCredentialPage = ({ id }: { id: number }) => {
  const router = useRouter()
  const credential = useCredential(id)
  const { usage } = useCredentialUsage()
  return (
    <div className="mx-auto max-w-3xl">
      <BackLink />
      <QueryState query={credential}>
        {data => (
          <>
            <PageHeader title={data.name || `Credential ${data.api_key_id}`} description={data.provider || undefined} />
            <CredentialFields
              key={data.api_key_id}
              initial={data}
              usedBy={usage ? (usage.get(data.api_key_id) ?? []) : null}
              onDone={() => router.push('/credentials')}
            />
            <div className="mt-5">
              <AdminPanel credential={data} />
            </div>
          </>
        )}
      </QueryState>
    </div>
  )
}
