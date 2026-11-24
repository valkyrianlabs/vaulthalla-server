'use client'

import React, { useState } from 'react'
import { api } from '@/lib/session'
import { Dialog, DialogContent } from '@/components/ui/Dialog'
import { Button } from '@/components/ui/Button'
import { Field, Input, Select } from '@/components/ui/Field'
import { InlineError } from '@/components/ui/State'
import { notify } from '@/components/ui/Toast'
import { useCredentialList } from '@/features/credentials/useCredentials'
import { supportsAdmin } from '@/models/upstream'
import { CONFLICT_OPTIONS, STRATEGY_OPTIONS } from '@/features/vaults/syncPolicy'
import type { ConflictPolicy, SyncStrategy } from '@/features/vaults/model'
import { UPSTREAM_ENCRYPTION_NEW } from '@/features/vaults/encryptionCopy'
import { CheckRow } from '@/features/gateway/CheckRow'
import { bucketPrefixProblem, profileNameProblem, type UpstreamProfile } from '@/features/gateway/model'
import { refreshProfiles } from '@/features/gateway/queries'

// Create an upstream profile, or change one. The name is what S3 clients send as a region, so it never changes.
export default function UpstreamProfileDialog({
  profile,
  onClose,
}: {
  profile: UpstreamProfile | null
  onClose: () => void
}) {
  const keys = useCredentialList()
  const [name, setName] = useState(profile?.name ?? '')
  const [keyId, setKeyId] = useState(profile?.api_key_id ? String(profile.api_key_id) : '')
  const [encrypt, setEncrypt] = useState(profile?.encrypt_upstream ?? true)
  // '' on a new profile: the server's default for S3 vaults.
  const [strategy, setStrategy] = useState<SyncStrategy | ''>(
    STRATEGY_OPTIONS.find(o => o.value === profile?.sync_strategy)?.value ?? '',
  )
  const [conflict, setConflict] = useState<ConflictPolicy | ''>(
    CONFLICT_OPTIONS.find(o => o.value === profile?.conflict_policy)?.value ?? '',
  )
  const [prefix, setPrefix] = useState(profile?.bucket_prefix ?? '')
  const [description, setDescription] = useState(profile?.description ?? '')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)

  const nameProblem = profile ? null : profileNameProblem(name.trim())
  const prefixProblem = bucketPrefixProblem(prefix.trim())
  const known = (keys.data ?? []).some(k => String(k.api_key_id) === keyId)
  const mirrorsOneWay = strategy === 'mirror' && conflict === 'keep_local'

  const submit = async () => {
    if ((!profile && (!name.trim() || nameProblem)) || !keyId || prefixProblem) return
    setBusy(true)
    setError(null)
    const settings = {
      api_key_id: Number(keyId),
      encrypt_upstream: encrypt,
      ...(strategy ? { sync_strategy: strategy } : {}),
      ...(conflict ? { conflict_policy: conflict } : {}),
      bucket_prefix: prefix.trim(),
      description: description.trim() || null,
    }
    try {
      if (profile) {
        const result = await api.send('s3.gateway.upstreamProfiles.update', { profile_id: profile.id, ...settings })
        const reapplied = result.reapplied ?? []
        const applied = reapplied.filter(r => r.applied).length
        notify.success(
          'Profile saved',
          reapplied.length === 0 ? profile.name : `${applied} of ${reapplied.length} existing buckets now use the new sync settings.`,
        )
      } else {
        await api.send('s3.gateway.upstreamProfiles.create', { name: name.trim(), ...settings })
        notify.success('Profile created', name.trim())
      }
      await refreshProfiles()
      onClose()
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open onOpenChange={open => !open && onClose()}>
      <DialogContent
        title={profile ? `Upstream profile “${profile.name}”` : 'New upstream profile'}
        description="What a CreateBucket through the gateway creates: an S3 vault over a bucket in this provider account, with these settings."
        footer={
          <>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button
              type="submit"
              form="gw-upstream-profile"
              variant="primary"
              loading={busy}
              data-testid="s3-gateway-save-upstream-profile">
              {profile ? 'Save profile' : 'Create profile'}
            </Button>
          </>
        }>
        <form
          id="gw-upstream-profile"
          className="space-y-4"
          onSubmit={event => {
            event.preventDefault()
            void submit()
          }}>
          <Field
            label="Name"
            htmlFor="gw-profile-name"
            required
            error={nameProblem ?? undefined}
            hint={
              profile ?
                'The name can’t change: S3 clients select the profile with it.'
              : 'S3 clients can select the profile by sending this name as their region. Not a real provider region.'
            }>
            <Input
              id="gw-profile-name"
              data-testid="s3-gateway-upstream-profile-name"
              value={name}
              onChange={e => setName(e.target.value.toLowerCase())}
              disabled={profile !== null}
              className="font-mono"
              placeholder="vl-b2"
              autoComplete="off"
            />
          </Field>
          <Field
            label="Provider credential"
            htmlFor="gw-profile-key"
            required
            hint="The upstream account buckets are created in. It must be enabled for provider administration (Provider credentials).">
            <Select
              id="gw-profile-key"
              data-testid="s3-gateway-upstream-profile-key"
              value={keyId}
              onChange={e => setKeyId(e.target.value)}>
              <option value="">{keys.isPending ? 'Loading…' : 'Choose a credential…'}</option>
              {keyId && !known ?
                <option value={keyId}>{profile?.api_key_name ?? `Credential #${keyId}`}</option>
              : null}
              {(keys.data ?? []).map(k => (
                <option
                  key={k.api_key_id}
                  value={k.api_key_id}
                  disabled={!(supportsAdmin(k.provider) && k.admin_enabled) && String(k.api_key_id) !== keyId}>
                  {k.name} ({k.provider}){supportsAdmin(k.provider) && k.admin_enabled ? '' : ' · administration off'}
                </option>
              ))}
            </Select>
          </Field>
          <CheckRow
            id="gw-profile-encrypt"
            label="Encrypt objects before they leave this server"
            hint={`Recommended. ${UPSTREAM_ENCRYPTION_NEW} Turning it off stores plain objects at the provider.`}
            checked={encrypt}
            onCheckedChange={setEncrypt}
          />
          <div className="grid gap-4 sm:grid-cols-2">
            <Field
              label="Sync strategy"
              htmlFor="gw-profile-strategy"
              hint={STRATEGY_OPTIONS.find(o => o.value === strategy)?.hint ?? 'The server’s default for S3 vaults.'}>
              <Select
                id="gw-profile-strategy"
                value={strategy}
                onChange={e => setStrategy(e.target.value as SyncStrategy | '')}>
                {profile ? null : <option value="">Server default</option>}
                {STRATEGY_OPTIONS.map(o => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </Select>
            </Field>
            <Field
              label="When both sides changed"
              htmlFor="gw-profile-conflict"
              hint={CONFLICT_OPTIONS.find(o => o.value === conflict)?.hint ?? 'The server’s default for S3 vaults.'}>
              <Select
                id="gw-profile-conflict"
                value={conflict}
                onChange={e => setConflict(e.target.value as ConflictPolicy | '')}>
                {profile ? null : <option value="">Server default</option>}
                {CONFLICT_OPTIONS.map(o => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </Select>
            </Field>
          </div>
          {mirrorsOneWay ?
            <p className="text-fg-subtle text-xs">
              Mirror with Keep local removes bucket objects the vault doesn’t hold. A CreateBucket only ever uses a
              bucket it created, or one of yours that is empty.
            </p>
          : null}
          <Field
            label="Upstream bucket prefix"
            htmlFor="gw-profile-prefix"
            error={prefixProblem ?? undefined}
            hint={`The upstream bucket is named ${prefix.trim()}<bucket>. Bucket names are shared by every account of a provider, so a prefix of your own avoids names someone else holds.`}>
            <Input
              id="gw-profile-prefix"
              value={prefix}
              onChange={e => setPrefix(e.target.value.toLowerCase())}
              className="font-mono"
              placeholder="acme-"
              autoComplete="off"
            />
          </Field>
          <Field label="Description" htmlFor="gw-profile-description">
            <Input id="gw-profile-description" value={description} onChange={e => setDescription(e.target.value)} />
          </Field>
          <InlineError error={error} />
        </form>
      </DialogContent>
    </Dialog>
  )
}
