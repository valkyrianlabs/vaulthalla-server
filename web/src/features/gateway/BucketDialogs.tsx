'use client'

import React, { useState } from 'react'
import { api } from '@/lib/session'
import { Dialog, DialogContent } from '@/components/ui/Dialog'
import { Button } from '@/components/ui/Button'
import { Field, Input, Select } from '@/components/ui/Field'
import { InlineError } from '@/components/ui/State'
import { notify } from '@/components/ui/Toast'
import { formatBytes } from '@/lib/format'
import { ScaledInput, BYTE_UNITS } from '@/features/settings/controls'
import { useCredentialList } from '@/features/credentials/useCredentials'
import { BUCKET_MODES, bucketNameProblem } from '@/features/gateway/model'
import { refreshBuckets, useVaultOptions } from '@/features/gateway/queries'
import { CheckRow } from '@/features/gateway/CheckRow'
import type { S3GatewayBucketBindMode } from '@/models/s3Gateway'

export type BucketDialogKind = 'bind' | 'local' | 'remote'

const useSubmit = (onDone: () => void) => {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const submit = async (work: () => Promise<unknown>, success: string) => {
    setBusy(true)
    setError(null)
    try {
      await work()
      await refreshBuckets()
      notify.success(success)
      onDone()
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }
  return { busy, error, submit }
}

const Footer = ({
  busy,
  label,
  form,
  testId,
  onCancel,
}: {
  busy: boolean
  label: string
  form: string
  testId?: string
  onCancel: () => void
}) => (
  <>
    <Button variant="ghost" onClick={onCancel}>
      Cancel
    </Button>
    <Button type="submit" form={form} variant="primary" loading={busy} data-testid={testId}>
      {label}
    </Button>
  </>
)

const BindDialog = ({ onClose }: { onClose: () => void }) => {
  const vaults = useVaultOptions()
  const { busy, error, submit } = useSubmit(onClose)
  const [vaultId, setVaultId] = useState('')
  const [name, setName] = useState('')
  const [mode, setMode] = useState('')
  const [exclusive, setExclusive] = useState(false)
  const vault = vaults.list.find(v => String(v.id) === vaultId)
  const modes: S3GatewayBucketBindMode[] = vault?.type === 's3' ? ['remote_cache', 'remote_proxy'] : ['local']
  const chosenMode = modes.find(m => m === mode) ?? modes[0]
  const nameProblem = bucketNameProblem(name.trim())
  return (
    <DialogContent
      title="Bind a vault as a bucket"
      description="Expose an existing vault under an S3 bucket name. Binding doesn’t grant access; keys still need it."
      footer={<Footer busy={busy} label="Bind" form="gw-bind" onCancel={onClose} />}>
      <form
        id="gw-bind"
        className="space-y-4"
        onSubmit={event => {
          event.preventDefault()
          if (!vaultId || nameProblem) return
          void submit(
            () =>
              api.send('s3.gateway.buckets.bind', {
                ...(name.trim() ? { bucket_name: name.trim() } : {}),
                vault_id: Number(vaultId),
                mode: chosenMode,
                api_exclusive: exclusive,
              }),
            'Bucket bound',
          )
        }}>
        <Field label="Vault" htmlFor="gw-bind-vault" required>
          <Select id="gw-bind-vault" value={vaultId} onChange={e => setVaultId(e.target.value)}>
            <option value="">Choose a vault…</option>
            {vaults.list.map(v => (
              <option key={v.id} value={v.id}>
                {v.name}
              </option>
            ))}
          </Select>
        </Field>
        <Field
          label="Bucket name"
          htmlFor="gw-bind-name"
          hint="Empty: the vault’s slug."
          error={nameProblem ?? undefined}>
          <Input
            id="gw-bind-name"
            value={name}
            onChange={e => setName(e.target.value.toLowerCase())}
            className="font-mono"
            autoComplete="off"
          />
        </Field>
        <Field label="Mode" htmlFor="gw-bind-mode" hint={BUCKET_MODES[chosenMode]?.hint}>
          <Select
            id="gw-bind-mode"
            value={chosenMode}
            onChange={e => setMode(e.target.value)}
            disabled={modes.length === 1}>
            {modes.map(m => (
              <option key={m} value={m}>
                {BUCKET_MODES[m]?.label ?? m}
              </option>
            ))}
          </Select>
        </Field>
        <CheckRow
          id="gw-bind-exclusive"
          label="Gateway only"
          hint="Reserve the vault for S3 access (API-exclusive)."
          checked={exclusive}
          onCheckedChange={setExclusive}
        />
        <InlineError error={error} />
      </form>
    </DialogContent>
  )
}

const LocalDialog = ({ onClose }: { onClose: () => void }) => {
  const { busy, error, submit } = useSubmit(onClose)
  const [name, setName] = useState('')
  const [quota, setQuota] = useState<number | null>(null)
  const problem = bucketNameProblem(name.trim())
  return (
    <DialogContent
      title="New local bucket"
      description="Creates a new vault on this server and binds it as a bucket."
      footer={
        <Footer
          busy={busy}
          label="Create bucket"
          form="gw-local"
          testId="s3-gateway-create-local-bucket"
          onCancel={onClose}
        />
      }>
      <form
        id="gw-local"
        className="space-y-4"
        onSubmit={event => {
          event.preventDefault()
          if (!name.trim() || problem) return
          void submit(
            () =>
              api.send('s3.gateway.buckets.createLocal', {
                bucket_name: name.trim(),
                ...(quota ? { quota_bytes: quota } : {}),
              }),
            'Bucket created',
          )
        }}>
        <Field label="Bucket name" htmlFor="gw-local-name" required error={problem ?? undefined}>
          <Input
            id="gw-local-name"
            data-testid="s3-gateway-local-bucket-name-input"
            value={name}
            onChange={e => setName(e.target.value.toLowerCase())}
            className="font-mono"
            autoComplete="off"
          />
        </Field>
        <Field label="Quota" htmlFor="gw-local-quota" hint={quota ? formatBytes(quota) : 'Empty: no quota.'}>
          <ScaledInput id="gw-local-quota" value={quota} onChange={setQuota} units={BYTE_UNITS} />
        </Field>
        <InlineError error={error} />
      </form>
    </DialogContent>
  )
}

const RemoteDialog = ({ onClose }: { onClose: () => void }) => {
  const { busy, error, submit } = useSubmit(onClose)
  const keys = useCredentialList()
  const [name, setName] = useState('')
  const [keyId, setKeyId] = useState('')
  const [upstream, setUpstream] = useState('')
  const [encrypt, setEncrypt] = useState(true)
  const problem = bucketNameProblem(name.trim())
  return (
    <DialogContent
      title="New remote-cache bucket"
      description="Creates an S3 vault on an upstream bucket and serves it through the gateway with a local cache."
      footer={<Footer busy={busy} label="Create bucket" form="gw-remote" onCancel={onClose} />}>
      <form
        id="gw-remote"
        className="space-y-4"
        onSubmit={event => {
          event.preventDefault()
          if (!name.trim() || problem || !keyId || !upstream.trim()) return
          void submit(
            () =>
              api.send('s3.gateway.buckets.createRemoteCache', {
                bucket_name: name.trim(),
                api_key_id: Number(keyId),
                upstream_bucket: upstream.trim(),
                encrypt_upstream: encrypt,
              }),
            'Bucket created',
          )
        }}>
        <Field label="Bucket name" htmlFor="gw-remote-name" required error={problem ?? undefined}>
          <Input
            id="gw-remote-name"
            value={name}
            onChange={e => setName(e.target.value.toLowerCase())}
            className="font-mono"
            autoComplete="off"
          />
        </Field>
        <Field
          label="Provider credential"
          htmlFor="gw-remote-key"
          required
          hint="The upstream S3/R2 account (Provider credentials).">
          <Select id="gw-remote-key" value={keyId} onChange={e => setKeyId(e.target.value)}>
            <option value="">{keys.isPending ? 'Loading…' : 'Choose a credential…'}</option>
            {(keys.data ?? []).map(k => (
              <option key={k.api_key_id} value={k.api_key_id}>
                {k.name} ({k.provider})
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Upstream bucket" htmlFor="gw-remote-upstream" required>
          <Input
            id="gw-remote-upstream"
            value={upstream}
            onChange={e => setUpstream(e.target.value)}
            className="font-mono"
            autoComplete="off"
          />
        </Field>
        <CheckRow
          id="gw-remote-encrypt"
          label="Encrypt objects before they leave this server"
          hint="Recommended. Turning it off stores plain objects at the provider."
          checked={encrypt}
          onCheckedChange={setEncrypt}
        />
        <InlineError error={error} />
      </form>
    </DialogContent>
  )
}

export default function BucketDialog({ kind, onClose }: { kind: BucketDialogKind; onClose: () => void }) {
  return (
    <Dialog open onOpenChange={open => !open && onClose()}>
      {kind === 'bind' ?
        <BindDialog onClose={onClose} />
      : kind === 'local' ?
        <LocalDialog onClose={onClose} />
      : <RemoteDialog onClose={onClose} />}
    </Dialog>
  )
}
