'use client'

import React, { useState } from 'react'
import { api } from '@/lib/session'
import { Dialog, SheetContent } from '@/components/ui/Dialog'
import { Button } from '@/components/ui/Button'
import { Checkbox } from '@/components/ui/Choice'
import { Field, Input, Select } from '@/components/ui/Field'
import { Badge } from '@/components/ui/Badge'
import { Meter } from '@/components/ui/Stat'
import { InlineError, Skeleton } from '@/components/ui/State'
import { confirm } from '@/components/ui/Confirm'
import { notify } from '@/components/ui/Toast'
import { BanIcon, FloppyDiskIcon, PlusIcon, TrashIcon } from '@/components/ui/icons'
import { DASH, formatDateTime, formatPercent } from '@/lib/format'
import { isDecimal } from '@/features/settings/controls'
import { MODES, type BudgetMode, type BudgetPolicy, type BudgetTrend } from '@/features/cost/model'
import { findPolicy } from '@/features/cost/queries'
import { Money } from '@/features/cost/bits'
import { LedgerTable } from '@/features/cost/tables'
import { SCOPE_MODES, type GatewayCredential, type PathOverride, type ScopeMode } from '@/features/gateway/model'
import {
  refreshCredentials,
  refreshGatewayBudgets,
  useDefaultOverrides,
  useDefaultRole,
  useFsPermissionOptions,
  useGatewayBudgetStatus,
  useGatewayLedger,
  useGatewayPerms,
  useGatewayPolicies,
  useRoleAssignments,
  useSelectedVaults,
  useVaultOptions,
  useVaultOverrides,
  useVaultRoleOptions,
} from '@/features/gateway/queries'
import { CheckRow } from '@/features/gateway/CheckRow'
import { revokeCredential } from '@/features/gateway/CredentialsTab'

const run = async (work: () => Promise<unknown>, after: () => Promise<unknown>, failure: string) => {
  try {
    await work()
    await after()
    return true
  } catch (error) {
    notify.error(error, failure)
    return false
  }
}

const Block = ({
  title,
  hint,
  children,
  testId,
}: {
  title: string
  hint?: React.ReactNode
  children: React.ReactNode
  testId?: string
}) => (
  <div className="rounded-card border-line bg-surface-1 space-y-3 border p-4" data-testid={testId}>
    <div>
      <h4 className="text-fg text-sm font-medium">{title}</h4>
      {hint ?
        <p className="text-fg-subtle mt-0.5 text-xs">{hint}</p>
      : null}
    </div>
    {children}
  </div>
)

const SectionTitle = ({ children, hint }: { children: React.ReactNode; hint?: React.ReactNode }) => (
  <div className="mb-3">
    <h3 className="text-fg text-[15px] font-semibold">{children}</h3>
    {hint ?
      <p className="text-fg-subtle mt-0.5 text-sm">{hint}</p>
    : null}
  </div>
)

// ---- overrides --------------------------------------------------------------------------------------------------

const OverrideTable = ({
  rows,
  onRemove,
  empty,
}: {
  rows: PathOverride[]
  onRemove: (o: PathOverride) => void
  empty: string
}) => (
  <div className="rounded-control border-line overflow-x-auto border">
    <table className="w-full text-sm">
      <thead>
        <tr className="border-line text-fg-subtle border-b text-left text-xs">
          <th className="h-8 px-3 font-medium">Permission</th>
          <th className="h-8 px-3 font-medium">Path</th>
          <th className="h-8 px-3 font-medium">Effect</th>
          <th className="h-8 w-10 px-2" aria-label="Actions" />
        </tr>
      </thead>
      <tbody>
        {rows.length === 0 ?
          <tr>
            <td colSpan={4} className="text-fg-subtle px-3 py-4 text-center text-xs">
              {empty}
            </td>
          </tr>
        : rows.map(o => (
            <tr key={o.id} className="border-line/60 border-b last:border-0">
              <td className="text-fg h-9 px-3 font-mono text-xs">
                {o.permission}
                {o.enabled ? null : <span className="text-fg-faint ml-2">(off)</span>}
              </td>
              <td className="text-fg-muted h-9 px-3 font-mono text-xs">{o.glob_path}</td>
              <td className="h-9 px-3">
                <Badge tone={o.effect === 'deny' ? 'neutral' : 'accent'}>
                  {o.effect === 'deny' ? 'Deny' : 'Allow'}
                </Badge>
              </td>
              <td className="h-9 px-2 text-right">
                <Button
                  size="icon-sm"
                  variant="ghost"
                  aria-label={`Remove override ${o.glob_path}`}
                  onClick={() => onRemove(o)}>
                  <TrashIcon aria-hidden />
                </Button>
              </td>
            </tr>
          ))
        }
      </tbody>
    </table>
  </div>
)

const OverrideForm = ({
  prefix,
  permissions,
  onAdd,
  disabled,
}: {
  prefix: 'default-override' | 'override'
  permissions: string[]
  onAdd: (spec: {
    permission_qualified: string
    glob_path: string
    effect: 'allow' | 'deny'
    enabled: boolean
  }) => Promise<boolean>
  disabled?: boolean
}) => {
  const [permission, setPermission] = useState('')
  const [glob, setGlob] = useState('**')
  const [effect, setEffect] = useState<'allow' | 'deny'>('deny')
  const [enabled, setEnabled] = useState(true)
  const chosen = permission || permissions[0] || ''
  return (
    <div className="grid gap-2 sm:grid-cols-[1.3fr_1fr_6.5rem_auto_auto] sm:items-end">
      <Field label="Permission" htmlFor={`gw-${prefix}-perm`}>
        <Select
          id={`gw-${prefix}-perm`}
          data-testid={`s3-gateway-${prefix}-permission-select`}
          value={chosen}
          onChange={e => setPermission(e.target.value)}>
          {permissions.map(p => (
            <option key={p} value={p}>
              {p}
            </option>
          ))}
        </Select>
      </Field>
      <Field label="Path pattern" htmlFor={`gw-${prefix}-glob`}>
        <Input
          id={`gw-${prefix}-glob`}
          data-testid={`s3-gateway-${prefix}-glob-input`}
          value={glob}
          onChange={e => setGlob(e.target.value)}
          className="font-mono"
        />
      </Field>
      <Field label="Effect" htmlFor={`gw-${prefix}-effect`}>
        <Select
          id={`gw-${prefix}-effect`}
          data-testid={`s3-gateway-${prefix}-effect-select`}
          value={effect}
          onChange={e => setEffect(e.target.value as 'allow' | 'deny')}>
          <option value="deny">deny</option>
          <option value="allow">allow</option>
        </Select>
      </Field>
      <label className="text-fg-muted flex h-9 items-center gap-2 text-sm">
        <Checkbox checked={enabled} onCheckedChange={setEnabled} />
        On
      </label>
      <Button
        variant="secondary"
        data-testid={`s3-gateway-${prefix}-add-submit`}
        disabled={disabled || !chosen || !glob.trim()}
        onClick={async () => {
          if (await onAdd({ permission_qualified: chosen, glob_path: glob.trim(), effect, enabled })) setGlob('**')
        }}>
        <PlusIcon aria-hidden />
        Add
      </Button>
    </div>
  )
}

// ---- access -----------------------------------------------------------------------------------------------------

const AccessEditor = ({ credential }: { credential: GatewayCredential }) => {
  const id = credential.id
  const [scope, setScope] = useState<ScopeMode>(credential.scope_mode ?? 'user_access')
  const [description, setDescription] = useState(credential.description ?? '')
  const [localBudget, setLocalBudget] = useState(credential.enforce_budget_for_local_requests)
  const [saveState, setSaveState] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle')
  const [saveError, setSaveError] = useState<unknown>(null)
  const policyScope = scope !== 'user_access'
  const savedScope = credential.scope_mode

  const defaultRole = useDefaultRole(id)
  const selected = useSelectedVaults(id, scope === 'vault_allowlist')
  const defaultOverrides = useDefaultOverrides(id, policyScope)
  const assignments = useRoleAssignments(id, policyScope)
  const roles = useVaultRoleOptions()
  const vaults = useVaultOptions()
  const permissions = useFsPermissionOptions(policyScope)

  const [roleId, setRoleId] = useState<string>('')
  const shownRole = roleId || (defaultRole.data?.vault_role_id ? String(defaultRole.data.vault_role_id) : '')
  const [addVault, setAddVault] = useState('')
  const [assignVault, setAssignVault] = useState('')
  const [assignRole, setAssignRole] = useState('')
  const [overrideVault, setOverrideVault] = useState('')

  const selectedIds = new Set((selected.data ?? []).filter(s => s.enabled).map(s => s.vault_id))
  const exceptionVaults = scope === 'global' ? vaults.list : vaults.list.filter(v => selectedIds.has(v.id))
  const assigned = new Set((assignments.data ?? []).map(a => a.vault_id))
  const overrideVaultId = Number(overrideVault) || exceptionVaults[0]?.id || null
  const vaultOverrides = useVaultOverrides(id, policyScope ? overrideVaultId : null)

  const save = async () => {
    setSaveState('saving')
    setSaveError(null)
    try {
      await api.send('s3.gateway.credentials.scope.update', {
        access_key: credential.access_key,
        scope_mode: scope,
        description: description.trim() || null,
        ...(policyScope && shownRole ? { default_vault_role_id: Number(shownRole) } : {}),
        ...(scope === 'vault_allowlist' ? { selected_vault_ids: [...selectedIds] } : {}),
        enforce_budget_for_local_requests: localBudget,
      })
      await refreshCredentials()
      setSaveState('saved')
    } catch (error) {
      setSaveState('error')
      setSaveError(error)
    }
  }

  const removeOverride = (o: PathOverride, vaultId?: number) =>
    void run(
      () =>
        vaultId ?
          api.send('s3.gateway.credentials.roles.overrides.remove', {
            credential_id: id,
            vault_id: vaultId,
            override_id: o.id,
          })
        : api.send('s3.gateway.credentials.defaultRole.overrides.remove', { credential_id: id, override_id: o.id }),
      refreshCredentials,
      'Could not remove the override',
    )

  return (
    <section data-testid="s3-gateway-section-credential-roles" className="space-y-4">
      <SectionTitle hint="What this key can reach, and with which vault role.">Access</SectionTitle>

      <div className="grid gap-3 sm:grid-cols-[14rem_1fr]">
        <Field label="Access" htmlFor="gw-scope" hint={SCOPE_MODES.find(m => m.value === scope)?.hint}>
          <Select
            id="gw-scope"
            data-testid="s3-gateway-scope-editor-scope-select"
            value={scope}
            onChange={e => {
              setScope(e.target.value as ScopeMode)
              setSaveState('idle')
            }}>
            {SCOPE_MODES.map(m => (
              <option key={m.value} value={m.value}>
                {m.label}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Description" htmlFor="gw-scope-desc">
          <Input id="gw-scope-desc" value={description} onChange={e => setDescription(e.target.value)} />
        </Field>
      </div>
      <CheckRow
        id="gw-scope-local"
        testId="s3-gateway-scope-enforce-local-budget"
        label="Count cache and local hits against this key’s budget"
        hint="When on, requests served without an upstream S3 call still use up this key’s budget."
        checked={localBudget}
        onCheckedChange={setLocalBudget}
      />
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="primary" data-testid="s3-gateway-scope-save" loading={saveState === 'saving'} onClick={save}>
          <FloppyDiskIcon aria-hidden />
          Save access
        </Button>
        <span className="text-fg-subtle text-xs" data-testid="s3-gateway-scope-save-status" aria-live="polite">
          {saveState === 'saving' ?
            'Saving'
          : saveState === 'saved' ?
            'Saved'
          : saveState === 'error' ?
            'Save failed'
          : ''}
        </span>
      </div>
      {saveError ?
        <InlineError error={saveError} />
      : null}

      {!policyScope ?
        <p
          className="rounded-control border-line bg-surface-1 text-fg-subtle border px-3 py-2.5 text-sm"
          data-testid="s3-gateway-user-access-policy-note">
          This key uses {credential.principal_user?.name ?? 'its principal'}’s own vault roles and overrides. There is
          no extra gateway policy to configure.
        </p>
      : <>
          {savedScope !== scope ?
            <p className="text-fg-subtle text-xs">Save the access change before editing the policy below.</p>
          : null}
          <Block
            title="Default vault role"
            hint={
              scope === 'global' ?
                'Applies to every bound bucket unless a per-vault exception overrides it.'
              : 'Applies to every selected vault unless a per-vault exception overrides it.'
            }>
            <div className="flex flex-wrap items-end gap-2">
              <Field label="Vault role" htmlFor="gw-default-role" className="min-w-48 flex-1">
                <Select
                  id="gw-default-role"
                  data-testid="s3-gateway-default-role-select"
                  value={shownRole}
                  onChange={e => setRoleId(e.target.value)}>
                  <option value="">Choose a role…</option>
                  {roles.map(r => (
                    <option key={r.id} value={r.id}>
                      {r.name}
                    </option>
                  ))}
                </Select>
              </Field>
              <Button
                variant="secondary"
                data-testid="s3-gateway-default-role-save"
                disabled={!shownRole}
                onClick={() =>
                  void run(
                    () =>
                      api.send('s3.gateway.credentials.defaultRole.set', {
                        credential_id: id,
                        vault_role_id: Number(shownRole),
                        enabled: true,
                      }),
                    refreshCredentials,
                    'Could not set the default role',
                  )
                }>
                Set role
              </Button>
              <Button
                variant="ghost"
                disabled={!defaultRole.data}
                onClick={() =>
                  void run(
                    () => api.send('s3.gateway.credentials.defaultRole.clear', { credential_id: id }),
                    async () => {
                      setRoleId('')
                      await refreshCredentials()
                    },
                    'Could not clear the default role',
                  )
                }>
                Clear
              </Button>
            </div>
          </Block>

          {scope === 'vault_allowlist' ?
            <Block
              title="Selected vaults"
              testId="s3-gateway-selected-vaults-panel"
              hint="The key can reach only these vaults.">
              {selected.isPending ?
                <Skeleton className="h-9" />
              : (selected.data ?? []).length === 0 ?
                <p className="text-fg-subtle text-sm">No vaults yet — the key reaches nothing until you add one.</p>
              : <ul className="divide-line/60 rounded-control border-line divide-y border">
                  {(selected.data ?? []).map(s => (
                    <li key={s.vault_id} className="flex items-center justify-between gap-3 px-3 py-2 text-sm">
                      <span className="text-fg">
                        {s.vault?.name ?? vaults.name(s.vault_id)}
                        {s.enabled ? null : <span className="text-fg-faint ml-2 text-xs">(off)</span>}
                      </span>
                      <Button
                        size="sm"
                        variant="ghost"
                        aria-label={`Remove ${s.vault?.name ?? 'vault'}`}
                        onClick={() =>
                          void run(
                            () =>
                              api.send('s3.gateway.credentials.selectedVaults.remove', {
                                credential_id: id,
                                vault_id: s.vault_id,
                              }),
                            refreshCredentials,
                            'Could not remove the vault',
                          )
                        }>
                        Remove
                      </Button>
                    </li>
                  ))}
                </ul>
              }
              <div className="flex flex-wrap items-end gap-2">
                <Field label="Add a vault" htmlFor="gw-add-vault" className="min-w-48 flex-1">
                  <Select
                    id="gw-add-vault"
                    data-testid="s3-gateway-selected-vault-add-select"
                    value={addVault}
                    onChange={e => setAddVault(e.target.value)}>
                    <option value="">Choose a vault…</option>
                    {vaults.list
                      .filter(v => !selectedIds.has(v.id))
                      .map(v => (
                        <option key={v.id} value={v.id}>
                          {v.name}
                        </option>
                      ))}
                  </Select>
                </Field>
                <Button
                  variant="secondary"
                  data-testid="s3-gateway-selected-vault-add-submit"
                  disabled={!addVault}
                  onClick={async () => {
                    const ok = await run(
                      () =>
                        api.send('s3.gateway.credentials.selectedVaults.add', {
                          credential_id: id,
                          vault_id: Number(addVault),
                          enabled: true,
                        }),
                      refreshCredentials,
                      'Could not add the vault',
                    )
                    if (ok) setAddVault('')
                  }}>
                  <PlusIcon aria-hidden />
                  Add
                </Button>
              </div>
            </Block>
          : null}

          <Block
            title="Default path overrides"
            hint="Allow or deny one permission under a path pattern, in every vault the key reaches.">
            <OverrideTable
              rows={defaultOverrides.data ?? []}
              onRemove={o => removeOverride(o)}
              empty="No default overrides."
            />
            <OverrideForm
              prefix="default-override"
              permissions={permissions}
              disabled={!defaultRole.data}
              onAdd={spec =>
                run(
                  () => api.send('s3.gateway.credentials.defaultRole.overrides.add', { credential_id: id, ...spec }),
                  refreshCredentials,
                  'Could not add the override',
                )
              }
            />
          </Block>

          <Block title="Per-vault exceptions" hint="A different vault role for one vault.">
            {(assignments.data ?? []).length === 0 ?
              <p className="text-fg-subtle text-sm">No exceptions.</p>
            : <ul className="divide-line/60 rounded-control border-line divide-y border">
                {(assignments.data ?? []).map(a => (
                  <li
                    key={a.vault_id}
                    data-testid="s3-gateway-role-assignment-row"
                    className="flex items-center justify-between gap-3 px-3 py-2 text-sm">
                    <span className="min-w-0">
                      <span className="text-fg">{a.vault?.name ?? vaults.name(a.vault_id)}</span>
                      <span className="text-fg-subtle ml-2 text-xs">as {a.role?.name ?? a.vault_role_id ?? DASH}</span>
                    </span>
                    <Button
                      size="sm"
                      variant="ghost"
                      aria-label={`Revoke exception for ${a.vault?.name ?? 'vault'}`}
                      onClick={() =>
                        void run(
                          () =>
                            api.send('s3.gateway.credentials.roles.revoke', {
                              credential_id: id,
                              vault_id: a.vault_id,
                            }),
                          refreshCredentials,
                          'Could not revoke the exception',
                        )
                      }>
                      Revoke
                    </Button>
                  </li>
                ))}
              </ul>
            }
            <div className="grid gap-2 sm:grid-cols-[1fr_1fr_auto] sm:items-end">
              <Field label="Vault" htmlFor="gw-assign-vault">
                <Select
                  id="gw-assign-vault"
                  data-testid="s3-gateway-role-assign-vault-select"
                  value={assignVault}
                  onChange={e => setAssignVault(e.target.value)}>
                  <option value="">Choose a vault…</option>
                  {exceptionVaults
                    .filter(v => !assigned.has(v.id))
                    .map(v => (
                      <option key={v.id} value={v.id}>
                        {v.name}
                      </option>
                    ))}
                </Select>
              </Field>
              <Field label="Vault role" htmlFor="gw-assign-role">
                <Select
                  id="gw-assign-role"
                  data-testid="s3-gateway-role-assign-role-select"
                  value={assignRole || String(roles[0]?.id ?? '')}
                  onChange={e => setAssignRole(e.target.value)}>
                  {roles.map(r => (
                    <option key={r.id} value={r.id}>
                      {r.name}
                    </option>
                  ))}
                </Select>
              </Field>
              <Button
                variant="secondary"
                data-testid="s3-gateway-role-assign-submit"
                disabled={!assignVault || !(assignRole || roles[0])}
                onClick={async () => {
                  const ok = await run(
                    () =>
                      api.send('s3.gateway.credentials.roles.assign', {
                        credential_id: id,
                        vault_id: Number(assignVault),
                        vault_role_id: Number(assignRole || roles[0]?.id),
                        enabled: true,
                      }),
                    refreshCredentials,
                    'Could not add the exception',
                  )
                  if (ok) setAssignVault('')
                }}>
                Assign
              </Button>
            </div>
          </Block>

          <Block title="Per-vault path overrides">
            <Field label="Vault" htmlFor="gw-override-vault" className="sm:max-w-xs">
              <Select
                id="gw-override-vault"
                data-testid="s3-gateway-override-vault-select"
                value={overrideVaultId ?? ''}
                onChange={e => setOverrideVault(e.target.value)}>
                {exceptionVaults.length === 0 ?
                  <option value="">No vaults</option>
                : null}
                {exceptionVaults.map(v => (
                  <option key={v.id} value={v.id}>
                    {v.name}
                  </option>
                ))}
              </Select>
            </Field>
            <OverrideTable
              rows={vaultOverrides.data ?? []}
              onRemove={o => overrideVaultId && removeOverride(o, overrideVaultId)}
              empty="No overrides for this vault."
            />
            <OverrideForm
              prefix="override"
              permissions={permissions}
              disabled={!overrideVaultId}
              onAdd={spec =>
                run(
                  () =>
                    api.send('s3.gateway.credentials.roles.overrides.add', {
                      credential_id: id,
                      vault_id: overrideVaultId ?? 0,
                      ...spec,
                    }),
                  refreshCredentials,
                  'Could not add the override',
                )
              }
            />
          </Block>
        </>
      }
    </section>
  )
}

// ---- budget -----------------------------------------------------------------------------------------------------

const Usage = ({ trend, policy }: { trend: BudgetTrend | undefined; policy: BudgetPolicy | null }) => {
  if (!policy?.is_active) return <p className="text-fg-subtle text-sm">No cap.</p>
  return (
    <div className="space-y-1.5">
      <div className="flex items-baseline justify-between gap-3 text-sm">
        <span className="text-fg">
          <Money value={trend?.total_cost} currency={policy.currency} /> <span className="text-fg-subtle">of</span>{' '}
          <Money value={policy.max_monthly_cost} currency={policy.currency} />{' '}
          <span className="text-fg-subtle">this month · {policy.mode}</span>
        </span>
        <span className="tabular text-fg-subtle text-xs">{formatPercent(trend?.percent_used, { digits: 0 })}</span>
      </div>
      <Meter ratio={trend?.percent_used} label="Monthly budget used" />
    </div>
  )
}

const amountProblem = (value: string) =>
  value.trim() && !isDecimal(value) ? 'Invalid amount: use a plain number like 12.50' : null

const BudgetEditor = ({ credential }: { credential: GatewayCredential }) => {
  const id = credential.id
  const can = useGatewayPerms()
  const policies = useGatewayPolicies()
  const status = useGatewayBudgetStatus()
  const ledger = useGatewayLedger()
  const vaults = useVaultOptions()
  const [mode, setMode] = useState<BudgetMode>('enforce')
  const [keyAmount, setKeyAmount] = useState('')
  const [vaultId, setVaultId] = useState('')
  const [vaultAmount, setVaultAmount] = useState('')
  const [error, setError] = useState<string | null>(null)

  const all = policies.data ?? []
  const keyPolicy = findPolicy(all, { scope: 'gateway_credential', gateway_credential_id: id })
  const keyVaultPolicy =
    vaultId ?
      findPolicy(all, { scope: 'gateway_credential_vault', gateway_credential_id: id, vault_id: Number(vaultId) })
    : null
  const monthly = (status.data?.trends ?? []).filter(t => t.window_type === 'monthly' && t.gateway_credential_id === id)
  const vaultPolicies = all.filter(
    p => p.scope === 'gateway_credential_vault' && p.gateway_credential_id === id && p.is_active,
  )

  const upsert = async (
    scope: 'gateway_credential' | 'gateway_credential_vault',
    amount: string,
    vault: number | null,
  ) => {
    const problem = amountProblem(amount)
    setError(problem)
    if (problem) return
    await run(
      () =>
        api.send('s3.gateway.budget.policy.upsert', {
          scope,
          gateway_credential_id: id,
          vault_id: vault,
          mode,
          currency: 'USD',
          max_run_cost: null,
          max_daily_cost: null,
          max_monthly_cost: amount.trim(),
          require_verified_catalog: true,
          allow_stale_catalog: false,
          max_catalog_age_seconds: 43_200,
        }),
      refreshGatewayBudgets,
      'Could not save the budget',
    )
  }

  const disable = async (
    scope: 'gateway_credential' | 'gateway_credential_vault',
    vault: number | null,
    label: string,
  ) => {
    const ok = await confirm({
      title: `Disable the ${label} budget?`,
      description: 'Its cap stops applying immediately. Spend already recorded stays in the ledger.',
      confirmLabel: 'Disable budget',
    })
    if (!ok) return
    await run(
      () =>
        api.send('s3.gateway.budget.policy.disable', { scope, gateway_credential_id: id, vault_id: vault }),
      refreshGatewayBudgets,
      'Could not disable the budget',
    )
  }

  return (
    <section data-testid="s3-gateway-section-budgets" className="space-y-4">
      <SectionTitle hint="Monthly caps on what requests through this key may cost.">Budget</SectionTitle>
      <Field
        label="Mode for new caps"
        htmlFor="gw-budget-mode"
        className="sm:max-w-xs"
        hint={MODES.find(m => m.value === mode)?.hint}>
        <Select id="gw-budget-mode" value={mode} onChange={e => setMode(e.target.value as BudgetMode)}>
          {MODES.filter(m => m.value !== 'off').map(m => (
            <option key={m.value} value={m.value}>
              {m.label}
            </option>
          ))}
        </Select>
      </Field>

      <Block title="Whole key">
        <Usage trend={monthly.find(t => t.scope === 'gateway_credential')} policy={keyPolicy} />
        <div className="flex flex-wrap items-end gap-2">
          <Field label="Monthly cap (USD)" htmlFor="gw-key-budget" className="w-40">
            <Input
              id="gw-key-budget"
              data-testid="s3-gateway-key-budget-input"
              inputMode="decimal"
              value={keyAmount}
              onChange={e => setKeyAmount(e.target.value)}
              className="tabular"
              placeholder="e.g. 25"
            />
          </Field>
          <Button
            variant="secondary"
            data-testid="s3-gateway-key-budget-save"
            disabled={!keyAmount.trim() || !can.budgets}
            onClick={() => void upsert('gateway_credential', keyAmount, null)}>
            Save cap
          </Button>
          <Button
            variant="danger"
            data-testid="s3-gateway-key-budget-disable"
            disabled={!keyPolicy?.is_active || !can.budgets}
            onClick={() => void disable('gateway_credential', null, 'whole-key')}>
            Disable
          </Button>
        </div>
      </Block>

      <Block title="Per vault">
        {vaultPolicies.length ?
          <ul className="space-y-3">
            {vaultPolicies.map(p => (
              <li key={p.id ?? p.vault_id}>
                <div className="text-fg-subtle mb-1 text-xs">{vaults.name(p.vault_id)}</div>
                <Usage
                  trend={monthly.find(t => t.scope === 'gateway_credential_vault' && t.vault_id === p.vault_id)}
                  policy={p}
                />
              </li>
            ))}
          </ul>
        : null}
        <div className="flex flex-wrap items-end gap-2">
          <Field label="Vault" htmlFor="gw-kv-vault" className="min-w-44 flex-1">
            <Select
              id="gw-kv-vault"
              data-testid="s3-gateway-key-vault-budget-vault-select"
              value={vaultId}
              onChange={e => setVaultId(e.target.value)}>
              <option value="">Choose a vault…</option>
              {vaults.list.map(v => (
                <option key={v.id} value={v.id}>
                  {v.name}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Monthly cap (USD)" htmlFor="gw-kv-budget" className="w-40">
            <Input
              id="gw-kv-budget"
              data-testid="s3-gateway-key-vault-budget-input"
              inputMode="decimal"
              value={vaultAmount}
              onChange={e => setVaultAmount(e.target.value)}
              className="tabular"
              placeholder="e.g. 10"
            />
          </Field>
          <Button
            variant="secondary"
            data-testid="s3-gateway-key-vault-budget-save"
            disabled={!vaultId || !vaultAmount.trim() || !can.budgets}
            onClick={() => void upsert('gateway_credential_vault', vaultAmount, Number(vaultId))}>
            Save cap
          </Button>
          <Button
            variant="danger"
            data-testid="s3-gateway-key-vault-budget-disable"
            disabled={!vaultId || !keyVaultPolicy?.is_active || !can.budgets}
            onClick={() => void disable('gateway_credential_vault', Number(vaultId), 'per-vault')}>
            Disable
          </Button>
        </div>
      </Block>
      {error ?
        <p role="alert" className="text-danger text-sm">
          {error}
        </p>
      : null}

      <div>
        <h4 className="text-fg mb-2 text-sm font-medium">Recent charges</h4>
        <LedgerTable
          gateway
          showEmptyTable
          ledger={(ledger.data ?? []).filter(e => e.gateway_credential_id === id)}
          vaultName={vaults.name}
          empty="No charges recorded for this key yet."
        />
      </div>
    </section>
  )
}

export default function CredentialSheet({
  credential,
  onClose,
}: {
  credential: GatewayCredential
  onClose: () => void
}) {
  return (
    <Dialog open onOpenChange={open => !open && onClose()}>
      <SheetContent
        width="max-w-3xl"
        title={credential.name}
        description={
          <span className="block space-y-0.5">
            <span className="block font-mono text-xs">{credential.access_key}</span>
            <span className="block">
              Acts as {credential.principal_user?.name ?? DASH} · created {formatDateTime(credential.created_at)}
              {credential.expires_at ? ` · expires ${formatDateTime(credential.expires_at)}` : ''}
            </span>
          </span>
        }
        footer={
          credential.enabled ?
            <Button
              variant="danger"
              className="mr-auto"
              onClick={async () => {
                if (await revokeCredential(credential)) onClose()
              }}>
              <BanIcon aria-hidden />
              Revoke key
            </Button>
          : <span className="text-fg-subtle mr-auto text-sm">This key is revoked.</span>
        }>
        <div className="space-y-8">
          <AccessEditor key={credential.id} credential={credential} />
          <BudgetEditor credential={credential} />
        </div>
      </SheetContent>
    </Dialog>
  )
}
