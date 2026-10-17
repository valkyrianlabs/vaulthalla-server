'use client'

import React from 'react'
import { cn } from '@/util/cn'
import { toneClasses, type Tone } from '@/lib/tone'
import { DASH, formatBytes, formatDateTime, formatMoney } from '@/lib/format'
import { isWsError, type WsError } from '@/lib/ws/errors'
import type { Money, RecoveryBackend, RecoveryCostBasis, RecoveryItemAction, RecoveryPoint } from '@/models/recovery'

// Shared by every recovery surface. Everything here is display only: the daemon owns every decision, and unknown
// values (money above all) stay unknown, never 0.

// A NeedsConfirmation refusal with this data.code.
export const needsCode = (error: unknown, code: string): error is WsError =>
  isWsError(error, 'needs_confirmation') && error.code === code

// Money the daemon could not estimate is null: say so, never "$0.00".
export const moneyText = (money: Money | null | undefined, unknown = 'not estimated') =>
  money ? formatMoney(money.amount, money.currency) : unknown

export const BACKEND_LABEL: Record<RecoveryBackend, string> = {
  local_snapshot: 'Snapshots',
  local_version: 'Local versions',
  provider_version: 'Provider versions',
}

export const BACKEND_HINT: Record<RecoveryBackend, string> = {
  local_snapshot: 'Named recovery points someone created. Kept until deleted.',
  local_version: 'Earlier contents kept on this server each time the file changed.',
  provider_version: 'Object versions kept by the bucket. Vaulthalla stores only their metadata.',
}

export const REASON_LABEL: Record<string, string> = {
  overwrite: 'Overwritten',
  truncate: 'Truncated',
  delete: 'Deleted',
  download: 'Replaced by a sync download',
  restore: 'Replaced by a restore',
  conflict: 'Replaced resolving a conflict',
}

export const retentionLabel = (policy: string | null | undefined) => {
  if (!policy) return DASH
  if (policy === 'snapshot') return 'Kept until deleted'
  if (policy === 'indefinite') return 'Kept indefinitely'
  if (policy === 'unknown') return 'Unknown'
  const [kind, value] = policy.split(':')
  if (kind === 'keep_last') return `Newest ${value} kept`
  if (kind === 'max_age_days') return `Kept ${value} days`
  if (kind === 'provider_days') return `Provider keeps it ${value} days after it is replaced`
  return policy
}

// Retention choices offered for provider versioning. No default: a person picks one.
export const RETENTION_CHOICES = [
  { value: '30d', label: '30 days' },
  { value: '90d', label: '90 days' },
  { value: '365d', label: '365 days' },
  { value: 'indefinite', label: 'Indefinitely' },
] as const

export const retentionChoiceLabel = (value: string | null | undefined) =>
  RETENTION_CHOICES.find(c => c.value === value)?.label ?? (value ? value : DASH)

export const ACTION_TONE: Record<RecoveryItemAction, Tone> = {
  create: 'accent',
  overwrite: 'warn',
  skip: 'neutral',
  conflict: 'danger',
  remove: 'danger',
  unavailable: 'unknown',
}

export const ACTION_LABEL: Record<RecoveryItemAction, string> = {
  create: 'Create',
  overwrite: 'Overwrite',
  skip: 'Skip',
  conflict: 'Conflict',
  remove: 'Remove',
  unavailable: 'Unavailable',
}

export const METHOD_LABEL: Record<string, string> = {
  local_copy: 'Local copy',
  local_reseal: 'Local, re-encrypted',
  provider_copy: 'Provider copy',
  provider_transfer: 'Download + upload',
  none: DASH,
}

export const BASIS_LABEL: Record<RecoveryCostBasis, string> = {
  observed: 'From your observed workload',
  scenario: 'Scenario',
  illustrative: 'Illustrative assumption, not your data',
}

export const BASIS_TONE: Record<RecoveryCostBasis, Tone> = {
  observed: 'accent',
  scenario: 'neutral',
  illustrative: 'warn',
}

export const pointTime = (point: RecoveryPoint) => point.created_at ?? point.valid_from

export const sizeText = (bytes: number | null | undefined) =>
  bytes === null || bytes === undefined ? DASH : formatBytes(bytes)

export const timeText = (value: string | null | undefined) => formatDateTime(value)

// A bordered, toned message block. Warnings and the consistency note use it so they can't be skimmed past.
export const Notice = ({
  tone = 'neutral',
  title,
  children,
  className,
  icon: Icon,
  role,
  testId,
}: {
  tone?: Tone
  title?: React.ReactNode
  children?: React.ReactNode
  className?: string
  icon?: React.ComponentType<React.SVGProps<SVGSVGElement>>
  role?: 'alert' | 'note' | 'status'
  testId?: string
}) => {
  const t = toneClasses[tone]
  return (
    <div
      role={role}
      data-testid={testId}
      className={cn('rounded-control flex gap-2.5 border px-3 py-2.5 text-sm', t.bg, t.border, className)}>
      {Icon ?
        <Icon className={cn('mt-0.5 size-4 shrink-0', t.text)} aria-hidden />
      : null}
      <div className="min-w-0">
        {title ?
          <p className={cn('font-medium', t.text)}>{title}</p>
        : null}
        {children ?
          <div className={cn('text-fg-muted', title ? 'mt-0.5' : null)}>{children}</div>
        : null}
      </div>
    </div>
  )
}

export const SubHeading = ({ children, className }: { children: React.ReactNode; className?: string }) => (
  <h3 className={cn('text-fg-subtle mb-2 text-[11px] font-medium tracking-wide uppercase', className)}>{children}</h3>
)

export const BulletList = ({ items, className }: { items: React.ReactNode[]; className?: string }) =>
  items.length ?
    <ul className={cn('list-disc space-y-1 pl-5 text-sm', className)}>
      {items.map((item, i) => (
        <li key={i}>{item}</li>
      ))}
    </ul>
  : null

// GiB in the inputs, bytes on the wire. Empty means "no limit" (0 / null on the wire).
export const GIB = 1024 ** 3
export const bytesToGib = (bytes: number | null | undefined) =>
  bytes ? String(Math.round((bytes / GIB) * 100) / 100) : ''
export const gibToBytes = (value: string) => {
  const n = Number(value.trim())
  return value.trim() && Number.isFinite(n) && n > 0 ? Math.round(n * GIB) : 0
}
