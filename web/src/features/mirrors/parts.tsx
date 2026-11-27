'use client'

import React from 'react'
import { Badge } from '@/components/ui/Badge'
import { formatDateTime } from '@/lib/format'
import { cn } from '@/util/cn'
import { ROLE_TEXT, statusText, type MirroredVault, type StatusFacts } from '@/features/mirrors/model'

// Small pieces the Mirrored vaults pages share.

export const date = (unix: number) => formatDateTime(unix)

export const RoleBadge = ({ role, testId = 'mirror-role' }: { role: MirroredVault['role']; testId?: string }) => {
  const r = ROLE_TEXT[role] ?? { label: role, tone: 'neutral' as const }
  return (
    <Badge tone={r.tone} className="h-5 px-2 text-[11px]">
      <span data-testid={testId}>{r.label}</span>
    </Badge>
  )
}

// The state as a badge and, unless `compact`, its sentence (and a reason code the console has no words for).
export const MirrorStatus = ({
  row,
  facts,
  compact = false,
  className,
}: {
  row: MirroredVault
  facts: Omit<StatusFacts, 'date'>
  compact?: boolean
  className?: string
}) => {
  const s = statusText(row, { ...facts, date })
  return (
    <span className={cn('flex min-w-0 flex-col gap-0.5', className)} data-testid="mirror-status">
      <span>
        <Badge tone={s.tone} dot className="h-5 px-2 text-[11px]" title={compact ? s.sentence : undefined}>
          <span data-testid="mirror-status-label">{s.label}</span>
        </Badge>
      </span>
      {compact ? null : (
        <span className="text-xs break-words text-fg-subtle" data-testid="mirror-status-sentence">
          {s.sentence}
          {s.code ? <code className="ml-1.5 font-mono text-[11px] opacity-80">({s.code})</code> : null}
        </span>
      )}
    </span>
  )
}

// A two-choice radio group in the console's card style (as the vault deletion's upstream choice).
export const ChoiceCards = <T extends string>({
  name,
  legend,
  value,
  onChange,
  options,
  testId,
}: {
  name: string
  legend: React.ReactNode
  value: T | null
  onChange: (value: T) => void
  options: { value: T; title: string; hint: string }[]
  testId?: string
}) => (
  <fieldset className="space-y-2" data-testid={testId}>
    <legend className="mb-2 text-sm font-medium text-fg">{legend}</legend>
    {options.map(option => (
      <label
        key={option.value}
        className={cn(
          'flex cursor-pointer items-start gap-3 rounded-control border px-3 py-2.5 transition-colors',
          value === option.value ? 'border-accent-line bg-accent-soft' : 'border-line hover:border-line-strong',
        )}>
        <input
          type="radio"
          name={name}
          className="mt-1"
          value={option.value}
          checked={value === option.value}
          onChange={() => onChange(option.value)}
          data-testid={testId ? `${testId}-${option.value}` : undefined}
        />
        <span className="min-w-0">
          <span className="block text-sm font-medium text-fg">{option.title}</span>
          <span className="block text-xs text-fg-subtle">{option.hint}</span>
        </span>
      </label>
    ))}
  </fieldset>
)
