'use client'

import React from 'react'
import { Field, Input, Select, Textarea } from '@/components/ui/Field'
import { SwitchRow } from '@/components/ui/Choice'
import { Badge } from '@/components/ui/Badge'
import { titleCase } from '@/lib/format'
import { BYTE_UNITS, ScaledInput, TagInput, UnitInput, isDecimal } from '@/features/settings/controls'
import { LOG_LEVELS, type FieldDef, type FieldKind } from '@/features/settings/schema'
import { parseDuration, parseInterval, parseSize, type Json } from '@/features/settings/patch'

const MB_UNITS = [
  { label: 'MB', factor: 1 },
  { label: 'GB', factor: 1024 },
  { label: 'TB', factor: 1024 * 1024 },
]

const num = (v: Json | undefined) => (typeof v === 'number' && Number.isFinite(v) ? v : null)
const text = (v: Json | undefined) =>
  typeof v === 'string' ? v
  : v === null || v === undefined ? ''
  : String(v)

// Returns an error message for an invalid value, or null.
export const validate = (type: FieldKind, value: Json | undefined): string | null => {
  switch (type.kind) {
    case 'int': {
      const n = num(value)
      if (n === null || !Number.isInteger(n)) return 'Enter a whole number'
      if (type.min !== undefined && n < type.min) return `At least ${type.min}`
      if (type.max !== undefined && n > type.max) return `At most ${type.max}`
      return null
    }
    case 'port': {
      const n = num(value)
      return n === null || !Number.isInteger(n) || n < 1 || n > 65535 ? 'Use a port from 1 to 65535' : null
    }
    case 'bytes':
    case 'megabytes':
      return num(value) === null || (num(value) as number) <= 0 ? 'Enter a size' : null
    case 'sizeString':
      return parseSize(value) ? null : 'Enter a size in MB or GB'
    case 'intervalString':
      return parseInterval(value) ? null : 'Enter hours or days'
    case 'durationString':
      return parseDuration(value) ? null : 'Enter a duration'
    case 'decimal':
      return typeof value === 'string' && isDecimal(value) ? null : 'Use a plain decimal, e.g. 0.00000001'
    case 'text':
      return text(value).trim() ? null : 'Required'
    default:
      return null
  }
}

const SplitUnit = ({
  id,
  amount,
  unit,
  units,
  onChange,
  invalid,
}: {
  id: string
  amount: number | null
  unit: string
  units: { value: string; label: string }[]
  onChange: (amount: number | null, unit: string) => void
  invalid?: boolean
}) => (
  <div className="flex">
    <Input
      id={id}
      type="number"
      min={1}
      inputMode="numeric"
      value={amount ?? ''}
      aria-invalid={invalid || undefined}
      onChange={e => onChange(e.target.value.trim() === '' ? null : Number(e.target.value), unit)}
      className="tabular rounded-r-none"
    />
    <select
      aria-label="Unit"
      value={unit}
      onChange={e => onChange(amount, e.target.value)}
      className="rounded-r-control border-line-strong bg-surface-2 text-fg-muted focus:border-accent-line h-9 border border-l-0 px-2 text-xs focus:outline-none">
      {units.map(u => (
        <option key={u.value} value={u.value}>
          {u.label}
        </option>
      ))}
    </select>
  </div>
)

export const SettingField = ({
  id,
  def,
  value,
  changed,
  onChange,
}: {
  id: string
  def: FieldDef
  value: Json | undefined
  changed: boolean
  onChange: (value: Json) => void
}) => {
  const type = def.type
  const error = validate(type, value)
  const label = (
    <span className="inline-flex items-center gap-2">
      {def.label}
      {def.restart ?
        <Badge tone="neutral" className="h-5 px-1.5 text-[10px]">
          restart
        </Badge>
      : null}
      {changed ?
        <span className="bg-accent size-1.5 rounded-full" title="Changed" aria-label="Changed" />
      : null}
    </span>
  )

  if (type.kind === 'bool')
    return (
      <div className="sm:col-span-2">
        <SwitchRow id={id} label={label} hint={def.hint} checked={value === true} onCheckedChange={v => onChange(v)} />
      </div>
    )

  const control = (() => {
    switch (type.kind) {
      case 'int':
        return (
          <UnitInput
            id={id}
            unit={type.unit}
            min={type.min}
            max={type.max}
            value={num(value)}
            onChange={v => onChange(v)}
            invalid={Boolean(error)}
          />
        )
      case 'port':
        return (
          <UnitInput
            id={id}
            min={1}
            max={65535}
            value={num(value)}
            onChange={v => onChange(v)}
            invalid={Boolean(error)}
          />
        )
      case 'text':
        return (
          <Input
            id={id}
            value={text(value)}
            onChange={e => onChange(e.target.value)}
            placeholder={type.placeholder}
            className={type.mono ? 'font-mono' : undefined}
            aria-invalid={Boolean(error) || undefined}
          />
        )
      case 'optionalText':
        return (
          <Input
            id={id}
            value={text(value)}
            onChange={e => onChange(e.target.value.trim() ? e.target.value : null)}
            placeholder={type.placeholder}
            className={type.mono ? 'font-mono' : undefined}
          />
        )
      case 'enum': {
        const current = text(value)
        const known = type.options.some(o => o.value === current)
        return (
          <Select id={id} value={current} onChange={e => onChange(e.target.value)}>
            {!known && current ?
              <option value={current}>{current}</option>
            : null}
            {type.options.map(o => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </Select>
        )
      }
      case 'bytes':
        return (
          <ScaledInput
            id={id}
            value={num(value)}
            onChange={v => onChange(v)}
            units={BYTE_UNITS}
            invalid={Boolean(error)}
          />
        )
      case 'megabytes':
        return (
          <ScaledInput
            id={id}
            value={num(value)}
            onChange={v => onChange(v)}
            units={MB_UNITS}
            invalid={Boolean(error)}
          />
        )
      case 'sizeString': {
        const parsed = parseSize(value)
        return (
          <SplitUnit
            id={id}
            amount={parsed?.amount ?? null}
            unit={parsed?.unit ?? 'MB'}
            units={[
              { value: 'MB', label: 'MB' },
              { value: 'GB', label: 'GB' },
            ]}
            invalid={Boolean(error)}
            onChange={(amount, unit) => onChange(amount === null ? '' : `${Math.max(0, Math.round(amount))}${unit}`)}
          />
        )
      }
      case 'intervalString': {
        const parsed = parseInterval(value)
        return (
          <SplitUnit
            id={id}
            amount={parsed?.amount ?? null}
            unit={parsed?.unit ?? 'h'}
            units={[
              { value: 'h', label: 'hours' },
              { value: 'd', label: 'days' },
            ]}
            invalid={Boolean(error)}
            onChange={(amount, unit) => onChange(amount === null ? '' : `${Math.max(0, Math.round(amount))}${unit}`)}
          />
        )
      }
      case 'durationString': {
        const parsed = parseDuration(value)
        return (
          <SplitUnit
            id={id}
            amount={parsed?.amount ?? null}
            unit={parsed?.unit ?? 'd'}
            units={[
              { value: 's', label: 'seconds' },
              { value: 'm', label: 'minutes' },
              { value: 'h', label: 'hours' },
              { value: 'd', label: 'days' },
              { value: 'w', label: 'weeks' },
            ]}
            invalid={Boolean(error)}
            onChange={(amount, unit) => onChange(amount === null ? '' : `${Math.max(0, Math.round(amount))}${unit}`)}
          />
        )
      }
      case 'decimal':
        return (
          <div className="relative">
            <Input
              id={id}
              inputMode="decimal"
              value={text(value)}
              onChange={e => onChange(e.target.value)}
              className="tabular pr-14"
              aria-invalid={Boolean(error) || undefined}
            />
            {type.unit ?
              <span className="text-fg-subtle pointer-events-none absolute top-1/2 right-3 -translate-y-1/2 font-mono text-xs">
                {type.unit}
              </span>
            : null}
          </div>
        )
      case 'tags': {
        const list = Array.isArray(value) ? value.map(v => String(v)) : []
        return (
          <TagInput
            id={id}
            value={list}
            mono={type.mono}
            placeholder={type.numeric ? 'Add a number…' : 'Add…'}
            validate={type.numeric ? item => (/^\d+$/.test(item) ? null : 'Whole numbers only') : undefined}
            onChange={items => onChange(type.numeric ? items.map(Number) : items)}
          />
        )
      }
      case 'lines': {
        const list = Array.isArray(value) ? value.map(v => String(v)) : []
        return (
          <Textarea
            id={id}
            rows={Math.max(2, list.length + 1)}
            value={list.join('\n')}
            placeholder={type.placeholder}
            onChange={e =>
              onChange(
                e.target.value
                  .split('\n')
                  .map(l => l.trim())
                  .filter(Boolean),
              )
            }
            className="font-mono text-xs"
          />
        )
      }
      case 'logLevel': {
        const n = num(value)
        return (
          <Select id={id} value={n ?? ''} onChange={e => onChange(Number(e.target.value))}>
            {n === null ?
              <option value="">Unknown</option>
            : null}
            {LOG_LEVELS.map((name, i) => (
              <option key={name} value={i}>
                {titleCase(name)}
              </option>
            ))}
          </Select>
        )
      }
    }
  })()

  const hint =
    changed && def.changeWarning ? <span className="text-warn">{def.changeWarning}</span> : def.hint
  return (
    <Field
      label={label}
      htmlFor={id}
      hint={hint}
      error={error ?? undefined}
      className={type.kind === 'lines' || type.kind === 'tags' ? 'sm:col-span-2' : undefined}>
      {control}
    </Field>
  )
}

// A key the schema doesn't know: render by its JSON type so it still round-trips.
export const genericDef = (key: string, value: Json | undefined): FieldDef | null => {
  const label = titleCase(key)
  if (typeof value === 'boolean') return { key, label, type: { kind: 'bool' } }
  if (typeof value === 'number') return { key, label, type: { kind: 'int' } }
  if (typeof value === 'string') return { key, label, type: { kind: 'optionalText' } }
  if (value === null) return { key, label, type: { kind: 'optionalText', placeholder: 'Not set' } }
  if (Array.isArray(value))
    return { key, label, type: { kind: 'tags', numeric: value.every(v => typeof v === 'number') && value.length > 0 } }
  return null
}
