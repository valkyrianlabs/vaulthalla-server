export interface FSEntry {
  id: number
  vault_id: number
  parent_id?: number
  name: string
  created_by: number
  created_at: number | string // Unix timestamp seconds, milliseconds, or ISO timestamp
  updated_at: number | string // Unix timestamp seconds, milliseconds, or ISO timestamp
  last_modified_by?: number
  path?: string
  // Opaque; changes on rename, move, mode change or an updated_at change (compare for equality only). Absent from
  // older daemons.
  metadata_version?: string
}

export type FSTimestampInput = number | string | Date | null | undefined

export interface FSEntryWireAliases {
  createdAt?: FSTimestampInput
  updatedAt?: FSTimestampInput
  modified_at?: FSTimestampInput
  modifiedAt?: FSTimestampInput
  last_modified?: FSTimestampInput
  lastModified?: FSTimestampInput
  last_modified_at?: FSTimestampInput
  lastModifiedAt?: FSTimestampInput
}

export type FSEntryWire<T extends Partial<FSEntry> = Partial<FSEntry>> = T & FSEntryWireAliases

const normalizeNumericTimestamp = (value: number) => {
  if (!Number.isFinite(value) || value <= 0) return 0
  return value > 1_000_000_000_000 ? Math.floor(value / 1000) : Math.floor(value)
}

export const normalizeFsTimestamp = (value: FSTimestampInput) => {
  if (value === null || value === undefined) return 0
  if (value instanceof Date) return normalizeNumericTimestamp(value.getTime())
  if (typeof value === 'number') return normalizeNumericTimestamp(value)

  const trimmed = value.trim()
  if (!trimmed) return 0
  if (/^\d+(\.\d+)?$/.test(trimmed)) return normalizeNumericTimestamp(Number(trimmed))

  const parsed = Date.parse(trimmed)
  return Number.isNaN(parsed) ? 0 : normalizeNumericTimestamp(parsed)
}

const firstValidFsTimestamp = (...values: FSTimestampInput[]) => {
  for (const value of values) {
    const normalized = normalizeFsTimestamp(value)
    if (normalized > 0) return normalized
  }
  return 0
}

export const normalizeFsEntryTimestamps = <T extends Partial<FSEntry>>(data?: FSEntryWire<T>): Partial<FSEntry> => {
  if (!data) return {}
  const {
    createdAt,
    updatedAt,
    modified_at,
    modifiedAt,
    last_modified,
    lastModified,
    last_modified_at,
    lastModifiedAt,
    ...entry
  } = data

  return {
    ...entry,
    created_at: firstValidFsTimestamp(data.created_at, createdAt),
    updated_at: firstValidFsTimestamp(
      data.updated_at,
      updatedAt,
      modified_at,
      modifiedAt,
      last_modified_at,
      lastModifiedAt,
      last_modified,
      lastModified
    ),
  }
}
