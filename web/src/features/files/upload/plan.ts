// Part planning for resumable uploads (docs/reference/transfer-protocol.md §3). Pure: no DOM, no network, so
// `node --test` runs it as is (see plan.test.ts). Ranges are half-open [start, end) byte offsets.

export type Range = readonly [number, number]

export interface PartLimits {
  default_bytes: number
  min_bytes: number
  max_bytes: number
  max_in_flight: number
}

export interface Part {
  offset: number
  length: number
}

// Cloudflare refuses request bodies of 100 MB (decimal) and more; the web listener's part cap keeps parts below it,
// and the client asserts it again before every request.
export const REQUEST_BODY_LIMIT = 100_000_000
// The browser never sends parts above 64 MiB, whatever a server advertises: it bounds memory (each in-flight part
// is held as an ArrayBuffer) and stays under the body limit above.
export const CLIENT_MAX_PART = 64 * 1024 * 1024
export const CLIENT_MAX_IN_FLIGHT = 3

const positive = (value: unknown): number | null => (typeof value === 'number' && Number.isFinite(value) && value > 0 ? Math.floor(value) : null)

// The largest part this client sends to this server: its max, the client cap and the body limit, whichever is lowest.
export const maxPartSize = (part: PartLimits): number => Math.min(positive(part.max_bytes) ?? CLIENT_MAX_PART, CLIENT_MAX_PART, REQUEST_BODY_LIMIT - 1)

// The part size: the server's default, never above maxPartSize, never below the server's min.
export const choosePartSize = (part: PartLimits): number => {
  const max = maxPartSize(part)
  const min = Math.min(positive(part.min_bytes) ?? 1, max)
  const wanted = positive(part.default_bytes) ?? max
  return Math.max(min, Math.min(wanted, max))
}

export const partsInFlight = (part: PartLimits): number => Math.max(1, Math.min(CLIENT_MAX_IN_FLIGHT, positive(part.max_in_flight) ?? 1))

// Sorted, coalesced copy of `ranges` clipped to [0, size). Tolerates unsorted, overlapping or malformed input.
export const normalizeRanges = (ranges: readonly (readonly number[])[], size: number): Range[] => {
  const clean = ranges
    .filter(r => Array.isArray(r) && r.length === 2 && Number.isFinite(r[0]) && Number.isFinite(r[1]))
    .map(([start, end]) => [Math.max(0, start), Math.min(size, end)] as [number, number])
    .filter(([start, end]) => end > start)
    .sort((a, b) => a[0] - b[0])
  const out: [number, number][] = []
  for (const [start, end] of clean) {
    const last = out.at(-1)
    if (last && start <= last[1]) last[1] = Math.max(last[1], end)
    else out.push([start, end])
  }
  return out
}

export const mergeRanges = (a: readonly Range[], b: readonly Range[], size: number): Range[] => normalizeRanges([...a, ...b], size)

export const coveredBytes = (ranges: readonly Range[]): number => ranges.reduce((sum, [start, end]) => sum + (end - start), 0)

// The byte ranges of [0, size) not covered by `ranges` (what a resuming client sends).
export const gapsOf = (ranges: readonly (readonly number[])[], size: number): Range[] => {
  const gaps: Range[] = []
  let cursor = 0
  for (const [start, end] of normalizeRanges(ranges, size)) {
    if (start > cursor) gaps.push([cursor, start])
    cursor = Math.max(cursor, end)
  }
  if (cursor < size) gaps.push([cursor, size])
  return gaps
}

export interface PartPlan {
  parts: Part[]
  // A gap that no legal sequence of parts can fill: shorter than min_bytes and not ending at the end of the file
  // (only possible when the stored parts came from a client with other part boundaries). The file has to start over.
  unsendable: boolean
}

// Splits every gap into parts of `partSize` (the last part of a gap may be shorter). Only a part ending at the end
// of the file may be shorter than `min`; a shorter tail elsewhere is merged into the part before it (when that stays
// within `max`) or the last two parts are split evenly.
export const planParts = (gaps: readonly Range[], size: number, partSize: number, min: number, max: number): PartPlan => {
  const parts: Part[] = []
  let unsendable = false
  for (const [start, end] of gaps) {
    const gap: Part[] = []
    for (let offset = start; offset < end; offset += partSize) gap.push({ offset, length: Math.min(partSize, end - offset) })
    const tail = gap.at(-1)
    if (tail && tail.length < min && tail.offset + tail.length !== size) {
      const before = gap.length > 1 ? gap[gap.length - 2] : null
      if (!before) {
        unsendable = true
        continue
      }
      const joined = before.length + tail.length
      gap.pop()
      if (joined <= max) before.length = joined
      else {
        const first = Math.ceil(joined / 2)
        if (joined - first < min) {
          unsendable = true
          continue
        }
        before.length = first
        gap.push({ offset: before.offset + first, length: joined - first })
      }
    }
    parts.push(...gap)
  }
  return { parts, unsendable }
}

// Throws when a part would break the protocol's rules or the proxy body limit (a bug, never a server answer).
export const assertPart = (part: Part, size: number, limits: Pick<PartLimits, 'min_bytes' | 'max_bytes'>) => {
  const { offset, length } = part
  if (!(length > 0) || offset < 0 || offset + length > size) throw new Error(`Invalid part ${offset}+${length} of ${size}`)
  if (length >= REQUEST_BODY_LIMIT) throw new Error(`Part of ${length} bytes exceeds the ${REQUEST_BODY_LIMIT} byte request limit`)
  if (length > limits.max_bytes) throw new Error(`Part of ${length} bytes exceeds the server's ${limits.max_bytes} byte limit`)
  if (length < limits.min_bytes && offset + length !== size) throw new Error(`Part of ${length} bytes is below the server's ${limits.min_bytes} byte minimum`)
}
