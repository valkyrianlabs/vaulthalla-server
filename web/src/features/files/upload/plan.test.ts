import { test } from 'node:test'
import assert from 'node:assert/strict'
import { assertPart, choosePartSize, CLIENT_MAX_PART, gapsOf, maxPartSize, mergeRanges, normalizeRanges, partsInFlight, planParts, REQUEST_BODY_LIMIT, type Part } from './plan.ts'

const MiB = 1024 * 1024
const limits = (over: Partial<{ default_bytes: number; min_bytes: number; max_bytes: number; max_in_flight: number }> = {}) => ({
  default_bytes: 64 * MiB,
  min_bytes: MiB,
  max_bytes: 64 * MiB,
  max_in_flight: 4,
  ...over,
})

// Every part list must tile the gaps exactly, in order, with legal sizes.
const checkTiling = (parts: Part[], gaps: [number, number][], size: number, min: number, max: number) => {
  let i = 0
  for (const [start, end] of gaps) {
    let cursor = start
    while (cursor < end) {
      const part = parts[i++]
      assert.ok(part, `missing part at ${cursor}`)
      assert.equal(part.offset, cursor)
      assert.ok(part.length > 0 && part.length <= max, `length ${part.length} within max`)
      if (part.offset + part.length !== size) assert.ok(part.length >= min, `length ${part.length} >= min`)
      cursor += part.length
    }
    assert.equal(cursor, end)
  }
  assert.equal(i, parts.length)
}

test('part size follows the server default within its bounds and the client cap', () => {
  assert.equal(choosePartSize(limits()), 64 * MiB)
  assert.equal(choosePartSize(limits({ default_bytes: 8 * MiB })), 8 * MiB)
  // Device-listener style limits: never above 64 MiB in the browser.
  assert.equal(choosePartSize(limits({ default_bytes: 256 * MiB, max_bytes: 512 * MiB })), CLIENT_MAX_PART)
  // A lower HTTP max wins.
  assert.equal(choosePartSize(limits({ default_bytes: 64 * MiB, max_bytes: 16 * MiB })), 16 * MiB)
  // Never below min.
  assert.equal(choosePartSize(limits({ default_bytes: 1000, min_bytes: 2 * MiB })), 2 * MiB)
  // Missing default: the max.
  assert.equal(choosePartSize(limits({ default_bytes: 0, max_bytes: 32 * MiB })), 32 * MiB)
  assert.ok(maxPartSize(limits({ max_bytes: 4 * 1024 * MiB })) < REQUEST_BODY_LIMIT)
})

test('in-flight parts are min(3, max_in_flight), at least 1', () => {
  assert.equal(partsInFlight(limits()), 3)
  assert.equal(partsInFlight(limits({ max_in_flight: 2 })), 2)
  assert.equal(partsInFlight(limits({ max_in_flight: 0 })), 1)
  assert.equal(partsInFlight(limits({ max_in_flight: 16 })), 3)
})

test('ranges normalize: sorted, coalesced, clipped', () => {
  assert.deepEqual(normalizeRanges([[10, 20], [0, 5], [5, 8], [18, 30], [40, 40], [90, 200]], 100), [[0, 8], [10, 30], [90, 100]])
  assert.deepEqual(mergeRanges([[0, 10]], [[10, 20]], 100), [[0, 20]])
})

test('gaps are the complement of the stored ranges', () => {
  assert.deepEqual(gapsOf([], 100), [[0, 100]])
  assert.deepEqual(gapsOf([[0, 100]], 100), [])
  assert.deepEqual(gapsOf([[0, 536870912], [1073741824, 1610612736]], 2147483648), [
    [536870912, 1073741824],
    [1610612736, 2147483648],
  ])
  assert.deepEqual(gapsOf([[20, 30]], 50), [[0, 20], [30, 50]])
  assert.deepEqual(gapsOf([], 0), [])
})

test('a fresh file splits into full parts and a short last part', () => {
  const size = 200 * MiB + 123
  const { parts, unsendable } = planParts([[0, size]], size, 64 * MiB, MiB, 64 * MiB)
  assert.equal(unsendable, false)
  assert.deepEqual(parts.map(p => p.length), [64 * MiB, 64 * MiB, 64 * MiB, 8 * MiB + 123])
  checkTiling(parts, [[0, size]], size, MiB, 64 * MiB)
})

test('a file smaller than min_bytes is one (last) part', () => {
  const { parts, unsendable } = planParts([[0, 1200]], 1200, 64 * MiB, MiB, 64 * MiB)
  assert.equal(unsendable, false)
  assert.deepEqual(parts, [{ offset: 0, length: 1200 }])
})

test('a short tail before stored bytes is merged or rebalanced, never below min', () => {
  const size = 300 * MiB
  // Gap of 64 MiB + 100 bytes ending where stored bytes start: a 100-byte tail would be illegal.
  const gap: [number, number] = [0, 64 * MiB + 100]
  const merged = planParts([gap], size, 32 * MiB, MiB, 64 * MiB)
  checkTiling(merged.parts, [gap], size, MiB, 64 * MiB)
  const halves = planParts([gap], size, 64 * MiB, MiB, 64 * MiB)
  assert.equal(halves.unsendable, false)
  checkTiling(halves.parts, [gap], size, MiB, 64 * MiB)
  assert.equal(halves.parts.length, 2)
})

test('a mid-file gap below min_bytes is unsendable', () => {
  const size = 10 * MiB
  const plan = planParts([[MiB, MiB + 10]], size, 4 * MiB, MiB, 4 * MiB)
  assert.equal(plan.unsendable, true)
  assert.equal(plan.parts.length, 0)
  // ...but at the end of the file it is the last part.
  assert.equal(planParts([[size - 10, size]], size, 4 * MiB, MiB, 4 * MiB).unsendable, false)
})

test('random gap layouts always tile legally', () => {
  let seed = 7
  const rand = () => ((seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31)
  for (let round = 0; round < 300; round++) {
    const min = 1 + Math.floor(rand() * 1000)
    const partSize = min + Math.floor(rand() * 5000)
    const max = partSize + Math.floor(rand() * 3000)
    const size = 1 + Math.floor(rand() * 50000)
    const stored: [number, number][] = []
    for (let i = 0; i < 5; i++) {
      const start = Math.floor(rand() * size)
      stored.push([start, Math.min(size, start + Math.floor(rand() * 8000))])
    }
    const gaps = gapsOf(stored, size) as [number, number][]
    const plan = planParts(gaps, size, partSize, min, max)
    if (plan.unsendable) continue
    checkTiling(plan.parts, gaps, size, min, max)
    for (const part of plan.parts) assertPart(part, size, { min_bytes: min, max_bytes: max })
  }
})

test('assertPart enforces the protocol rules and the 100 MB body limit', () => {
  const l = { min_bytes: MiB, max_bytes: 512 * MiB }
  assert.throws(() => assertPart({ offset: 0, length: REQUEST_BODY_LIMIT }, 10 ** 9, l), /request limit/)
  assert.throws(() => assertPart({ offset: 0, length: 10 }, 100, l), /minimum/)
  assert.doesNotThrow(() => assertPart({ offset: 90, length: 10 }, 100, l))
  assert.throws(() => assertPart({ offset: 95, length: 10 }, 100, l), /Invalid/)
  assert.throws(() => assertPart({ offset: 0, length: 0 }, 100, l), /Invalid/)
})
