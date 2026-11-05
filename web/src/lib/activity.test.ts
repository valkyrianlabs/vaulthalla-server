import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ACTIVITY_EVENTS, createActivityReporter, trackActivity } from './activity.ts'

const settle = () => new Promise(resolve => setImmediate(resolve))

test('reports the first input at once, then at most once per interval', async () => {
  let clock = 0
  let sends = 0
  const reporter = createActivityReporter({ send: async () => void sends++, now: () => clock, intervalMs: 60_000 })
  reporter.onActivity()
  await settle()
  for (let i = 0; i < 100; i++) {
    clock += 500 // a busy minute of pointer movement
    reporter.onActivity()
    await settle()
  }
  assert.equal(sends, 1, 'one report for the first 50 s of input')
  clock = 60_000
  reporter.onActivity()
  await settle()
  assert.equal(sends, 2, 'a new report once the interval has passed')
})

test('no input, no reports: background traffic never counts', async () => {
  let sends = 0
  createActivityReporter({ send: async () => void sends++ })
  await settle()
  assert.equal(sends, 0)
})

test('a failed report is retried on the next input, and reports never overlap', async () => {
  let clock = 0
  let calls = 0
  let release: () => void = () => {}
  const reporter = createActivityReporter({
    now: () => clock,
    send: () => {
      calls++
      if (calls === 1) return Promise.reject(new Error('disconnected'))
      return new Promise<void>(resolve => (release = resolve))
    },
  })
  reporter.onActivity()
  await settle()
  clock += 1_000
  reporter.onActivity() // retried despite the interval: the first one never arrived
  await settle()
  assert.equal(calls, 2)
  clock += 120_000
  reporter.onActivity() // the second is still in flight
  await settle()
  assert.equal(calls, 2)
  release()
  await settle()
})

test('trackActivity listens for real input events and cleans up', async () => {
  const target = new EventTarget()
  let reports = 0
  const stop = trackActivity(target, { onActivity: () => void reports++ })
  for (const type of ACTIVITY_EVENTS) target.dispatchEvent(new Event(type))
  target.dispatchEvent(new Event('message')) // not input
  assert.equal(reports, ACTIVITY_EVENTS.length)
  stop()
  target.dispatchEvent(new Event('keydown'))
  assert.equal(reports, ACTIVITY_EVENTS.length)
})
