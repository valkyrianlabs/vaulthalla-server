import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createResumeStore, RESUME_STORAGE_KEY, resumeKey, type KeyValueStorage } from './resumeStore.ts'

const memory = (): KeyValueStorage & { data: Map<string, string> } => {
  const data = new Map<string, string>()
  return { data, getItem: k => data.get(k) ?? null, setItem: (k, v) => void data.set(k, v), removeItem: k => void data.delete(k) }
}

test('records are keyed by source, path, size and lastModified', () => {
  assert.notEqual(resumeKey('vault:1', '/a', 10, 5), resumeKey('vault:2', '/a', 10, 5))
  assert.notEqual(resumeKey('vault:1', '/a', 10, 5), resumeKey('vault:1', '/a', 11, 5))
  assert.notEqual(resumeKey('vault:1', '/a', 10, 5), resumeKey('vault:1', '/a', 10, 6))
  assert.notEqual(resumeKey('vault:1', '/a|b', 10, 5), resumeKey('vault:1|/a', 'b', 10, 5))
})

test('put, get, remove, removeUpload and expiry', () => {
  const storage = memory()
  let now = 1000
  const store = createResumeStore(() => storage, () => now)
  const a = resumeKey('vault:1', '/a', 10, 1)
  const b = resumeKey('vault:1', '/b', 10, 1)
  store.put([
    [a, { upload_id: 'u1', file_id: 'f0', expires_at: 2000 }],
    [b, { upload_id: 'u2', file_id: 'f0', expires_at: null }],
  ])
  assert.deepEqual(store.get(a), { upload_id: 'u1', file_id: 'f0', expires_at: 2000 })
  now = 2500
  assert.equal(store.get(a), null)
  assert.ok(store.get(b))
  store.removeUpload('u2')
  assert.equal(store.get(b), null)
  assert.equal(storage.data.has(RESUME_STORAGE_KEY), false)
})

test('broken or missing storage never throws', () => {
  const throwing: KeyValueStorage = {
    getItem: () => {
      throw new Error('denied')
    },
    setItem: () => {
      throw new Error('quota')
    },
    removeItem: () => {
      throw new Error('denied')
    },
  }
  for (const storage of [() => null, () => throwing]) {
    const store = createResumeStore(storage, () => 0)
    store.put([['k', { upload_id: 'u', file_id: 'f', expires_at: null }]])
    assert.equal(store.get('k'), null)
    store.remove(['k'])
    store.removeUpload('u')
  }
  const garbage = memory()
  garbage.data.set(RESUME_STORAGE_KEY, '{not json')
  assert.equal(createResumeStore(() => garbage, () => 0).get('k'), null)
})
