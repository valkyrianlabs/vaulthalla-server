import { test } from 'node:test'
import assert from 'node:assert/strict'
import { activeOperation, canAbort, isRunning, lastError, phaseLabel, progressRatio, remoteSummaryLabel, type VaultRemoteStatus } from './vaultRemote.ts'

const base = (): VaultRemoteStatus =>
  ({
    vault_id: 4,
    vault_name: 'photos',
    type: 's3',
    remote: 'attached',
    attach: null,
    detach: null,
    progress: null,
    items: { files_pending: 0, files_sent: 0, files_failed: 0, envelopes: 0, metadata_objects: 0, orphans: 0 },
  }) as unknown as VaultRemoteStatus

const withDetach = (state: string, abortAsked = false): VaultRemoteStatus =>
  ({ ...base(), detach: { state, abort_requested_at: abortAsked ? 1 : null, last_error: state === 'failed' ? 'boom' : null } }) as unknown as VaultRemoteStatus

const withAttach = (state: string): VaultRemoteStatus =>
  ({ ...base(), type: 'local', attach: { state, abort_requested_at: null, last_error: null } }) as unknown as VaultRemoteStatus

test('the unfinished operation is the detach before the attach, and none once both ended', () => {
  assert.equal(activeOperation(null), null)
  assert.equal(activeOperation(base()), null)
  assert.equal(activeOperation(withAttach('uploading')), 'attach')
  assert.equal(activeOperation(withAttach('done')), null)
  assert.equal(activeOperation(withDetach('hydrating')), 'detach')
  assert.equal(activeOperation(withDetach('failed')), 'detach')
  assert.equal(activeOperation(withDetach('aborted')), null)
  const both = { ...withAttach('done'), detach: withDetach('verifying').detach } as VaultRemoteStatus
  assert.equal(activeOperation(both), 'detach')
})

test('a failed operation is not running but can be aborted; nothing after the cutover can', () => {
  assert.equal(isRunning(withDetach('failed')), false)
  assert.equal(canAbort(withDetach('failed')), true)
  assert.equal(lastError(withDetach('failed')), 'boom')
  assert.equal(isRunning(withDetach('cutover')), true)
  assert.equal(canAbort(withDetach('cutover')), false)
  assert.equal(canAbort(withDetach('hydrating', true)), false, 'an abort asked for already')
  assert.equal(canAbort(withAttach('catching_up')), true)
})

test('progress is never made up', () => {
  assert.equal(progressRatio(null), null)
  const p = { files_total: 0, files_done: 0, bytes_total: 0, bytes_done: 0 } as never
  assert.equal(progressRatio(p), null)
  assert.equal(progressRatio({ files_total: 4, files_done: 1, bytes_total: 0, bytes_done: 0 } as never), 0.25)
  assert.equal(progressRatio({ files_total: 4, files_done: 1, bytes_total: 200, bytes_done: 50 } as never), 0.25)
})

test('labels', () => {
  assert.equal(phaseLabel('hydrating'), 'Fetching and verifying the files on this server')
  assert.equal(phaseLabel('something-new'), 'something-new')
  assert.equal(remoteSummaryLabel('none'), 'Local storage only')
  assert.equal(remoteSummaryLabel('detaching:hydrating'), 'Detaching remote storage (fetching and verifying the files on this server)')
})
