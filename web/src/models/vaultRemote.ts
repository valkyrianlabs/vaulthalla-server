// Remote storage of a vault (design/storage/attach-remote.md): attaching a bucket to a local vault, and detaching it
// from an S3 vault again. The daemon runs both in the background (vault.remote.attach / vault.remote.detach start
// them, vault.remote.status follows them, vault.remote.abort ends one before its cutover); the console only renders
// what the status says. Core: ops/VaultRemote.hpp, vault/RemoteAttach.hpp, vault/RemoteDetach.hpp.

import type { WsModels } from '../util/generated/wsContract.ts'

export type VaultRemoteStatus = WsModels['VaultRemoteStatus']
export type VaultRemoteProgress = WsModels['VaultRemoteProgress']

export type RemoteOperation = 'attach' | 'detach'

const ATTACH_RUNNING = new Set(['preparing', 'uploading', 'catching_up', 'verifying', 'cutover'])
const DETACH_RUNNING = new Set(['preparing', 'hydrating', 'verifying', 'cutover'])
const BEFORE_CUTOVER = new Set(['preparing', 'uploading', 'catching_up', 'hydrating', 'verifying', 'failed'])

// The operation that is unfinished (running, or failed and resumable), if any: the detach wins, as on the server.
export const activeOperation = (s: VaultRemoteStatus | null | undefined): RemoteOperation | null => {
  if (!s) return null
  if (s.detach && (DETACH_RUNNING.has(s.detach.state) || s.detach.state === 'failed')) return 'detach'
  if (s.attach && (ATTACH_RUNNING.has(s.attach.state) || s.attach.state === 'failed')) return 'attach'
  return null
}

// Something runs in the background: the status is worth polling.
export const isRunning = (s: VaultRemoteStatus | null | undefined): boolean => {
  const op = activeOperation(s)
  if (op === 'detach') return DETACH_RUNNING.has(s!.detach!.state)
  if (op === 'attach') return ATTACH_RUNNING.has(s!.attach!.state)
  return false
}

// An abort is possible: before the cutover, and not asked for already.
export const canAbort = (s: VaultRemoteStatus | null | undefined): boolean => {
  const op = activeOperation(s)
  const row = op === 'detach' ? s?.detach : op === 'attach' ? s?.attach : null
  return Boolean(row && BEFORE_CUTOVER.has(row.state) && row.abort_requested_at === null)
}

export const lastError = (s: VaultRemoteStatus | null | undefined): string | null => {
  const op = activeOperation(s)
  if (op === 'detach') return s?.detach?.last_error ?? null
  if (op === 'attach') return s?.attach?.last_error ?? null
  return null
}

const PHASES: Readonly<Record<string, string>> = {
  preparing: 'Checking the vault and the bucket',
  uploading: 'Uploading the files',
  catching_up: 'Sending what changed meanwhile',
  hydrating: 'Fetching and verifying the files on this server',
  verifying: 'Verifying',
  cutover: 'Switching over',
  done: 'Done',
  failed: 'Stopped',
  aborted: 'Aborted',
}

export const phaseLabel = (phase: string | null | undefined): string => (phase && PHASES[phase]) || phase || 'Unknown'

// The share of the work done (files by bytes), or null while it is unknown: never a made-up 0 %.
export const progressRatio = (p: VaultRemoteProgress | null | undefined): number | null => {
  if (!p || p.bytes_total <= 0) return p && p.files_total > 0 ? p.files_done / p.files_total : null
  return Math.min(1, p.bytes_done / p.bytes_total)
}

export type VaultRemoteAccess = WsModels['VaultRemoteAccess']

// An S3 vault's remote access gate, in words; null while it is full (nothing to say).
export const accessNotice = (access: VaultRemoteAccess | null | undefined): string | null => {
  if (!access || access.mode === 'full') return null
  const why = access.reason ? ` (${access.reason})` : ''
  if (access.mode === 'read_only')
    return `Read-only${why}: files are read and fetched as before, but nothing is uploaded, deleted or published to the bucket. Changes made here wait and go up once access is full again.`
  return `Unavailable${why}: no request goes to the bucket. Files with a copy on this server keep working; files without one can’t be opened.`
}

// What the remote summary of storage.vault.get says, in words.
export const remoteSummaryLabel = (remote: string | null | undefined): string => {
  if (!remote || remote === 'none') return 'Local storage only'
  if (remote === 'attached') return 'Remote storage attached'
  if (remote.startsWith('attaching:')) return `Attaching remote storage (${phaseLabel(remote.slice(10)).toLowerCase()})`
  if (remote.startsWith('detaching:')) return `Detaching remote storage (${phaseLabel(remote.slice(10)).toLowerCase()})`
  return remote
}
