// Mirrored vaults (design/peers/mirror.md; ws mirror.*, ops::mirrors): the pure parts of the console's pages. What a
// vault's role and state read as, the advice for what can be done next, which actions apply to which role and state,
// held changes in words, and the refusals that mean "linked servers are off". Pure: see model.test.ts. Imports by
// relative path with the .ts extension (node --test).
import type { Response } from '@/lib/ws/client'
import { MIRROR_COPY as C } from './copy.ts'

export type MirroredVault = Response<'mirror.list'>['vaults'][number]
export type MirrorRole = MirroredVault['role']
export type MirrorState = NonNullable<MirroredVault['state']>
export type MirrorOffer = Response<'mirror.pending'>['offers'][number]
export type MirrorStart = NonNullable<MirroredVault['start']>
export type HeldChange = Response<'mirror.held.list'>['held'][number]
export type DetachPreview = Response<'mirror.detach.preview'>['preview']
export type SwitchResult = Response<'mirror.switch'>
export type Tone = 'ok' | 'info' | 'warn' | 'danger' | 'neutral' | 'unknown'

// Every read a mirror change can affect.
export const MIRROR_READS = ['mirror.list', 'mirror.get', 'mirror.pending', 'mirror.held.list', 'mirror.detach.preview'] as const

// ---- the switch: linked servers off

// Every mirror.* command refuses peers_experimental while peers.experimental is off (ops::peers gate).
export const PEERS_OFF_CODES: readonly string[] = ['peers_experimental', 'mirror_peers_off']
export const isPeersOff = (error: unknown): boolean => {
  const code = error && typeof error === 'object' ? (error as { code?: unknown }).code : undefined
  return typeof code === 'string' && PEERS_OFF_CODES.includes(code)
}

// ---- names

export const peerName = (row: Pick<MirroredVault, 'peer'>) => row.peer?.name || (row.peer ? C.unnamedServer : C.noServer)

export const ROLE_TEXT: Readonly<Record<MirrorRole, { label: string; tone: Tone }>> = {
  core: { label: 'Core', tone: 'info' },
  mirror: { label: 'Mirror', tone: 'info' },
  orphaned: { label: 'Orphaned copy', tone: 'warn' },
  starting: { label: 'Starting', tone: 'info' },
  detached: { label: 'Detached', tone: 'neutral' },
  none: { label: 'Not mirrored', tone: 'neutral' },
}

// "This server's role" in one sentence, with the other server's name.
export const roleSentence = (row: Pick<MirroredVault, 'role' | 'peer' | 'start'>): string => {
  const peer = peerName(row)
  switch (row.role) {
    case 'core':
      return C.roleCore(peer)
    case 'mirror':
      return C.roleMirror(peer)
    case 'orphaned':
      return C.roleOrphaned(peer)
    case 'starting':
      return row.start?.side === 'mirror' ? C.roleStartingMirror(peer) : C.roleStartingCore(peer)
    case 'detached':
      return C.roleDetached
    default:
      return C.roleNone
  }
}

// ---- reasons

// The stop and read-only reasons the server records (mirror/access/Access.hpp, the mirror's stop reasons), in words.
// Anything else falls back to the generic sentence of the state with the code beside it.
export const REASON_TEXT: Readonly<Record<string, string>> = {
  mirror_link_down: 'the link to the other server is down',
  mirror_paused: 'the mirror is paused',
  mirror_core_deleting: 'its core is deleting the vault',
  mirror_switching: 'the core role is moving between the two servers',
  mirror_diverged: 'the two copies stopped matching',
  mirror_core_diverged: 'the core found that the two copies stopped matching',
  mirror_digest_mismatch: 'the two copies stopped matching',
  mirror_scrub_mismatch: 'a check found a file that differs from the core’s',
  mirror_copy_mismatch: 'the first copy did not match the core’s files',
  mirror_revert_mismatch: 'a change made here could not be undone cleanly',
  mirror_settle_moved_digest: 'the copies stopped matching while a change was being confirmed',
  mirror_expired: 'the core no longer keeps the changes this copy missed',
  mirror_log_expired: 'the core no longer keeps the changes this copy missed',
  mirror_log_chain: 'the core’s list of changes had a gap',
  mirror_group_gap: 'the core’s list of changes had a gap',
  mirror_copy_gap: 'the first copy had a gap',
  mirror_term_changed: 'the core started a new term',
  mirror_log_malformed: 'the core sent changes this server could not read',
  mirror_tree_malformed: 'the core sent a file list this server could not read',
  mirror_unknown_op: 'the core sent a change this server does not understand',
  mirror_type_mismatch: 'an entry is a file on one server and a folder on the other',
  mirror_entry_missing: 'an entry the core changed is missing here',
  mirror_entry_unrecorded: 'an entry the core changed was never recorded here',
  mirror_content_unexpected: 'the core sent contents this server did not expect',
  mirror_fetch_failed: 'a file’s contents could not be fetched from the core',
  mirror_fetch_timeout: 'fetching a file’s contents from the core timed out',
  mirror_contents_missing: 'some files’ contents never arrived',
  mirror_hash: 'a file’s contents did not match their checksum',
  mirror_key_missing: 'a key this vault needs is missing here',
  mirror_keys_refused: 'the vault’s keys were refused',
  mirror_keys_unproven: 'the vault’s keys could not be proven',
  mirror_vault_root_missing: 'the vault’s folder is missing on this server',
  mirror_vault_engine_missing: 'the vault is not loaded on this server',
  mirror_resync_failed: 'starting the copy over failed',
  mirror_resync_refused: 'the core refused to start the copy over',
  mirror_core_gone: 'the core no longer has the vault',
  mirror_gone: 'the other server no longer has the vault',
  mirror_core_unreachable: 'the core could not be reached',
  mirror_orphaned: 'its core ended the mirror',
  mirror_first_copy: 'the first copy is not finished',
  mirror_stopped: 'the mirror stopped',
  mirror_peers_off: 'linked servers are switched off on this server',
}

export const reasonText = (code: string | null | undefined): string | null => {
  if (!code) return null
  return REASON_TEXT[code] ?? null
}

// ---- status

export interface StatusText {
  label: string
  tone: Tone
  // One or two plain sentences: what it means here.
  sentence: string
  // The stop reason's code when the sentence is generic (shown small beside it).
  code: string | null
}

export interface StatusFacts {
  // Whether the link to the vault's other server is up (peer.list health); null while unknown.
  linkUp: boolean | null
  // The detail view's preview of a held copy (mirror.detach.preview): the first copy's progress.
  firstCopy?: DetachPreview['first_copy'] | null
  date: (unix: number) => string
}

const deletingCopy = (d: NonNullable<MirroredVault['deleting']>): 'removed' | 'kept' => {
  const here = (d.here ?? '').toLowerCase()
  if (here.includes('kept') || here.includes('orphan') || here.includes('leave')) return 'kept'
  if (here.includes('remov')) return 'removed'
  return d.copy === 'remove' ? 'removed' : 'kept'
}

const startStatus = (row: MirroredVault, peer: string): StatusText => {
  const s = row.start
  const why = s?.reason ? reasonText(s.reason) ?? s.reason : s?.last_error ?? null
  const ours = s?.side === 'mirror'
  const base = { code: null as string | null }
  switch (s?.state) {
    case 'offered':
    case 'pending':
      return ours ?
          { ...base, label: C.stWaitingYou, tone: 'warn', sentence: C.stWaitingYouBody(peer) }
        : { ...base, label: C.stWaitingThem, tone: 'info', sentence: C.stWaitingThemBody(peer) }
    case 'accepted':
    case 'keys_acked':
      return { ...base, label: C.stKeys, tone: 'info', sentence: C.stKeysBody }
    case 'installed':
    case 'started':
      return { ...base, label: C.stStarting, tone: 'info', sentence: C.stStartingBody }
    case 'declined':
      return { ...base, label: C.stDeclined, tone: 'danger', sentence: ours ? C.stDeclinedHere : C.stDeclinedBody(peer) }
    case 'cancelled':
      return { ...base, label: C.stCancelled, tone: 'neutral', sentence: C.stCancelledBody }
    case 'expired':
      return { ...base, label: C.stOfferExpired, tone: 'warn', sentence: C.stOfferExpiredBody(peer) }
    case 'failed':
      return { label: C.stFailed, tone: 'danger', sentence: C.stFailedBody(why), code: s?.reason ?? null }
    default:
      return { ...base, label: C.stStarting, tone: 'info', sentence: C.stStartingBody }
  }
}

// A mirrored vault's state with its reason, in words (mirror.list / mirror.get row). Read-only is said as such, never
// guessed healthy: a mirror whose link is down is read-only (mirror::access readOnlyReason).
export const statusText = (row: MirroredVault, facts: StatusFacts): StatusText => {
  const peer = peerName(row)
  const none = { code: null as string | null }
  if (row.role === 'starting') return startStatus(row, peer)
  if (row.role === 'detached') {
    const theirs = row.detached?.side === 'core'
    return { ...none, label: C.stDetached, tone: 'neutral', sentence: theirs ? C.stDetachedThere(peer) : C.stDetachedHere(peer) }
  }
  if (row.role === 'none') return { ...none, label: C.stNone, tone: 'neutral', sentence: C.stNoneBody }

  if (row.deleting?.deleting) {
    const when = facts.date(row.deleting.purge_after)
    if (row.role === 'core')
      return { ...none, label: C.stDeleting, tone: 'warn', sentence: C.stDeletingCore(when, peer, row.deleting.copy === 'remove') }
    return { ...none, label: C.stCoreDeleting, tone: 'warn', sentence: C.stCoreDeletingBody(peer, when, deletingCopy(row.deleting) === 'removed') }
  }
  if (row.role === 'orphaned') return { ...none, label: C.stOrphaned, tone: 'warn', sentence: C.stOrphanedBody(peer) }

  const core = row.role === 'core'
  const reason = reasonText(row.stop_reason)
  const withCode = (s: Omit<StatusText, 'code'>): StatusText => ({ ...s, code: row.stop_reason && !reason ? row.stop_reason : null })
  switch (row.state) {
    case 'live': {
      if (!core && facts.firstCopy && !facts.firstCopy.finished) return firstCopy(row, facts, peer)
      if (facts.linkUp === false)
        return core ?
            { ...none, label: C.stLiveLinkDown, tone: 'warn', sentence: C.stLiveLinkDownCore(peer) }
          : { ...none, label: C.stReadOnlyLink, tone: 'warn', sentence: C.stReadOnlyLinkBody(peer) }
      return { ...none, label: C.stLive, tone: 'ok', sentence: core ? C.stLiveCore(peer) : C.stLiveMirror(peer) }
    }
    case 'starting':
      return firstCopy(row, facts, peer)
    case 'paused':
      return withCode({ label: C.stPaused, tone: 'warn', sentence: core ? C.stPausedCore(peer, reason) : C.stPausedMirror(reason) })
    case 'diverged':
      return withCode({ label: C.stDiverged, tone: 'danger', sentence: core ? C.stDivergedCore(peer) : C.stDivergedMirror(reason) })
    case 'expired':
      return withCode({ label: C.stExpired, tone: 'danger', sentence: core ? C.stExpiredCore(peer) : C.stExpiredMirror })
    case 'stopped':
      return withCode({ label: C.stStopped, tone: 'danger', sentence: core ? C.stStoppedCore(peer, reason) : C.stStoppedMirror(reason) })
    case 'switching':
      return { ...none, label: C.stSwitching, tone: 'info', sentence: C.stSwitchingBody }
    default:
      return { ...none, label: C.stUnknown, tone: 'unknown', sentence: C.stUnknownBody }
  }
}

const firstCopy = (row: MirroredVault, facts: StatusFacts, peer: string): StatusText => {
  if (row.role === 'core') return { label: C.stFirstCopy, tone: 'info', sentence: C.stFirstCopyCore(peer), code: null }
  const p = firstCopyProgress(facts.firstCopy ?? null)
  return { label: C.stFirstCopy, tone: 'info', sentence: C.stFirstCopyMirror(peer, p?.text ?? null), code: null }
}

// The first copy's progress (mirror.detach.preview first_copy): a ratio for the meter (null while the total is
// unknown) and "120 of 4,000 entries".
export const firstCopyProgress = (fc: DetachPreview['first_copy'] | null) => {
  if (!fc || fc.finished) return null
  const ratio = fc.entries_total > 0 ? Math.min(1, fc.entries_copied / fc.entries_total) : null
  const n = (v: number) => v.toLocaleString('en-US')
  return { ratio, text: fc.entries_total > 0 ? C.progress(n(fc.entries_copied), n(fc.entries_total)) : C.progressUnknown(n(fc.entries_copied)) }
}

// ---- position

// Where the two copies stand: the last change numbered here, and the last one the other side confirmed.
export const positionText = (row: Pick<MirroredVault, 'role' | 'term' | 'last_seq' | 'acked'>): string => {
  if (row.last_seq === null || row.term === null) return C.posNone
  const confirmed = row.acked ? C.posConfirmed(row.acked.seq, row.acked.term) : C.posNothingConfirmed
  return `${C.posAt(row.last_seq, row.term)} · ${confirmed}`
}

// Changes the core has numbered that the mirror hasn't confirmed yet (same term only; null when it can't be told).
export const unconfirmed = (row: Pick<MirroredVault, 'role' | 'term' | 'last_seq' | 'acked'>): number | null => {
  if (row.role !== 'core' || row.last_seq === null || row.term === null) return null
  if (!row.acked) return row.last_seq
  if (row.acked.term !== row.term) return null
  return Math.max(0, row.last_seq - row.acked.seq)
}

// ---- actions

export type MirrorAction = 'cancel' | 'switch' | 'resync' | 'detach' | 'versions' | 'held'

const START_OPEN: readonly MirrorStart['state'][] = ['offered', 'pending', 'accepted', 'keys_acked', 'installed', 'started', 'failed', 'expired']

// Which actions a vault offers, by this server's role and the vault's state (the server checks again and refuses with
// its sentence). A completed mirror on the mirror side ends by detaching, never by cancel (mirror_detach_required).
export const actionsFor = (row: Pick<MirroredVault, 'role' | 'state' | 'start' | 'deleting'>): MirrorAction[] => {
  const out: MirrorAction[] = []
  const deleting = Boolean(row.deleting?.deleting)
  switch (row.role) {
    case 'core':
      if (row.state === 'live' && !deleting) out.push('switch')
      out.push('cancel')
      break
    case 'mirror':
      if (row.state === 'live' && !deleting) out.push('switch')
      if (row.state === 'diverged' || row.state === 'expired' || row.state === 'stopped') out.push('resync')
      out.push('detach', 'versions', 'held')
      break
    case 'orphaned':
      out.push('detach', 'cancel', 'held')
      break
    case 'starting':
      if (row.start && START_OPEN.includes(row.start.state)) out.push('cancel')
      break
    case 'detached':
      out.push('held')
      break
    default:
      break
  }
  return out
}

// What cancel means for this row: end a mirror (core; choose what happens to the copy), cancel a start, or remove an
// orphaned copy with its keys.
export type CancelKind = 'end' | 'start' | 'remove_orphan'
export const cancelKind = (row: Pick<MirroredVault, 'role'>): CancelKind =>
  row.role === 'core' ? 'end'
  : row.role === 'orphaned' ? 'remove_orphan'
  : 'start'

// The payload that names a row for mirror.cancel: the vault, or the offer while its vault doesn't exist here yet.
export const cancelTarget = (row: Pick<MirroredVault, 'vault_id' | 'start'>): { vault_id: number } | { offer: number } =>
  row.vault_id > 0 ? { vault_id: row.vault_id } : { offer: row.start?.id ?? 0 }

// ---- advice

// The next step in plain words, from the role and state (the server's own `vh mirror info` sentences). Null when
// there is nothing to do.
export const adviceFor = (row: MirroredVault, facts: { linkUp: boolean | null; held: number }): string | null => {
  const peer = peerName(row)
  if (row.role === 'starting') {
    const s = row.start
    if (!s) return null
    if (s.side === 'core' && (s.state === 'offered' || s.state === 'pending')) return C.advWaitingThem(peer)
    if (s.side === 'mirror' && (s.state === 'offered' || s.state === 'pending')) return C.advWaitingYou
    if (s.state === 'failed' || s.state === 'expired') return C.advStartFailed
    return null
  }
  if (row.role === 'detached') return row.rekey_recommended || row.detached?.rekey_recommended ? C.advRekey : null
  if (row.role === 'orphaned') return C.advOrphaned
  if (row.deleting?.deleting) return row.role === 'core' ? C.advDeletingCore : C.advDeletingMirror
  const core = row.role === 'core'
  const parts: string[] = []
  switch (row.state) {
    case 'live':
      if (facts.linkUp === false) parts.push(core ? C.advLinkDownCore : C.advLinkDownMirror)
      break
    case 'diverged':
    case 'expired':
    case 'stopped':
      parts.push(core ? C.advStoppedCore(peer) : facts.linkUp === false ? C.advStoppedMirrorLinkDown : C.advStoppedMirror)
      break
    case 'paused':
      if (facts.linkUp === false) parts.push(core ? C.advLinkDownCore : C.advLinkDownMirror)
      break
    case 'switching':
      parts.push(C.advSwitching)
      break
    default:
      break
  }
  if (!core && facts.held > 0) parts.push(C.advHeld(facts.held))
  return parts.length ? parts.join(' ') : null
}

// ---- held changes

export const OP_TEXT: Readonly<Record<string, string>> = {
  mkdir: 'Created a folder',
  move: 'Moved',
  rename: 'Renamed',
  remove: 'Removed',
  copy: 'Copied',
  write: 'Saved a file',
}

export const heldWhat = (h: Pick<HeldChange, 'op' | 'kind' | 'copy_name'>): string => {
  if (h.kind === 'conflict') return h.copy_name ? C.heldConflictAs(h.copy_name) : C.heldConflict
  return OP_TEXT[h.op] ?? h.op
}

export const heldPath = (h: Pick<HeldChange, 'path' | 'name'>) => h.path || h.name || C.heldUnknownPath

// Whether a held change's bytes can be saved (mirror.held.get answers only a held write's).
export const canDownloadHeld = (h: Pick<HeldChange, 'op' | 'kind'>) => h.op === 'write' && h.kind === 'held'

// Open held changes per vault, from one mirror.held.list read.
export const heldCounts = (held: readonly Pick<HeldChange, 'vault_id' | 'state'>[]): Map<number, number> => {
  const counts = new Map<number, number>()
  for (const h of held) if (h.state === 'open') counts.set(h.vault_id, (counts.get(h.vault_id) ?? 0) + 1)
  return counts
}

// base64 (mirror.held.get content_b64) → bytes, for a Blob.
export const decodeBase64 = (b64: string): Uint8Array => {
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

// ---- switch

// What the old core keeps after a switch (mirror.switch peer_access / peer_role), in words.
export const accessText = (r: Pick<SwitchResult, 'peer_access' | 'peer_role'>, oldCore: string): string => {
  const role = r.peer_role?.role_name
  if (r.peer_access === 'none') return C.switchKeepsNone(oldCore)
  const how = r.peer_access === 'read-write' ? C.accessReadWrite : C.accessReadOnly
  return C.switchKeeps(oldCore, how, role ?? null)
}

// ---- versions

export type Parsed<T> = { ok: true; value: T } | { ok: false; error: string }

// A limit field: blank = the server's default (null), else a whole number ≥ 0 (0 = no limit of that kind).
export const parseLimit = (text: string): Parsed<number | null> => {
  const t = text.trim()
  if (!t) return { ok: true, value: null }
  if (!/^\d{1,15}$/.test(t)) return { ok: false, error: C.limitInvalid }
  return { ok: true, value: Number(t) }
}

// ---- add

// Vaults that can be offered: not already mirrored or starting here.
export const offerable = <V extends { id: number }>(vaults: readonly V[], mirrored: readonly Pick<MirroredVault, 'vault_id' | 'role'>[]) => {
  const busy = new Set(mirrored.filter(m => m.role !== 'detached' && m.role !== 'none').map(m => m.vault_id))
  return vaults.filter(v => !busy.has(v.id))
}
