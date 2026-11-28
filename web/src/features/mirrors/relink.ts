// Relink (ws mirror.relink.*; design/peers/mirror.md "As built: relink"): the pure parts of the Reconnect dialog. What a
// drift kind and an entry's resolution read as, the counts in words, and the payload a choice makes. Loaded only with the
// dialog. Pure: see relink.test.ts. Imports by relative path with the .ts extension (node --test).
import type { Response } from '@/lib/ws/client'

export type RelinkStatus = Response<'mirror.relink.get'>
export type RelinkEntry = Response<'mirror.relink.entries'>['entries'][number]
export type RelinkRequest = Response<'mirror.relink.pending'>['requests'][number]
export type RelinkPhase = NonNullable<RelinkStatus['relink']>['phase']
export type DriftKind = RelinkEntry['kind']
export type Choice = 'this' | 'theirs' | 'both'

export const DRIFT_KINDS: readonly DriftKind[] = ['only_this', 'only_theirs', 'changed_this', 'changed_theirs', 'changed_both', 'differs']

export const kindText = (kind: DriftKind, peer: string): string => {
  switch (kind) {
    case 'only_this':
      return 'Only on this server'
    case 'only_theirs':
      return `Only on ${peer}`
    case 'changed_this':
      return 'Changed here'
    case 'changed_theirs':
      return `Changed on ${peer}`
    case 'changed_both':
      return 'Changed on both'
    case 'differs':
      return 'Differs'
  }
}

export const choiceText = (choice: Choice, peer: string): string =>
  choice === 'this' ? 'Keep this server’s'
  : choice === 'theirs' ? `Keep ${peer}’s`
  : 'Keep both'

// The plan's core, in words: which server's tree becomes the vault's truth.
export const coreName = (core: 'this' | 'theirs', peer: string) => (core === 'this' ? 'this server' : peer)

// Which side's version an entry ends with, from its resolution and the plan's core.
export const winnerOf = (resolution: RelinkEntry['resolution'], core: 'this' | 'theirs'): Choice =>
  resolution === 'both' ? 'both'
  : resolution === 'core' ? core
  : core === 'this' ? 'theirs'
  : 'this'

export type CountLine = { kind: DriftKind; label: string; count: number }

// The drift counts that are not zero, in a fixed order.
export const countLines = (counts: RelinkStatus['counts'] | undefined, peer: string): CountLine[] =>
  DRIFT_KINDS.map(kind => ({ kind, label: kindText(kind, peer), count: Number((counts as Record<string, number> | undefined)?.[kind] ?? 0) })).filter(
    l => l.count > 0,
  )

// Only files may keep both versions (a folder's place is one or the other).
export const canKeepBoth = (e: Pick<RelinkEntry, 'this' | 'theirs'>): boolean => e.this?.kind === 'file' || e.theirs?.kind === 'file'

// One entry's choice as mirror.relink.plan takes it; '' is the plan's default.
export const choicePayload = (uid: string, value: Choice | '') => ({ set: [{ uid, choice: value === '' ? null : value }] })
export const kindPayload = (kind: DriftKind | '', value: Choice | '') => ({ by_kind: [{ kind, choice: value === '' ? null : value }] })

// "takes 3, keeps 2 as held changes, gains 1 conflict copy"
export const gainsText = (g: { takes: number; keeps_held: number; conflict_copies: number } | undefined): string => {
  if (!g) return ''
  const parts = [`takes ${g.takes} from the other`]
  parts.push(`keeps ${g.keeps_held} of its own as held change${g.keeps_held === 1 ? '' : 's'}`)
  if (g.conflict_copies) parts.push(`gains ${g.conflict_copies} conflict cop${g.conflict_copies === 1 ? 'y' : 'ies'}`)
  return parts.join(', ')
}

// Both servers agree, each by a super admin: the other server's accepts the request (before its tree is compared), then
// approves the outcome (before anything changes on either). The phases that wait on the other server's admin.
export const AWAITING_OTHER: readonly RelinkPhase[] = ['requested', 'proposed']
// Asked and answered, nothing applied yet: the dialog polls these.
export const HANDSHAKE: readonly RelinkPhase[] = ['requested', 'accepted', 'open', 'proposed', 'approved']

// The relink running: a sentence and whether it is still moving (the dialog polls while it is).
export const phaseText = (status: RelinkStatus | undefined, peer = 'the other server'): { text: string; running: boolean; tone: 'ok' | 'info' | 'warn' | 'danger' } => {
  const r = status?.relink
  if (!r) return { text: 'Not compared yet.', running: false, tone: 'info' }
  if (r.side === 'responder' && HANDSHAKE.includes(r.phase))
    return {
      text:
        r.phase === 'requested' ? `${peer} asks to compare its copy with this vault: answer it under Relink requests.`
        : r.phase === 'proposed' ? `${peer} proposes an outcome: approve or decline it under Relink requests.`
        : r.phase === 'approved' ? `Approved here: ${peer} carries it out.`
        : `Accepted here: ${peer} compares and proposes an outcome.`,
      running: false,
      tone: r.phase === 'requested' || r.phase === 'proposed' ? 'warn' : 'info',
    }
  switch (r.phase) {
    case 'requested':
      return { text: `Waiting for ${peer}’s admin to accept the request. Nothing of its copy is compared before they do.`, running: true, tone: 'info' }
    case 'accepted':
      return { text: `${peer}’s admin accepted: comparing…`, running: true, tone: 'info' }
    case 'proposed':
      return { text: `Awaiting ${peer}’s approval of the outcome. Nothing changes on either server before they approve.`, running: true, tone: 'info' }
    case 'approved':
      return { text: `${peer}’s admin approved: carrying it out…`, running: true, tone: 'info' }
    case 'declined':
      return { text: r.error ?? `${peer}’s admin declined. Neither copy changed.`, running: false, tone: 'warn' }
    case 'expired':
      return { text: r.error ?? 'The request expired. Neither copy changed: ask again.', running: false, tone: 'warn' }
    case 'open':
      return { text: 'Compared. Choose how to resolve the drift.', running: false, tone: 'info' }
    case 'prepared':
    case 'bring':
      return { text: 'Bringing the chosen versions onto the core…', running: true, tone: 'info' }
    case 'copying':
      return { text: 'The mirror is copying the core’s tree…', running: true, tone: 'info' }
    case 'done':
      return { text: 'Relinked: both servers hold the same tree.', running: false, tone: 'ok' }
    case 'stale':
      return { text: r.error ?? 'The vault changed since it was compared: compare again.', running: false, tone: 'warn' }
    case 'failed':
      return { text: r.error ?? 'The relink failed.', running: false, tone: 'danger' }
    default:
      return { text: r.error && r.error !== 'discarded' ? r.error : 'The relink was discarded.', running: false, tone: 'info' }
  }
}

// A request a linked server made of this server, in words: what it asks the person here to decide.
export const requestAsk = (q: Pick<RelinkRequest, 'phase' | 'handshake' | 'peer' | 'asked_by'>): string => {
  const who = q.asked_by ? `${q.peer.name} (${q.asked_by})` : q.peer.name
  switch (q.phase) {
    case 'requested':
      return `${who} asks to compare its copy with this vault.`
    case 'proposed':
      return `${who} proposes how to reconnect this vault.`
    case 'accepted':
      return `Accepted${q.handshake?.accepted_by ? ` by ${q.handshake.accepted_by}` : ''}: ${q.peer.name} compares and proposes an outcome, approved here.`
    case 'approved':
      return `Approved${q.handshake?.approved_by ? ` by ${q.handshake.approved_by}` : ''}: ${q.peer.name} carries it out.`
    default:
      return `${q.peer.name}’s relink is ${q.phase}.`
  }
}
