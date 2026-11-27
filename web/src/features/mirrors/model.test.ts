import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  accessText,
  actionsFor,
  adviceFor,
  canTakeOver,
  cancelKind,
  cancelTarget,
  copyProgress,
  decodeBase64,
  firstCopyProgress,
  heldCounts,
  heldWhat,
  offerable,
  parseLimit,
  positionText,
  statusText,
  unconfirmed,
  type MirroredVault,
} from './model.ts'

const date = (unix: number) => `@${unix}`

const row = (over: Partial<MirroredVault> = {}): MirroredVault => ({
  vault_id: 5,
  vault_name: 'Projects',
  role: 'mirror',
  peer: { id: 3, node_id: 'node-b', name: 'vps', revoked: false },
  term: 2,
  last_seq: 40,
  state: 'live',
  grant: null,
  acked: { term: 2, seq: 38 },
  created_at: 1_700_000_000,
  start: null,
  detached: null,
  rekey_recommended: false,
  deleting: null,
  stop_reason: null,
  switch: null,
  takeover: null,
  advice: null,
  pending_changes: 0,
  first_copy: null,
  link_up: true,
  confirmed_at: null,
  settings: null,
  ...over,
})

const start = (over: Partial<NonNullable<MirroredVault['start']>> = {}): NonNullable<MirroredVault['start']> => ({
  id: 9,
  offer_uid: 'o-1',
  side: 'core',
  peer_id: 3,
  vault_uid: 'u',
  vault_id: 5,
  core_vault_id: 5,
  term: 1,
  name: 'Projects',
  description: '',
  quota: 0,
  size_bytes: 0,
  file_count: 0,
  history: false,
  owner: { node: 'n', id: 1, name: 'alice' },
  role: null,
  state: 'offered',
  step: 'offered',
  told: true,
  remove_copy: false,
  copy: null,
  reason: null,
  detail: null,
  attempts: 0,
  last_error: null,
  created_at: 0,
  updated_at: 0,
  expires_at: 0,
  finished_at: null,
  ...over,
})

test('a live mirror reads live, and read-only once its link is down (never healthy by guess)', () => {
  assert.equal(statusText(row(), { linkUp: true, date }).label, 'Live')
  assert.equal(statusText(row(), { linkUp: null, date }).tone, 'ok')
  const down = statusText(row(), { linkUp: false, date })
  assert.equal(down.label, 'Read-only: link down')
  assert.match(down.sentence, /read-only until it reconnects/)
  const core = statusText(row({ role: 'core' }), { linkUp: false, date })
  assert.match(core.sentence, /keep working here/)
})

test('the first copy shows its progress', () => {
  const s = statusText(row(), { linkUp: true, date, firstCopy: { finished: false, entries_copied: 120, entries_total: 4000 } })
  assert.equal(s.label, 'First copy')
  assert.match(s.sentence, /120 of 4,000 entries/)
  assert.equal(firstCopyProgress({ finished: false, entries_copied: 1, entries_total: 4 })?.ratio, 0.25)
  assert.equal(firstCopyProgress({ finished: false, entries_copied: 3, entries_total: 0 })?.ratio, null)
  assert.equal(firstCopyProgress({ finished: true, entries_copied: 4, entries_total: 4 }), null)
})

test('stopped states give their reason in words, or the code when it has none', () => {
  const d = statusText(row({ state: 'diverged', stop_reason: 'mirror_digest_mismatch' }), { linkUp: true, date })
  assert.equal(d.label, 'Diverged')
  assert.match(d.sentence, /stopped matching the core’s, so/)
  assert.equal(d.code, null)
  assert.match(statusText(row({ state: 'diverged', stop_reason: 'mirror_type_mismatch' }), { linkUp: true, date }).sentence, /a file on one server/)
  const odd = statusText(row({ state: 'stopped', stop_reason: 'mirror_something_new' }), { linkUp: true, date })
  assert.equal(odd.code, 'mirror_something_new')
  assert.equal(statusText(row({ state: 'expired' }), { linkUp: true, date }).tone, 'danger')
  assert.equal(statusText(row({ state: 'switching' }), { linkUp: true, date }).label, 'Switching')
  assert.equal(statusText(row({ state: null }), { linkUp: true, date }).tone, 'unknown')
})

test('the core deleting a vault names the date and what happens to the copy', () => {
  const mirror = statusText(row({ state: 'paused', stop_reason: 'mirror_core_deleting', deleting: { deleting: true, purge_after: 99, copy: 'leave' } }), {
    linkUp: true,
    date,
  })
  assert.equal(mirror.label, 'Core is deleting it')
  assert.match(mirror.sentence, /until @99, then it is kept as an orphaned copy/)
  const core = statusText(row({ role: 'core', deleting: { deleting: true, purge_after: 99, copy: 'remove' } }), { linkUp: true, date })
  assert.match(core.sentence, /purged on @99.*removed/)
})

test('starts read from the side that asks', () => {
  assert.equal(statusText(row({ role: 'starting', start: start() }), { linkUp: true, date }).label, 'Waiting for an answer')
  assert.equal(statusText(row({ role: 'starting', start: start({ side: 'mirror' }) }), { linkUp: true, date }).label, 'Waiting for you')
  const failed = statusText(row({ role: 'starting', start: start({ state: 'failed', reason: 'mirror_no_space', last_error: 'no space' }) }), { linkUp: true, date })
  assert.equal(failed.tone, 'danger')
})

test('actions follow the role and state', () => {
  assert.deepEqual(actionsFor(row({ role: 'core' })), ['switch', 'cancel'])
  assert.deepEqual(actionsFor(row({ role: 'core', state: 'diverged' })), ['cancel'])
  assert.deepEqual(actionsFor(row()), ['switch', 'detach', 'copy', 'versions', 'held'])
  assert.deepEqual(actionsFor(row({ state: 'diverged' })), ['resync', 'detach', 'copy', 'versions', 'held'])
  assert.ok(!actionsFor(row()).includes('cancel'), 'a completed mirror leaves by detaching')
  assert.deepEqual(actionsFor(row({ role: 'orphaned' })), ['detach', 'copy', 'cancel', 'held'])
  assert.deepEqual(actionsFor(row({ role: 'starting', start: start() })), ['cancel'])
  assert.deepEqual(actionsFor(row({ role: 'starting', start: start({ state: 'declined' }) })), [])
  assert.deepEqual(actionsFor(row({ role: 'core', deleting: { deleting: true, purge_after: 1, copy: 'leave' } })), ['cancel'])
  assert.equal(cancelKind(row({ role: 'core' })), 'end')
  assert.equal(cancelKind(row({ role: 'orphaned' })), 'remove_orphan')
  assert.deepEqual(cancelTarget(row({ vault_id: 0, start: start({ id: 12 }) })), { offer: 12 })
  assert.deepEqual(cancelTarget(row()), { vault_id: 5 })
})

test('advice says what to do next, and nothing on a healthy vault', () => {
  assert.equal(adviceFor(row(), { linkUp: true, held: 0 }), null)
  assert.match(adviceFor(row(), { linkUp: true, held: 2 }) ?? '', /2 changes made here were refused/)
  assert.match(adviceFor(row({ state: 'diverged' }), { linkUp: true, held: 0 }) ?? '', /Resync/)
  assert.match(adviceFor(row({ state: 'diverged' }), { linkUp: false, held: 0 }) ?? '', /needs the link/)
  assert.match(adviceFor(row({ role: 'orphaned' }), { linkUp: true, held: 0 }) ?? '', /Detach/)
  assert.match(adviceFor(row({ role: 'starting', start: start() }), { linkUp: true, held: 0 }) ?? '', /A super admin on vps/)
})

test('positions and unconfirmed changes', () => {
  assert.equal(positionText(row()), 'Change 40 (term 2) · confirmed through 38 (term 2)')
  assert.equal(positionText(row({ last_seq: null })), 'No changes yet')
  assert.equal(unconfirmed(row({ role: 'core' })), 2)
  assert.equal(unconfirmed(row({ role: 'core', acked: { term: 1, seq: 3 } })), null)
  assert.equal(unconfirmed(row()), null)
})

test('held changes in words, counted per vault', () => {
  assert.equal(heldWhat({ op: 'write', kind: 'held', copy_name: null }), 'Saved a file')
  assert.equal(heldWhat({ op: 'write', kind: 'conflict', copy_name: 'a (conflict).txt' }), 'Conflict copy kept as “a (conflict).txt”')
  const counts = heldCounts([
    { vault_id: 1, state: 'open' },
    { vault_id: 1, state: 'open' },
    { vault_id: 2, state: 'discarded' },
  ])
  assert.equal(counts.get(1), 2)
  assert.equal(counts.get(2), undefined)
  assert.deepEqual([...decodeBase64('aGk=')], [104, 105])
})

test('the switch says what the old core keeps', () => {
  assert.equal(accessText({ peer_access: 'read-only', peer_role: { role_name: 'Viewer', files: 0, directories: 0, sync: 0, roles: 0 } }, 'studio'), 'studio keeps read-only access through the role “Viewer”.')
  assert.match(accessText({ peer_access: 'none', peer_role: null }, 'studio'), /keeps no access/)
})

test('limits and offerable vaults', () => {
  assert.deepEqual(parseLimit(''), { ok: true, value: null })
  assert.deepEqual(parseLimit('0'), { ok: true, value: 0 })
  assert.equal(parseLimit('-1').ok, false)
  assert.equal(parseLimit('1.5').ok, false)
  assert.deepEqual(
    offerable([{ id: 1 }, { id: 5 }, { id: 6 }], [row(), row({ vault_id: 6, role: 'detached' })]).map(v => v.id),
    [1, 6],
  )
})

test('take over: a mirror whose first copy finished and that still matches, never an orphan', () => {
  assert.deepEqual(actionsFor(row(), { firstCopyFinished: true }), ['switch', 'takeover', 'detach', 'copy', 'versions', 'held'])
  assert.ok(actionsFor(row({ state: 'stopped' }), { firstCopyFinished: true }).includes('takeover'))
  assert.ok(actionsFor(row({ state: 'switching' }), { firstCopyFinished: true }).includes('takeover'), 'the way out of a switch whose core never came back')
  assert.equal(canTakeOver(row(), false), false)
  assert.equal(canTakeOver(row(), null), false, 'unknown hides it')
  assert.equal(canTakeOver(row({ state: 'diverged' }), true), false)
  assert.equal(canTakeOver(row({ role: 'orphaned' }), true), false)
  assert.equal(canTakeOver(row({ role: 'core' }), true), false)
})

test('a replaced core (rejoining), both taking over (forked) and an open take over read in words', () => {
  const rejoining = statusText(row({ role: 'core', state: 'rejoining', stop_reason: 'mirror_rejoining' }), { linkUp: true, date })
  assert.equal(rejoining.label, 'Replaced as the core')
  assert.match(rejoining.sentence, /vps took over as the core.*never received.*read-only here; resync it.*or detach it/)
  assert.equal(rejoining.code, null)
  const forked = statusText(row({ role: 'core', state: 'forked', stop_reason: 'mirror_both_forced' }), { linkUp: true, date })
  assert.match(forked.sentence, /Both servers took over.*Pick the server whose files stay/)
  const took = row({ role: 'core', takeover: { term: 3, fork: { term: 2, seq: 40 }, peer_id: 3, contents_missing: 0, created_at: 1 } })
  assert.match(statusText(took, { linkUp: false, date }).sentence, /has not returned yet/)
  assert.match(adviceFor(took, { linkUp: false, held: 0 }) ?? '', /The old core has not returned yet/)
  assert.deepEqual(actionsFor(row({ role: 'core', state: 'rejoining' })), ['resync', 'detach', 'held'])
  assert.deepEqual(actionsFor(row({ role: 'core', state: 'forked' })), ['resync', 'detach', 'held'])
  assert.deepEqual(actionsFor(took), ['switch', 'detach', 'cancel'])
  assert.match(adviceFor(row({ role: 'core', state: 'rejoining' }), { linkUp: true, held: 0 }) ?? '', /Resync it to follow vps again/)
})

test('the server’s advice line replaces the console’s own', () => {
  const advised = row({ state: 'diverged', advice: 'Linked server 3 took over in term 4.' })
  assert.equal(adviceFor(advised, { linkUp: true, held: 0 }), 'Linked server 3 took over in term 4.')
  assert.match(adviceFor(advised, { linkUp: true, held: 1 }) ?? '', /^Linked server 3 took over in term 4\. One change made here was refused/)
})

test('a copy’s progress counts bytes when it knows them, else entries', () => {
  const bytes = (n: number) => `${n}B`
  assert.deepEqual(copyProgress({ entries_done: 1, entries_total: 4, bytes_done: 30, bytes_total: 120 }, bytes), { ratio: 0.25, text: '1 of 4 entries · 30B of 120B' })
  assert.equal(copyProgress({ entries_done: 2, entries_total: 4, bytes_done: 0, bytes_total: 0 }, bytes).ratio, 0.5)
  assert.deepEqual(copyProgress({ entries_done: 3, entries_total: 0, bytes_done: 0, bytes_total: 0 }, bytes), { ratio: null, text: '3 entries so far' })
})
