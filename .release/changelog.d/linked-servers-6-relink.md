- Mirror relink (migration 171_mirror_relink.sql): `vh mirror relink <vault> --with <server>` and ws
  mirror.relink.compare, .get, .entries, .plan, .apply (super admins, people only; the keys step-up bound to
  mirror.relink:<vault> in the console) compare a vault two linked servers hold since their mirror ended (detached,
  ended, orphaned, rejoining, forked) by entry uid against the bases kept when the mirror rows ended (mirror_base),
  keep a plan (one choice per drifted entry: this, theirs, both) and apply it, or the hard override (keep this |
  theirs): the chosen server becomes the core in a new term, the other its mirror; the future mirror brings its chosen
  versions onto the core through peer.mirror.submit and starts its copy over (resync); losing versions are held
  changes with their bytes or conflict copies. Peer wire peer.mirror.relink.state, .tree, .prepare, .go, .abort. Detach,
  take over and rejoin records settle (`relinked`). Refused for a stale plan, pending changes, a running switch or
  start, a deletion, or keys that differ.
- Mirror relink is a two-sided handshake (no server acts on the other's word alone): comparing sends
  peer.mirror.relink.request, recorded on the other server as waiting for its super admin (a day); until a person there
  accepts it (`vh mirror pending`, `vh mirror relink <vault> --accept | --decline`, ws mirror.relink.pending, .accept,
  .decline) peer.mirror.relink.state answers only the vault's status and .tree, .prepare and .go are refused
  (mirror_relink_not_accepted). Applying proposes the outcome (peer.mirror.relink.propose: the core, the mode, what the
  other vault gains and loses, both digests, the plan's hash) and waits for that server's super admin to approve it
  (`--approve --confirm <name>`, ws mirror.relink.approve, the keys step-up bound to mirror.relink:<vault>); the other
  server prepares only the approved plan (mirror_relink_not_approved otherwise), the asking server then carries it out
  (its follower's pass, or the command again). A changed plan or tree voids the approval; declines, cancels
  (peer.mirror.relink.cancel) and expiries change neither vault; answers travel as peer.mirror.relink.answer. Every step
  is audited on both servers (mirror.relink.request, .accept, .decline, .propose, .approve, .answer, .cancel, .expired,
  .voided). Migration 171 gains the phases requested, accepted, proposed, approved, declined, expired and the columns
  expires_at, accepted_at, accepted_by, proposal, approved_at, approved_by.
