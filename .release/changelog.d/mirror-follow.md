- Server mirror, following the core (migration 164_mirror_follow.sql; design/peers/mirror.md "As built: following the
  core"): MirrorVaults::startCore takes its baseline per vault (a `starting` row its writers wait on, the writers then
  running waited for) instead of a server-wide SHARE lock on the entry tables, and keeps the tree's state documents in
  mirror_baseline for the first copy; the sequencer records the digest after every group (digest_after); mirror_vault
  gains the states starting, expired and stopped, a stop reason and details, the first copy's cursor and the recorded
  vault document; an entry directly under a vault's root names the vault's uid as its parent in its replicated state.
- New peer wire commands peer.mirror.tree, peer.mirror.log, peer.mirror.ack and peer.mirror.notify (peer sessions only;
  not_found for a vault the caller is not the linked server of), the mirror's
  log applier (mirror::apply: one transaction per group, compare-and-set on entry hashes, temporary names for swaps,
  remote accounts created for another server's {node, id}, pending contents expected in the same transaction) and the
  "MirrorFollower" runtime service. A shared tree-apply module (fs/tree_apply) carries the uid lookup and the
  after-commit cache effects; the manifest applier calls it.
- Lock order: key rotation's set/compare-and-set of a file's IV and version and the manifest applier's content
  replacement lock the entry's fs_entry row before its files row, so a mirrored vault's type trigger cannot deadlock
  with a writer of fs_entry then files.
