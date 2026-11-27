- Server mirror (experimental, behind peers.experimental): a change made on the mirror. On a Live mirror, ops::fs and
  vh::fs::Filesystem's mutators (and FUSE unlink, rmdir and seals) apply mkdir, move, rename, remove, write and setattr
  as pending changes (migration 166: mirror_pending, mirror_dirty, mirror_held, mirror_submission), submitted in order
  with peer.mirror.submit; a write's sealed bytes go first with PUT on the sealed lane (verified and staged by the core).
  The core executes each as the person under the linked server's vault role, answers a request id once, and logs it
  with the request id in origin. The applier confirms a change from its own groups without applying it twice and
  settles the entries it held; a clash becomes a conflict copy, any other refusal a held change (ws
  mirror.held.list|discard|retry, vh mirror held|discard|retry). A seal of a file open when the link drops is kept as
  pending. A file whose contents have not arrived renames as metadata. Copy is submitted only; owner changes and
  symlinks are refused on a mirror. Log rows carry origin on the wire.
