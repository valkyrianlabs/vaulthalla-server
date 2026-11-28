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
