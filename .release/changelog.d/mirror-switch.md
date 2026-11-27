- Server mirror (experimental, behind peers.experimental): resync and the scrub (migration 168: mirror_vault
  resync_at, resync_by, resync_count, scrubbed_at). mirror.resync / vh mirror resync (super admins; audited) on a
  diverged, expired or stopped copy asks the core (peer.mirror.resync), which takes its baseline again in the next
  term; the mirror holds its pending changes, resets and runs the first copy over its own entries (taken in place by
  uid, bytes of the same generation reused, a conflicting name set aside), keeping its version of a replaced file and
  every entry the core's tree lacks as held changes (mirror_resync_replaced, mirror_resync_extra). The scrub compares
  every mirrored vault's entry hashes with its tables daily on both servers (the follower's hourly pass) and stops a
  mismatch as diverged (mirror_scrub_mismatch).
