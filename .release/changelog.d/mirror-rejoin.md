- Server mirror: the old core learns of a take over (migration 168: mirror_rejoin, mirror_vault states
  rejoining and forked, mirror_takeover old_core_outcome, told_at, old_core_changes). peer.mirror.promoted is told by
  the new core on every pass while the link is up until answered; the old core goes read-only at once (mirror_rejoining,
  every surface and the backstop), waits for its writers, then follows in the new term when it committed nothing past
  the fork point (the take over settles, the fork base goes) or stays rejoining with its changes counted. Both forced
  (each took over) is detected: both read-only (mirror_both_forced). vh mirror resync works from rejoining and forked.
