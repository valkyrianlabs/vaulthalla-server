- Server mirror (experimental, behind peers.experimental): take over (migration 168: mirror_takeover,
  mirror_fork_base; admin.mirror.takeover, bit 1 of admin_role.mirror_permissions, super_admin only among the built-in
  roles, --allow-mirror-takeover). mirror.takeover / vh mirror takeover <vault> --confirm <name> on the mirror (super
  admins or holders of admin.mirror.takeover, people only, via ops::mirrors::requireTakeover; the data.destroy step-up in the console; audited mirror.takeover): refused while the
  core answers (mirror_core_reachable), for an orphaned, unfinished or diverged copy and a name not typed exactly. It
  records the fork point and the fork base (the tree as the core last confirmed it), makes pending changes ordinary
  (held ones kept), rehashes the tree and becomes the core in term + 1. A prepared switch ends mirror_taken_over; the
  old core's later switched decision for it is answered as switched when the fork point agrees. An unlink ends a
  switch's telling on both sides. vh mirror info shows the latest switch, an open take over and what to do next.
  Allowed while paused mirror_core_deleting (audited core_deleting). mirror.detach also takes a core row with an open
  take over, or rejoining or forked: the take over settles ended, the rejoin ends (mirror_rejoin phase 'ended'), the
  fork base goes, and the other server is told peer.mirror.detached.
