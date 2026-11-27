- Server mirror (experimental, behind peers.experimental): the planned switch of the core role (migration 168:
  mirror_switch, mirror_vault state 'switching', vh_mirror_core_term and vh_mirror_track_vault refusing a switching
  core's changes). mirror.switch / vh mirror switch on either server (super admins; audited mirror.switch on both);
  wire peer.mirror.switch.request (mirror to core), peer.mirror.switch.prepare and peer.mirror.switch.commit (core to
  mirror). The core coordinates: freeze, wait for the writers already running, number its last change, prepare the
  mirror (read-only, caught up, equal digest, nothing pending, contents all held), decide durably (switched: it becomes
  the mirror in term + 1; abandoned: live again), tell the mirror until it answers (switched: it becomes the core in
  term + 1, its log from (term + 1, 1)). The prepare answers the role the old core will hold on the new core
  (peer_role); none abandons the switch (mirror_switch_no_role) unless accept_no_access (--accept-no-access); the
  answer names it (peer_role, peer_access). Refusals: mirror_pending_changes, mirror_contents_missing,
  mirror_submissions_queued, mirror_switch_running, mirror_has_remote, mirror_switch_timeout and others. Held changes
  stay listed on a server that became the core (retry needs a mirror).
