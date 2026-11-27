- Web console: Mirrored vaults (`/linked-servers/mirrors` and `/linked-servers/mirrors/<vault>`, features/mirrors), a
  tab beside Linked servers for super admins: `mirror.list`, `mirror.get` (the mirror
  side also reads `mirror.detach.preview` for pending changes, first-copy progress and missing files), `mirror.add`
  (keys step-up), `mirror.pending|accept|decline`, `mirror.accept_all.set`, `mirror.keep_removed.set`,
  `mirror.cancel` (data.destroy step-up), `mirror.switch` (`accept_no_access` after `mirror_switch_no_role`),
  `mirror.resync`, `mirror.detach.preview|detach`, `mirror.versions.set`, `mirror.held.list|retry|discard|get`.
- Web console: the vault delete dialog sends `mirror_copy` (remove | leave) for a vault this server mirrors (from
  `mirror.get`, or after a `mirror_copy_choice_required` refusal) and explains that a copy held here can't be deleted.
- Web console: `mirror.takeover` (typed name as `confirm`, data.destroy step-up "Take over as a vault’s core") on a
  mirror whose first copy finished and that isn't diverged; `mirror.detach.copy|copy.get|copy.cancel` (progress polled
  while running, skipped files listed); `rejoining`, `forked` and an open take over in the state text, and mirror.get's
  `advice` in place of the console's own.
