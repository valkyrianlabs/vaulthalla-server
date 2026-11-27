- Web console: Mirrored vaults (`/linked-servers/mirrors` and `/linked-servers/mirrors/<vault>`, features/mirrors), a
  tab beside Linked servers for super admins while `peers.experimental` is on: `mirror.list`, `mirror.get` (the mirror
  side also reads `mirror.detach.preview` for pending changes, first-copy progress and missing files), `mirror.add`
  (keys step-up), `mirror.pending|accept|decline`, `mirror.accept_all.set`, `mirror.keep_removed.set`,
  `mirror.cancel` (data.destroy step-up), `mirror.switch` (`accept_no_access` after `mirror_switch_no_role`),
  `mirror.resync`, `mirror.detach.preview|detach`, `mirror.versions.set`, `mirror.held.list|retry|discard|get`. A
  `peers_experimental` refusal shows the same unavailable state as Linked servers.
- Web console: the vault delete dialog sends `mirror_copy` (remove | leave) for a vault this server mirrors (from
  `mirror.get`, or after a `mirror_copy_choice_required` refusal) and explains that a copy held here can't be deleted.
