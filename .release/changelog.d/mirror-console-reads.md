- mirror.list / mirror.get rows carry pending_changes, first_copy (model MirrorFirstCopy: finished, entries_copied,
  entries_total), link_up, confirmed_at and settings (model MirrorSettings: versions, accept_all, keep_removed,
  mirror_all) from ops::mirrors::statusOf / toJson(Status); both models are checked by the contract-model tests.
