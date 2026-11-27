- Mirror every vault to a linked server (migration 170_mirror_all.sql): peer.mirror_vaults (+ set_by, set_at), off by
  default; ops::mirrors::setMirrorAll (super admins, person only, keys step-up target mirror.mirror_all:<peer> when it
  turns on; audited mirror.mirror_all.set), ws mirror.mirror_all.set, `vh mirror mirror-all <server> on|off`. The start
  service offers each eligible vault not mirrored yet (MirrorStart::mirrorEveryVaultCandidates: no mirror row, no
  running start, no offer to that server ended since the setting was turned on, not detached between the two) every
  10 s and on wake; refused vaults are retried after a minute.
