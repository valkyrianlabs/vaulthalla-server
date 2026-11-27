- Server mirror, the gate (migration 165_mirror_gate.sql; design/peers/mirror.md "As built: the gate"), experimental
  and off by default (peers.experimental).
  - mirror::access: per-vault state of a vault held as another server's copy (NotMirrored, Live, ReadOnly with a
    reason), in memory, published at startup and by every mirror_vault writer, kept by the link's up and down,
    reconciled by MirrorAccessWatcher; requireWritable throws MirrorReadOnly (ops::ReadOnly, code read_only, reason).
    Strictly read-only in this release (mirror_writes_not_built while live).
  - Refused on a held vault: FUSE (EROFS from the resolver and the seal), ops::fs, vh::fs::Filesystem's mutating
    calls, the HTTP upload and text-save lanes (503 read_only, Retry-After 30), vh fs put (exit 69), share uploads,
    the S3 gateway (503 ServiceUnavailable), ops::recovery::restore, vault settings, the recovery policy and
    vault.remote.attach (mirror_core_owned). The mount resolves a held vault's root through rbac::mirrored only.
  - Migration 165: BEFORE triggers on fs_entry, files, directories, symlinks, files_trashed refuse a replicated change
    to a held vault unless vh.mirror_apply or vh.mirror_local is set (db::query::mirror::Log::markMirrorApply,
    markMirrorLocal); the vault root, folder times, totals and a whole vault's removal pass; partial index
    mirror_vault_held_idx.
  - Background: format conversion, local versioning captures and retention skip a held vault; key rotation and
    salvage are refused on it whatever a test allows a core.
- FUSE setattr: chmod, chown and utimens are written through ops::fs::setAttributes in one transaction
  (db::query::fs::Entry::setAttributes, vh.keep_mtime, vh.actor); owner and group changes need a super admin, audited
  fs.chown.
- vh::fs::Filesystem::createFile with overwrite=false refuses an existing file (EEXIST) instead of returning it.
- ops::fs::check (Allowed, Denied, Missing): ops::fs refuses a missing entry with NotFound to a caller who may list
  the nearest existing folder, Denied otherwise.
- CLI socket: bound and listening under a private name, then renamed onto its path; the run loop removes its own path
  when it ends (the ShellServerTest flakes).
