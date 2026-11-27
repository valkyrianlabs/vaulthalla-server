- Leaving a mirror (migration 167_mirror_leave.sql; design/peers/mirror.md "As built: leaving a mirror").
  - admin_role.mirror_permissions: the admin module `mirror`, admin.mirror.detach ("Detach mirrored vaults"); super_admin
    only among the built-in roles; --allow-mirror-detach.
  - mirror_detached (the record of a detach on both servers), mirror_offer state 'detached' and copy_outcome 'detached',
    mirror_content_pending state 'missing', mirror_vault.keep_versions (+ set_by, set_at).
  - vh mirror detach [--owner] [--dry-run], ws mirror.detach.preview and mirror.detach (no step-up; confirm_name),
    peer.mirror.detached on the link; mirror_detached_copy refuses mirroring a detached uid between the two servers.
  - vh vault delete --mirror-copy remove|leave and storage.vault.remove {mirror_copy} on a mirrored vault's core
    (mirror_copy_choice_required without it); the data-destroy step-up target gains :mirror-copy for remove. The choice
    is recorded (mirror_vault.deleting_copy) and applied at the purge; peer.mirror.deleting pauses the mirror's copy
    (mirror_core_deleting) for the retention window and a restore resumes it.
  - fs.dir.list entries of missing files carry contents_missing; vh fs ls shows them as missing.
  - vh mirror versions, ws mirror.versions.set: the applier keeps the prior generation of what the core replaces,
    trashes or deletes (recovery::local::versions, RetainOptions::held_copy_policy), bounded by the setting.
  - vh mirror save <id> <dest> (streamed), ws mirror.held.get (inline up to 8 MiB).
  - A detached vault's file whose contents never arrived fails to open with mirror_contents_missing (ENODATA; HTTP 410).
