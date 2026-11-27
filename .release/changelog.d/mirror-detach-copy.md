- Detach a copy (migration 169_mirror_copy.sql; design/peers/mirror.md "As built: detach a copy").
  - vh mirror detach <vault> --copy [--name] [--owner] [--status | --cancel]; ws mirror.detach.copy,
    mirror.detach.copy.get, mirror.detach.copy.cancel (requireDetacher; mirror_not_held, mirror_copy_no_space,
    mirror_copy_not_running).
  - mirror_copy: the background job ("MirrorCopies" service), its progress and skipped files; a daemon restart removes
    the partial vault and starts over. While it runs the new vault is read-only to everything else
    (mirror_copy_writing).
