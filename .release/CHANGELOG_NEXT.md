<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- macOS: `uninstall.sh` (also run by `brew uninstall --cask vaulthalla-server`) says which daemon it is waiting on
  while launchd stops it (up to 75 s), instead of pausing silently.
- FUSE: every request is answered, even when its operation fails unexpectedly. A database pool timeout (or an
  unknown inode in rename) during unlink, rmdir, rename or any other op used to leave the kernel request unanswered, so
  `rm`, `mv` and the like hung; they now fail with EAGAIN (database unreachable) or EIO. FUSE stats count such ops
  as errors, not successes (#263).
