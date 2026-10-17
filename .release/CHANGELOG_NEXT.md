<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- fuse: rename over an existing entry replaces it as rename(2) does instead of failing with EIO
  (UNIQUE(parent_id, name)). The replaced file is trashed like an unlink (row, backing bytes, derived artifacts) in
  the rename's transaction; a symlink or empty folder is deleted; EISDIR/ENOTDIR/ENOTEMPTY/EINVAL per rename(2).
  Replacing needs Delete on the destination (checked like unlink); RENAME_NOREPLACE is enforced under the
  filesystem lock.
- fs: a rename that fails part-way rolls back its backing moves and never touches cached entries (it works on
  copies, published after commit). A failed cross-folder rename used to strand the file's bytes at the destination.
- fs: ws rename/move and uploads onto an existing name are refused with EEXIST instead of EIO.
