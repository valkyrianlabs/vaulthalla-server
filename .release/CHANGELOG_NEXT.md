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
- CLI tables (`vh fs ls` and every other `vh` table) measure, truncate and pad cells by display width instead of
  bytes, so long names with accents, CJK or emoji are never cut mid-character and columns stay aligned; malformed
  UTF-8 in a name shows as U+FFFD (#273).
