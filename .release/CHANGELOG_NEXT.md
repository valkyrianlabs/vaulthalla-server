<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- macOS meta cask: the `.desktop-opened` marker that makes the cask open Desktop only once now stays after
  `brew uninstall --cask vaulthalla` (Homebrew runs uninstall steps on upgrades too, so removing it would reopen
  Desktop after every upgrade). cask-smoke expected it removed, which held back the 1.21.0 macOS package.
