<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- Source moved to github.com/valkyrianlabs/vaulthalla-server (Homepage, debian/copyright Source, release.toml);
  the old vaulthalla/server URLs redirect. CI runs on the Valkyrian Labs VPS build pool (label vps-ci).
- The macOS installer's Nexus mirror moved to the valkyrian-raw repository (pkg.vaulthalla.sh).
