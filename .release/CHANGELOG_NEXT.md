<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- macOS: `valkyrianlabs/tap/vaulthalla` is a meta cask depending on `vaulthalla-server` and `vaulthalla-desktop`
  (each upgrades to its own latest release; it needs `brew trust valkyrianlabs/tap` once). The server package no
  longer bundles Vaulthalla Desktop (`fetch-desktop.sh`, the `sh.vaulthalla.desktop` choice and
  `VH_PKG_DESKTOP_APP` are gone) and the casks no longer conflict.
