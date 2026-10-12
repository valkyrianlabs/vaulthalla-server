<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Trustworthy integration testing, an admin-role fix and typed console errors

#### Fixed

- **Admin roles:** deleting an admin role that accounts still hold is refused again. The check counted the wrong
  table, so a held role could be deleted, which silently removed the admin role from every account that had it; an
  unused role could also be refused for no reason.
- **Web console:** moving, renaming or copying into a folder that doesn't exist (or from a missing source) now says
  "not found" instead of a generic error.

#### Web console follows the server's command definitions

- The console's command types are generated from the daemon's own command definitions, so the two can't drift
  apart unnoticed.
- After a daemon upgrade, an open console page notices that the server's commands changed and suggests reloading
  (once, without interrupting anything). This uses a new read-only command, `meta.contract.get`, which needs a
  signed-in session and returns no secrets.

#### For contributors: an integration engine for the real daemon

- `vaulthalla-server` can run as a fully private test instance (`VH_TEST_MODE=1`): its own database, paths, ports,
  CLI socket and FUSE mount. It refuses to start if anything would point at a real install. `vh` honours
  `VAULTHALLA_CLI_SOCKET` to talk to such an instance.
- `make proof` runs the in-process integration proofs against a private instance, reproducibly by seed, with
  JSON/JUnit reports; it no longer installs over or tears down the development install.
- `tools/harness` drives many independent CLI, web-console (ws), HTTP and FUSE sessions against a private instance,
  checks every result against an authorization model, canaries and cross-surface parity, records a replayable trace,
  shrinks failures and keeps them as regressions. See `.claude/context/testing.md`.
