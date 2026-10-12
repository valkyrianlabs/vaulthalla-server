<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Portability groundwork

No change in behavior for Ubuntu installs. Internals that touched Linux-only system calls now sit behind small
platform interfaces, which lets the daemon build and pass its test suite natively on macOS (Apple Silicon) for
development. macOS packaging is not part of this release.

Fixes found along the way:

- `vh … --help` no longer reads an uninitialized color theme while rendering help text.
- The `vh` client and daemon compute the control-socket address length portably and refuse socket paths that are
  too long instead of truncating them.
- Binding the first CLI user to the `admin` account no longer attempts a group change the unprivileged daemon could
  never make (membership is already checked when `vh` connects).
