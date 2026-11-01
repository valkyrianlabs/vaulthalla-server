<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# The macOS package and Homebrew casks of 1.20.1

1.20.1 published its Debian packages and docs, but not its macOS package or Homebrew casks: a check in the release's
Homebrew smoke test named casks the way `brew list` doesn't accept, and the release stopped before publishing them.
1.20.2 publishes them. Everything in the 1.20.1 notes applies: `valkyrianlabs/tap/vaulthalla` is now a meta cask over
`vaulthalla-server` and `vaulthalla-desktop`, it needs `brew trust valkyrianlabs/tap` once, and if you installed the
old `vaulthalla` cask, uninstall it and install it again rather than `brew upgrade` it (vault data is kept).
