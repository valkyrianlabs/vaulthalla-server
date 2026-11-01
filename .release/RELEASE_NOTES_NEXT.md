<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Vaulthalla on macOS installs as a meta cask

## Homebrew

`valkyrianlabs/tap/vaulthalla` is now a meta cask. It installs nothing itself and depends on
`valkyrianlabs/tap/vaulthalla-server` and `valkyrianlabs/tap/vaulthalla-desktop`, so the server and Vaulthalla
Desktop each install and upgrade to their own latest release. The server package no longer carries a copy of the
Desktop app: 1.20.0 shipped Desktop 0.2.0 inside it, and upgrading the old `vaulthalla` cask replaced a newer,
self-updated app with that copy. The casks no longer conflict with each other.

Homebrew loads a dependency cask only from a trusted tap, so the meta cask needs `brew trust valkyrianlabs/tap` once.
`vaulthalla-server` and `vaulthalla-desktop` named in full still need no trust step.

**If you installed the `vaulthalla` cask before 1.20.1**, move to the new one with an uninstall and a fresh install.
Both keep vault data, the database and configuration:

```bash
brew uninstall --cask valkyrianlabs/tap/vaulthalla
brew trust valkyrianlabs/tap
brew install --cask valkyrianlabs/tap/vaulthalla
```

Don't `brew upgrade` it: Homebrew installs the new dependencies first and then runs the old cask's uninstall, which
removes the server and the app it just installed. If that already happened, `brew reinstall --cask
valkyrianlabs/tap/vaulthalla-server valkyrianlabs/tap/vaulthalla-desktop` restores them, data intact.

The installer package (`vaulthalla-<version>-arm64.pkg`) installs the server only and no longer offers Vaulthalla
Desktop under Customize; download Desktop from its own releases.
