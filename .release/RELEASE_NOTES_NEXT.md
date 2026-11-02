<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# macOS package and Homebrew casks for 1.21

The macOS installer package and the Homebrew casks of 1.21.0 were held back by a check in the release's cask test;
this release publishes them. Everything in 1.21.0 is included.

- The `vaulthalla` meta cask opens Vaulthalla Desktop once, on its first install. Uninstalling and reinstalling it
  doesn't open Desktop again; Desktop still sets itself up with this Mac's server whenever it starts.
