<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# APT signing key kept current through upgrades

`vaulthalla` now depends on `vaulthalla-archive-keyring`, which owns `/usr/share/keyrings/vaulthalla.gpg`: the
`signed-by=` key that `install.sh` and the documented manual setup have always configured. When the repository's
signing key is renewed (for example a new expiry date), the keyring package updates it on the next upgrade, so
existing installs keep verifying `apt.vaulthalla.sh` without downloading the key again or editing their APT sources.

**Upgrading.** `sudo apt upgrade` (or `apt-get dist-upgrade`) installs the new dependency. A plain `apt-get upgrade`
never installs new packages and holds `vaulthalla` back until you run one of those, or
`sudo apt install vaulthalla-archive-keyring` first. The signing key fingerprint is
`0657 4F63 2342 3EBC 99A1  DF7B E906 C69B 29C0 E706`.

No daemon, database or configuration changes.
