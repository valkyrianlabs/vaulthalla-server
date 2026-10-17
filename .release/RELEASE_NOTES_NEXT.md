<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Vault keys load after a restart mid-rotation

**Key rotation survives a restart.** A vault key rotation is prepared by `vh vault keys rotate` and finished by the
next sync pass. If the daemon restarted in between, it could not load that vault's key at all (the log showed
`Unknown column name: 'updated_at'`), so the vault stayed unreadable until the rotation was completed by hand. The
daemon now loads both the new and the previous key after such a restart, files not yet re-encrypted stay readable,
and the rotation finishes on the next pass as usual.
