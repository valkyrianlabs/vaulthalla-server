<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Vault keys after a restart mid-rotation, and S3 listings beyond 1,000 objects

**Key rotation survives a restart.** A vault key rotation is prepared by `vh vault keys rotate` and finished by the
next sync pass. If the daemon restarted in between, it could not load that vault's key at all (the log showed
`Unknown column name: 'updated_at'`), so the vault stayed unreadable until the rotation was completed by hand. The
daemon now loads both the new and the previous key after such a restart, files not yet re-encrypted stay readable,
and the rotation finishes on the next pass as usual.

**S3 listings beyond 1,000 objects.** Listing an AWS S3 vault, or a prefix in one, that holds more than 1,000 objects
now returns every object. The second and later pages of a listing were signed with their query parameters in the
wrong order, which AWS rejects with `SignatureDoesNotMatch`: the paged listing failed outright, and the older
whole-bucket listing quietly stopped after the first 1,000 keys. Requests that were already in order sign exactly as
before.
