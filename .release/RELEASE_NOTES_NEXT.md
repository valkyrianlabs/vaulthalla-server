<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# macOS crash durability

On macOS, every write Vaulthalla needs to survive a power loss now reaches the disk itself, not just the drive's
volatile cache. Covered: file saves and seals, key rotation, recovery snapshots and versions, cloud hydration, `vh fs
put`, durable preview artifacts and the bootstrap secret. Plain `fsync` on macOS does not guarantee this, so an
interrupted write could previously leave a file that didn't match its database row. Linux behaviour is unchanged.
