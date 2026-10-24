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

## No server mount on macOS

The macOS server never mounts vaults, and no longer carries the unused macFUSE build path. Finder access belongs to
Vaulthalla Desktop, which is building it on Apple's File Provider. `vh status` and the console's Runtime page now say
so on the mount line. If an older `config.yaml` on a Mac sets `mount.mode` to `multiuser` or `service_private`, the
daemon runs with the mount disabled and logs a warning instead of reporting degraded health. `vh fs`, the web console
and the S3 gateway remain the ways to reach vault files on a Mac. Linux is unchanged.
