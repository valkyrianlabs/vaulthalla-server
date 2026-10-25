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

## Item versions for sync clients

Every file and folder the console, Desktop and other ws clients list or look up now carries a `metadata_version`, and
every file a `content_version`. The content version is exactly the strong ETag `/download/content` serves for the
file's current bytes, so a client can tell from a listing which files changed without asking for each one, and send it
back as a precondition. It changes on every write and stays the same across rename and move. The metadata version
changes on rename, move, mode change and any change of the modification time. An entry's id stays the same across
rename and move, so it can serve as a stable item identifier. Renaming or touching an empty file no longer changes its
ETag. Nothing else changes for existing clients: the fields are additive.

## Security

- **Folder listings hide what you may not see.** The web console and Desktop (`fs.dir.list`) and `vh fs ls` now leave
  out files and folders you aren't allowed to look up, as the mounted filesystem already did, and a folder's size and
  item counts no longer include them. The Linux mount hides two more cases it used to list: entries matched by a deny
  override whose pattern starts above the folder (such as `/**/secret.txt`), and every file for a role that can list
  folders but neither preview nor download files. Anyone who could see the names of entries they couldn't open no
  longer sees them.
- **Moving something into a folder now needs permission to create it there.** Moving or renaming a file or folder into
  another folder, in the web console, Desktop or the mounted filesystem, used to check only that you could move or
  rename the source. It now also needs what creating it in the destination needs: upload for a file, create-folder
  for a folder, and for a folder, the same for everything inside it. Refused moves change nothing; in the Linux mount
  they fail with "permission denied" (or "no such file or directory" for a folder you can't see). Renaming within the
  same folder works as before.
