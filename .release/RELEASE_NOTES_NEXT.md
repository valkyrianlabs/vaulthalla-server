<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Editors can save over files on the mount

Renaming a file over an existing one through the FUSE mount (`mv new.txt existing.txt`, and the way vim, LibreOffice
and most IDEs save: write a temporary file, then rename it over the original) failed with an I/O error. It now
replaces the existing file the way `rename(2)` does: the old version goes to the vault's trash exactly as if it had
been deleted (its previews are dropped, cloud vaults delete the remote copy on the next sync), and the renamed file
takes its place in one step. Replacing a file needs permission to delete it, as deleting it would. A folder can
replace an empty folder; renaming a file over a folder, a folder over a file or over a non-empty folder is refused
with the usual errors.

A rename that fails part-way now changes nothing. Before, a failed rename into another folder moved the file's bytes
to the destination while its record stayed at the source, leaving the file unreadable.

The console and API keep refusing a rename or move onto an existing name.
