<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.

Parallel changes: add a file per change to .release/notes.d/ (and .release/changelog.d/)
instead of editing this file; `vlr prepare` appends them below this body. The title here
is still required; the body may then be empty.
-->
# macOS package for 1.22
