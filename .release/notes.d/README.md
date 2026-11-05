# Release-note fragments

One new file per change: `<issue>-<slug>.md`, user-facing Markdown describing what changes for users and operators.
It may start with one `## Section` heading (e.g. `## S3 gateway`) to be grouped under it. `vlr prepare` assembles
the fragments after `../RELEASE_NOTES_NEXT.md` (which holds the release title) and deletes them. This README is
ignored. Format and rules: `vlr help staging`.
