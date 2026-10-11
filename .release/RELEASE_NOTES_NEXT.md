<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Identity checks from memory

Every FUSE operation, preview, download, S3 request and permission check used to reload the caller's account (and,
for most permission checks, the vault owner's) from the database, together with the full member list of every group
the account belonged to. Accounts and groups now live in memory as one shared object each, kept current as they
change, so those checks no longer wait on the database.

#### Faster

- FUSE operations (`stat`, `ls`, `open`, reads and writes) no longer query the database to identify the caller or to
  check vault permissions.
- Thumbnail grids, previews, downloads and S3 gateway requests no longer reload accounts per request.

#### Changes take effect at once

- A rename, a role change, a vault role or permission override, a group membership or a group's vault role, made
  from the CLI or the web console, applies to the very next request everywhere: open web sessions, the S3 gateway
  and the FUSE mount included, without waiting for a session to refresh.
- Changes made directly in the database (for example with `psql`) are picked up within about a second.
- **Security:** a deactivated account could still use the FUSE mount through its Linux UID; it is now refused at the
  next operation, like everywhere else. Deleted and deactivated accounts are refused at the next request even on
  connections that were already open.
- Password hashes are no longer kept in memory with the account; logins and password changes read them from the
  database each time.
