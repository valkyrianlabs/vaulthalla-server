<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Identity checks from memory and cheaper previews

Every FUSE operation, preview, download, S3 request and permission check used to reload the caller's account (and,
for most permission checks, the vault owner's) from the database, together with the full member list of every group
the account belonged to. Accounts and groups now live in memory as one shared object each, kept current as they
change, so those checks no longer wait on the database.

#### Faster

- FUSE operations (`stat`, `ls`, `open`, reads and writes) no longer query the database to identify the caller or to
  check vault permissions.
- Thumbnail grids, previews, downloads and S3 gateway requests no longer reload accounts per request.
- Requests signed in by the session cookie (thumbnails, previews, downloads) check the session with one database read
  instead of three; the session signing key stays in memory instead of being read and unsealed for every request.
  Revoked sessions are still refused at the next request.
- Listing a folder in the FUSE mount (`ls`) checks the database with one query instead of reloading the folder and
  each of its subfolders, and no longer scans every cached entry to find the folder's contents.
- Adding, overwriting or deleting a file updates the totals of every folder above it in one statement instead of
  two per level.

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

#### Previews and thumbnails

- The file grid's readiness check (`/preview/batch`) answers from the cache index in one query instead of reading
  and decrypting every cached thumbnail just to say it exists.
- A file that can't be previewed (corrupt or over a limit) is reported as such once; the grid used to keep asking
  for it.
- Opening an image also leaves its grid thumbnails behind, and concurrent requests for the same file share one
  decode instead of each decoding it. The image or PDF page you opened is sent as soon as it is ready; its grid
  thumbnails are finished right after, from the same decode.
- Background thumbnail generation (uploads, cloud sync, grid fills) has its own render budget and can no longer
  make the image viewer wait or answer "busy".
- Serving a cached preview costs one database round trip instead of six, and PDF page previews no longer read a
  second cache entry for the page count.
- The grid asks for thumbnails sized for its tiles (256 px, 512 px on high-density screens) instead of stretching
  128 px images. Thumbnails are smaller to store and send (4:2:0 chroma), and transparent PNGs render on white
  instead of black. Existing thumbnails are regenerated on first view.
- Cached previews are no longer flushed to disk one by one (they are verified on every read and regenerated if a
  crash damaged one), which makes generating thumbnails much lighter on slow disks.

#### Fixes

- Overwriting a file from the web console or the API now updates the folder sizes the file browser shows right away;
  they could stay stale.
