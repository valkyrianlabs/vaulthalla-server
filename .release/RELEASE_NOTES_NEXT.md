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
- Vault roles now grant their sync permissions. A member whose vault role (their own, or a group's) allows triggering
  a sync, editing sync settings or signing the encryption waiver can now do so on that vault; before, only admin
  vault globals counted, so built-in roles such as contributor, editor and manager could not trigger a sync on
  someone else's vault.
- S3/R2 vaults using the `keep_remote` or `keep_newest` conflict policy no longer download a file again on every sync
  after downloading it once. A file neither side changed since its last sync is left alone under every policy.

#### Fixed

- **Admin roles:** deleting an admin role that accounts still hold is refused again. The check counted the wrong
  table, so a held role could be deleted, which silently removed the admin role from every account that had it; an
  unused role could also be refused for no reason.
- **Web console:** moving, renaming or copying into a folder that doesn't exist (or from a missing source) now says
  "not found" instead of a generic error.

#### Web console follows the server's command definitions

- The console's command types are generated from the daemon's own command definitions, so the two can't drift
  apart unnoticed.
- After a daemon upgrade, an open console page notices that the server's commands changed and suggests reloading
  (once, without interrupting anything). This uses a new read-only command, `meta.contract.get`, which needs a
  signed-in session and returns no secrets.

#### For contributors: an integration engine for the real daemon

- `vaulthalla-server` can run as a fully private test instance (`VH_TEST_MODE=1`): its own database, paths, ports,
  CLI socket and FUSE mount. It refuses to start if anything would point at a real install. `vh` honours
  `VAULTHALLA_CLI_SOCKET` to talk to such an instance.
- `make proof` runs the in-process integration proofs against a private instance, reproducibly by seed, with
  JSON/JUnit reports; it no longer installs over or tears down the development install.
- `tools/harness` drives many independent CLI, web-console (ws), HTTP and FUSE sessions against a private instance,
  checks every result against an authorization model, canaries and cross-surface parity, records a replayable trace,
  shrinks failures and keeps them as regressions. See `.claude/context/testing.md`.

