# Vaulthalla release notes

<!-- vl-release:entry version=1.14.0 -->
## 1.14.0 — Managed S3 and R2 buckets, and event-driven sync

_Released 2026-10-16_

AWS S3 and Cloudflare R2 credentials can now administer their account. Turn it on for an existing credential with
`vh upstream admin enable <key>` (or the credential's **Provider administration** panel), and Vaulthalla can list the
account's buckets, create a new bucket when you create a vault, adopt an existing bucket after a read-only admission
check, keep its own lifecycle rule on the buckets it manages, and delete buckets it created when you explicitly ask.
One access-key pair per account does everything; who may do what is decided by the new `admin.upstream` permissions
(view, configure, provision, protect, unprotect, destroy), granted to the built-in roles as documented.

**Protection locks.** `vh upstream protect <key> <bucket> --reason …` excludes a bucket from everything Vaulthalla
does: no probes, adoption, vault binding, lifecycle or event rules, sync reads or writes, emptying or deletion,
including scheduled jobs, retries and work already running. The lock belongs to the bucket (provider, account and
name), not the credential, survives restarts and credential re-creation, and is loaded before the server makes any
upstream request. Removing it needs its own permission and an explicit, audited confirmation.

**Event-driven sync.** `vh upstream events enable <vault>` subscribes a vault's bucket to a Vaulthalla-owned queue
(AWS S3 → SQS, Cloudflare R2 → Queues with HTTP pull), and files written to the bucket by other tools reach the vault
within seconds: each event is stored before its queue message is acknowledged, deduplicated and ordered, applied to
the remote index, and only the changed keys are synced (about one HEAD and one GET per new object, one HEAD per
removal), under the vault's request and price budgets. Other applications' notification rules are preserved; only
Vaulthalla's own rules and queues are ever removed. Removals upstream now delete the vault's copy when it hasn't
changed since the last sync and the provider confirms the object is gone. If events may have been lost (dead-lettered
messages, or a delivery gap longer than the queue keeps messages), the next sync lists the bucket again instead of
trusting events. `vh upstream events status` shows queue health, backlog and errors; `repair` fixes
failed provisioning. R2 event delivery needs one Cloudflare API token (Queues: Edit, Workers R2 Storage: Edit), stored
sealed on the same credential; the R2 S3 key pair can't sign Cloudflare's account API.

**Safety.** Creating a bucket never takes over an existing one: name collisions are refused without changing
anything, and an existing bucket must be adopted explicitly. Deleting or detaching a vault leaves its bucket and
objects in place. Deleting a bucket is a separate operation, only for buckets Vaulthalla created and no vault uses,
after a preflight with object and version counts and a typed confirmation, and it reports partial results honestly.
Every control-plane change is in the upstream audit log (`vh upstream audit`), which shows each reader only the
credentials they may view. Bucket names and regions are validated before any request, and a bucket's identity (and so
its lock) follows the credential's endpoint, whatever provider label the credential was saved under.

Existing credentials and vaults are unchanged until you turn administration on: plain credentials make no
administrative calls. Also fixed: an object overwritten upstream by another tool could fail to sync on vaults that
don't encrypt upstream. On vaults that do, an object without Vaulthalla metadata over an encrypted file is still
treated as tampering unless the vault's event subscription imports foreign objects (the default for adopted buckets;
other vaults that encrypt upstream ignore foreign objects unless you choose `--foreign-objects import`).

<!-- vl-release:entry version=1.13.0 -->
## 1.13.0 — Vaulthalla on macOS

_Released 2026-10-13_

Vaulthalla now installs on Apple Silicon Macs (macOS 14 or later) as a system service, from an installer package or
Homebrew (`brew install --cask vaulthalla/tap/vaulthalla`). Both run the same package: it creates a hidden
`_vaulthalla` service account, keeps vault data, sealed secrets and a private PostgreSQL database in
`/Library/Application Support/Vaulthalla` where only that account can read them, and starts the server, the web
console and the database at boot through launchd, before anyone logs in. The person installing it is enrolled for
`vh` and becomes the CLI `admin` (change it later with `vh`). Upgrading reinstalls over the top and keeps every vault;
`/Library/Application Support/Vaulthalla/uninstall.sh` removes it and keeps the data unless given `--purge`.
On macOS the vault isn't mounted in Finder yet: use the web console, the S3 gateway or `vh fs`.

HTTPS on macOS is one command: `sudo vh setup caddy --domain vault.home.arpa` serves the console, WebSockets,
uploads and downloads (and, with `--s3-domain`, the S3 gateway) through Caddy, running as the service account.
Internal names (`.home.arpa`, `.internal`, `.lan`, `.local`, `.test`) get certificates from Vaulthalla's own CA, which is
name-constrained to your hostnames so trusting it on a device can't let it vouch for any other site; `--trust` trusts
it on the Mac, and the command prints how to trust it on phones and other computers. Public names get Let's Encrypt
certificates, through Cloudflare DNS with `--dns-cloudflare` (the same credentials file `vh setup nginx` uses on
Linux) when the Mac isn't reachable from the internet, or use your own certificate with `--cert`/`--key`. Caddy renews
certificates by itself; `vh setup caddy --status` shows what is served, and `vh teardown caddy` removes it.

The package isn't signed by Apple yet. Opened from Finder, macOS blocks it the first time: choose **Open Anyway** in
System Settings → Privacy & Security, then run it again. `sudo installer -pkg vaulthalla-<version>-arm64.pkg -target /`
and the Homebrew cask install it without that prompt.

Existing behavior on Ubuntu installs is unchanged. Internals that touched Linux-only system calls now sit behind small
platform interfaces, so one code base builds and passes its tests on both systems.

New: `vh fs ls`, `vh fs get` and `vh fs put` read and write vault files over the control socket, without a mount, with
the same permissions as the web console. Downloads to a file are written atomically and only when complete; uploads
are stored only when every byte arrives, and `--overwrite` refuses to replace a file that changed meanwhile. This is
an interim path for macOS until its FUSE mount can map local users to their own Vaulthalla identities.

Fixes found along the way:

- `vh … --help` no longer reads an uninitialized color theme while rendering help text.
- The `vh` client and daemon compute the control-socket address length portably and refuse socket paths that are
  too long instead of truncating them.
- On the FUSE mount, an exchange-rename (`renameat2(RENAME_EXCHANGE)`) is now refused instead of silently
  overwriting the second file.
- Binding the first CLI user to the `admin` account no longer attempts a group change the unprivileged daemon could
  never make (membership is already checked when `vh` connects).

<!-- vl-release:entry version=1.12.3 -->
## 1.12.3 — Trustworthy integration testing, an admin-role fix and typed console errors

_Released 2026-10-12_

##### Fixed

- **Admin roles:** deleting an admin role that accounts still hold is refused again. The check counted the wrong
  table, so a held role could be deleted, which silently removed the admin role from every account that had it; an
  unused role could also be refused for no reason.
- **Web console:** moving, renaming or copying into a folder that doesn't exist (or from a missing source) now says
  "not found" instead of a generic error.

##### Web console follows the server's command definitions

- The console's command types are generated from the daemon's own command definitions, so the two can't drift
  apart unnoticed.
- After a daemon upgrade, an open console page notices that the server's commands changed and suggests reloading
  (once, without interrupting anything). This uses a new read-only command, `meta.contract.get`, which needs a
  signed-in session and returns no secrets.

##### For contributors: an integration engine for the real daemon

- `vaulthalla-server` can run as a fully private test instance (`VH_TEST_MODE=1`): its own database, paths, ports,
  CLI socket and FUSE mount. It refuses to start if anything would point at a real install. `vh` honours
  `VAULTHALLA_CLI_SOCKET` to talk to such an instance.
- Tests are isolated from the development install. `make test` (DB-backed unit tests) and `make itest` (integration
  proofs) each run against a database created for that run and dropped afterwards, with private paths and nothing
  installed. The old `make run_test`, which installed a test build over the system binaries, rotated a shared test
  password into the daemon's environment file and could reach the development database, is gone (`run_test` now
  runs `make itest`). One-time setup: `sudo tools/harness/bootstrap.sh`.
- Test mode can no longer fall back to the configured database: it needs its connection settings in the environment,
  and the test-only wipe helpers refuse any database that isn't a test database.
- `tools/harness` drives many independent CLI, web-console (ws), HTTP and FUSE sessions against a private instance,
  checks every result against an authorization model, canaries and cross-surface parity, records a replayable trace,
  shrinks failures and keeps them as regressions. See `.claude/context/testing.md`.

<!-- vl-release:entry version=1.12.2 -->
## 1.12.2 — Identity checks from memory and cheaper previews

_Released 2026-10-11_

Every FUSE operation, preview, download, S3 request and permission check used to reload the caller's account (and,
for most permission checks, the vault owner's) from the database, together with the full member list of every group
the account belonged to. Accounts and groups now live in memory as one shared object each, kept current as they
change, so those checks no longer wait on the database.

##### Faster

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

##### Changes take effect at once

- A rename, a role change, a vault role or permission override, a group membership or a group's vault role, made
  from the CLI or the web console, applies to the very next request everywhere: open web sessions, the S3 gateway
  and the FUSE mount included, without waiting for a session to refresh.
- Changes made directly in the database (for example with `psql`) are picked up within about a second.
- **Security:** a deactivated account could still use the FUSE mount through its Linux UID; it is now refused at the
  next operation, like everywhere else. Deleted and deactivated accounts are refused at the next request even on
  connections that were already open.
- Password hashes are no longer kept in memory with the account; logins and password changes read them from the
  database each time.

##### Previews and thumbnails

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

##### Fixes

- Overwriting a file from the web console or the API now updates the folder sizes the file browser shows right away;
  they could stay stale.
- Vault roles now grant their sync permissions. A member whose vault role (their own, or a group's) allows triggering
  a sync, editing sync settings or signing the encryption waiver can now do so on that vault; before, only admin
  vault globals counted, so built-in roles such as contributor, editor and manager could not trigger a sync on
  someone else's vault.
- S3/R2 vaults using the `keep_remote` or `keep_newest` conflict policy no longer download a file again on every sync
  after downloading it once. A file neither side changed since its last sync is left alone under every policy.

<!-- vl-release:entry version=1.12.1 -->
## 1.12.1 — Restarts in about a second

_Released 2026-10-11_

`systemctl restart vaulthalla`, package upgrades and `make dev` used to take 5 seconds on a freshly started daemon
and, once it had been running for a while, 30 seconds ending in a forced kill. The daemon now stops in tens of
milliseconds and a full restart takes about a second.

- **No more 30-second hang on stop.** The thread pools could lend a worker to another pool; stopping them then
  waited forever on a worker parked on the wrong queue, until systemd killed the process. Workers are no longer lent,
  and every pool stops within a deadline.
- **Stopping no longer waits out timers.** Services, the watchdog and the sync scheduler wake the moment a stop is
  requested instead of finishing their current sleep, and all services stop in parallel (FUSE last).
- **A held mount can't block shutdown.** If something still has the mount open (a shell sitting in
  `/mnt/vaulthalla`, an open file), the daemon aborts its FUSE connection after one second instead of hanging; the
  journal names the connection it aborted.
- **A hard limit.** From the first SIGTERM the daemon exits within 10 seconds whatever it is doing, including a
  startup stuck on an unreachable database; a second SIGTERM exits at once.
- **Faster startup.** The daemon no longer computes four deliberately slow password hashes on every start.
- The Runtime health page no longer shows the "Borrowed" worker column (workers are not lent anymore).

<!-- vl-release:entry version=1.12.0 -->
## 1.12.0 — Current PDFium and libpqxx 8, with sturdier database connections

_Released 2026-10-10_

This release moves Vaulthalla onto the two libraries it builds for itself, now published only on apt.vaulthalla.sh:
PDFium tracking Chrome Stable (Chromium 155) and libpqxx 8. apt.vaulthalla.sh is now a required package source;
the upgrade pulls in the new PDFium runtime (`libpdfium8059`) and no longer needs a libpqxx runtime package.

#### Upgrading

- Upgrade with `sudo apt update && sudo apt upgrade` (or `apt full-upgrade`, or `apt install vaulthalla`). Plain
  `apt-get upgrade` keeps Vaulthalla back because the release adds a new dependency (`libpdfium8059`).
- `libpdfium-2025` and `libpqxx-7.10` are no longer needed and `apt autoremove` offers to remove them. They are no
  longer published, so keep them until you are sure you won't roll back to an earlier release.
- libpqxx 8 requires PostgreSQL 11 or newer; a remote database server older than that is refused at startup.
- An IPv6 `database.host` may be written with or without brackets (`::1` or `[::1]`).

#### PDF previews

- PDF previews and thumbnails render with current PDFium. Documents that use predefined CJK character maps now
  render their text; the previous build left it blank.
- Pages render straight into the preview image: about half the memory per page and noticeably faster renders, with
  identical output.

#### Database connections

- A database server or network that stops answering without closing the connection is now detected within about a
  minute (TCP keepalives), and the connection is replaced instead of a request waiting for the kernel's two-hour
  timeout.
- A connection that libpqxx reports as unusable after an error (for example a COMMIT whose outcome is unknown) is
  replaced before it can serve another request.
- Vaulthalla's sessions show up as `vaulthalla` in `pg_stat_activity`.

<!-- vl-release:entry version=1.11.2 -->
## 1.11.2 — Sync conflict resolution, recoverable vault deletion, Health access and streaming folder downloads

_Released 2026-10-10_

This release adds a way to resolve sync conflicts, resolves the open product decisions on vault deletion, stats access, sharing settings, folder deletion
and copying, and makes folder downloads stream at any size.

#### Upgrade notes

- **Two settings were renamed.** `sharing.enable_public_links` is now `sharing.enable_email_validated`, and
  `s3_gateway.default_remote_sync_strategy` / `default_remote_conflict_policy` moved to `vaults.s3`. Your
  `config.yaml` is not rewritten: the old names keep working and the daemon logs a deprecation warning at startup.
  Rename them when convenient; saving settings from the console writes the new names.
- **Deleting a vault is now a schedule, not an immediate delete.** `vh vault delete` and the console make the vault
  disappear at once and purge its data when `vaults.retention_window` ends (default 5 minutes); until then
  `vh vault restore` brings it back. A deleted vault's name, mount name and bucket stay reserved until it is purged.
  Scripts that delete vaults keep working; `--now` and keeping an S3 vault's encrypted objects without an exported
  key need `--yes` / `--accept-key-loss` when there is no terminal. Migration 106 adds the deletion records.
- **A user whose API keys are still bound to a vault can't be deleted**, including vaults deleted but not yet purged.
- **New S3/R2 vaults default to the `ask` conflict policy** (`vaults.s3.default_remote_conflict_policy`). Existing
  vaults keep theirs. Migration 107 adds the new "resolve sync conflicts" vault permission and grants it to every
  role that can trigger a sync.
- **Health has its own permission.** Migration 105 adds "view stats" (`admin.stats.view`) and grants it to the admin,
  auditor, platform operator and super admin roles, plus any custom role that could already see Health.
- **`rmdir` on the mount refuses a folder that still has contents** (`ENOTEMPTY`). It used to delete the contents.
- **Copying needs create permission where the copy lands** and download permission on what is copied. The built-in
  `reader` role (no upload) can no longer copy.

#### Sync conflicts

- Under the `ask` policy, a file changed both in the vault and in the bucket since they last agreed is recorded as
  a conflict, once, and waits for a decision while everything else keeps syncing. A change on only one side syncs
  normally, and a conflict closes itself if both copies become identical again.
- Resolve conflicts with **Keep local** or **Keep remote** on the console's Sync Conflicts page (a button in the top
  bar and a System page, shown only when there is something to resolve): select several or all, filter by vault,
  and click a conflict to compare both copies side by side (images, media, a text diff, or the metadata). The bucket
  copy is fetched only when you open it, within the vault's request and price budgets; copies over 32 MiB aren't
  previewed.
- From the CLI: `vh sync resolve` (or `vh resolve`) opens an interactive session in a terminal; `--list`,
  `<id...> --keep-local|--keep-remote` and `--vault X --all` script it.
- Resolving needs the new vault permission `vault.sync.action.resolve_conflicts` plus Overwrite on the file. A
  decision is refused if either copy changed after the conflict was recorded.

#### Vault deletion

- Deleting a vault no longer leaves its data behind. It disappears from listings, the mount, shares, sync and the S3
  gateway at once, stays restorable for `vaults.retention_window` (`vh vault restore`, or Vaults → Deleted vaults),
  and is then purged: local data always, and the bucket's objects too when you chose that at delete time.
- **Delete now** skips the restore window after one extra confirmation. It never shortens the key retention window.
- Encryption keys of deleted vaults are kept for `vaults.tpm_retention_window` (90 days), or
  `vaults.s3.tpm_retention_window` (180 days) for S3 vaults, and stay exportable with `vh vault keys export`. A small
  record of the vault (name, key, dates) remains after the purge.
- Deleting an S3 vault asks whether to delete the bucket's objects too. Keeping encrypted objects whose key was never
  exported needs an explicit acknowledgement on the CLI and in the console, because without the key they can never be
  decrypted again. `vh vault keys export` now records each export, and every delete warns when a vault's key was never
  exported. Existing installs have no export records yet, so the first delete of each encrypted vault warns.
- New: `vh vault deleted` lists vaults waiting for their purge, `vh vault restore` brings one back, and `vh vault delete`
  takes `--now`, `--delete-upstream` / `--keep-upstream`, `--accept-key-loss` and `--yes`.

#### Health and stats

- The built-in admin role can open Health and see the health dot. Health, the health dot and every server, daemon
  and system statistic follow `admin.stats.view` instead of a full-admin check.
- A vault's owner sees that vault's statistics without an admin role; other people's vaults stay private.
- The 24-hour trend view reads the same 5-minute data as the 7-day view, so it is never larger than the week.
- Unknown values are shown as unknown: cost figures without a monthly budget are no longer a fake $0.00, and the
  file-metadata cache no longer reports "0 B of 0 B". The preview cache reports its configured size from startup.

#### Sharing and settings

- Operators can turn share links off: `sharing.enabled` turns off every link, and `sharing.enable_anonymous` and
  `sharing.enable_email_validated` turn off one kind each. Links already handed out stop working while their switch
  is off and work again when it is turned back on. The console hides what is turned off.
- New S3/R2 vaults take their sync strategy and conflict policy from `vaults.s3.default_remote_sync_strategy`
  (`cache`) and `vaults.s3.default_remote_conflict_policy` (`keep_local`) when none is given, from the CLI or the
  console.
- `websocket_server.max_connections` (default 1024) now limits open console and share connections. Connections over
  the limit get `503` and the console reconnects.

#### Web console

- Icons are cyan again, matching the console's accent. They rendered black everywhere; status icons keep their
  status colors.

#### Files

- Deleting a file no longer deletes the folder it was in or that folder's parents, in the console, on the mount,
  through the S3 gateway or by sync. Delete the folder itself to remove it.
- Copying a folder copies everything inside it, and every copied file opens immediately (copied files used to have
  no content until a sync pass that never ran). Copies are checked against permissions for every item and against
  the vault's quota, and a failed copy leaves nothing behind.
- Folder downloads stream as a ZIP at any size: the 256 MiB and 4096-file limits are gone and the browser shows the
  archive's size and progress from the start. File names keep their Unicode characters and leading dots inside the
  ZIP. Folders with more than 50,000 items are refused with a clear message in the transfer panel, and a file that
  can't be read mid-download fails the download instead of saving a damaged archive.
- On share links, a folder download counts as one download, and the console's pre-download check never counts.

<!-- vl-release:entry version=1.10.2 -->
## 1.10.2 — Security and stability fixes

_Released 2026-10-09_

This release fixes authorization, account lifecycle and filesystem-cache defects found while provisioning an
authorized penetration-test fixture, plus the open log-hygiene and API-consistency bugs.

#### Sharing and authorization

- **Public share links work on any folder or file, not just the vault root.** The share permission check evaluated
  the share path in the wrong path space, so every subfolder or file target was refused with
  `missing_share_public_permission`. In the same path, a share path that matched another vault's mount name was
  judged against that other vault's root. Links are now checked against the vault they belong to, the filesystem
  permission check refuses any entry from a different vault, and a link whose `root_entry_id` doesn't match its
  path, vault or type is refused when it is created.
- **The mount no longer confirms that hidden paths exist.** Inside a vault, a path you have no permission to see now
  consistently answers `No such file or directory`, whichever operation reaches the daemon first. Paths you can see
  but can't act on still answer `Permission denied`.
- **The mount no longer serves cached metadata across users.** The kernel caches lookups and file attributes for all
  users of the mount, so a user without access could `stat` a path another user had just opened (for up to a minute
  after it was created). Every lookup and `stat` is now checked for the calling user. Files you may download are now
  also visible to you in lookups and directory listings even when your role grants no preview.

#### Accounts

- **Deleting a user no longer fails** for anyone who has shared, used a share link, uploaded into someone else's
  vault, kept file versions or held a lock. Attribution and audit records keep their history without the identity
  link. File locks and the public share links the user created are removed with the account.

#### Filesystem

- **Recreating a vault with a deleted vault's name starts empty.** The filesystem cache kept a deleted vault's
  entries, so uploads into a new vault with the same name failed with `Upload target already exists` until the
  daemon restarted. Renaming a vault also moves its cached entries to the new mount name.

#### Logs and operations

- Rate-limited and unauthorized web-console requests log one warning per client and command per minute, plus a
  "suppressed N more" summary, instead of one line per request. The rate-limit message names the right limiter.
- Expected refusals (permission denied, not found, invalid input) are no longer logged as database errors, and a
  failed refresh-token check logs its reason.
- Stopping or upgrading the package no longer marks `vaulthalla-web.service` as failed.

#### Breaking: S3 gateway and pricing WebSocket payloads

- `s3.gateway.credentials.*` commands no longer accept a bare `id`. Name the credential with `credential_id` (or
  `access_key` / `name`), a role override with `override_id`, and a permission with `permission_id` (or
  `permission_qualified` / `permission_name`). A payload that carries `id` is refused with an `invalid` error naming
  the expected field. The bundled web console already sends the explicit fields. `vh s3-gateway creds role override
  remove` also takes `--override-id`.
- The same rule now applies to pricing: `pricing.budget.override.approve` / `.deny` take `override_id` and
  `pricing.notifications.ack` takes `notification_id`. A bare `id` (or a missing field) is refused with `invalid`.

<!-- vl-release:entry version=1.10.1 -->
## 1.10.1 — Simpler Cloudflare DNS-01 setup for the S3 domain

_Released 2026-10-09_

#### `--certbot-dns-cloudflare` takes the credentials file directly

Publishing the S3 gateway on its own hostname used to take two flags. Now the credentials file is the value of
`--certbot-dns-cloudflare`:

```bash
sudo vh setup nginx --domain vault.example.com --s3-domain s3.vault.example.com \
  --certbot-dns-cloudflare /etc/vaulthalla/certbot/cloudflare.ini
```

The older form, `--certbot-dns-cloudflare --cloudflare-credentials <path>`, still works, and
`--cloudflare-credentials <path>` on its own now also selects DNS-01 mode. If both flags are given with different
paths, setup refuses to run instead of guessing.

#### The credentials file is documented

`vh setup nginx --help` and the [S3 Gateway Setup](https://vaulthalla.io/docs/s3-gateway/setup) guide now explain
the whole setup:

- the file holds `dns_cloudflare_api_token = <token>`, a Cloudflare API token with **Zone → DNS → Edit** on the
  zones of both hostnames;
- how to create it as a root-only `0600` file;
- why it has to stay in place after setup (certbot reads it again on every renewal);
- why `--s3-domain` needs DNS-01. Vaulthalla renders both HTTPS hosts itself, and DNS-01 is the mode that issues
  one certificate covering both, without opening port 80.

The S3 gateway guide no longer shows `--s3-domain` with `--certbot`, which setup has always refused.

#### `vh setup` help no longer needs sudo

`vh setup nginx --help` (and `--help` on `setup db`, `setup remote-db` and the `teardown` commands) asked for sudo,
and under sudo printed the lifecycle helper's terse internal help instead of the documented one. Help now comes
from the same command reference as every other `vh` command, without sudo. If the daemon is not reachable, for
example before `vh setup db`, `sudo vh setup … --help` still prints the helper's own help.

<!-- vl-release:entry version=1.10.0 -->
## 1.10.0 — Rich previews, streaming downloads and safer key rotation

_Released 2026-10-08_

### Security fixes in previews and share links

- **Previews now follow vault permissions.** Rendered previews require the same vault access as downloads, and
  someone who cannot read a vault can no longer tell which paths exist in it.
- **Preview-only share links stay preview-only.** They show rendered images and PDF pages, but never hand out a
  file's original bytes (or a converted copy of something only a download link should get).
- **Nothing decrypted is left on disk for previews.** PDF and image previews render in memory, cached previews are
  encrypted with the vault key (old unencrypted thumbnails are deleted on upgrade and regenerate), and the daemon
  tells nginx not to buffer decrypted responses to disk. New installs also disable proxy buffering in the nginx
  site; an existing site file is not modified and relies on that header.
- **Hostile images and PDFs are bounded:** oversized images are refused from their header before decoding
  (`preview.max_render_pixels`, 64 MP by default), at most four renders run at once, and a file that fails to
  render is not retried until it changes.
- **A crash restarts the daemon instead of hanging the mount.** A race in file-type detection could crash the
  daemon under concurrent uploads; it is fixed, and a crash now exits and restarts cleanly rather than leaving
  `/mnt/vaulthalla` (and `apt`) stuck.

### Long generated passwords are accepted again

Changing a password (including the first-login change of the `admin` password) refused most long, randomly
generated passwords with "New password does not meet password policy". The dictionary check rejected any
password that contained a common word of three or more letters anywhere inside it, so a 64-character password
from a password manager almost always failed on some fragment like `doc` or `bet`, and the longer the password,
the more likely it was to be refused.

The dictionary check now refuses a password only when the password itself is a dictionary word, ignoring case
and any digits or symbols around it (`Sunshine2024!` is still refused). Registration and password changes now
apply the same policy:

- 8 to 128 characters.
- Passwords shorter than 20 characters need at least one letter and one digit. Longer passwords and
  passphrases (`correct-horse-battery-staple`) don't.
- Not a dictionary word, not on the common-password lists, and not found in public breaches.

When a password is refused, the error now says which rule it broke.

### Downloads stream, with seeking and no size cap

Downloads are streamed straight from the encrypted vault instead of being decrypted into memory first: the first
byte arrives immediately, memory use no longer grows with file size, and the old 256 MiB download limit is gone
(folder downloads as ZIP are still limited). Range requests, `HEAD`, ETags and conditional requests work, so
video and audio seek, resumable download tools resume, and the browser can revalidate instead of refetching.
Integrity is still checked: each file version is authenticated once before ranged reads are served from it.
Busy servers answer new HTTP connections beyond `http_preview_server.max_connections` with a retryable 503
instead of slowing everyone down.

### Safer vault key rotation

**Vault key rotation can no longer strand files on a dropped key.** A rotation now finishes only when every encrypted file was re-encrypted and committed; if any file fails, is open, or changes mid-way, the previous key stays loaded (so everything stays readable) and the next sync retries. Each file's new ciphertext is written to a durable side file and swapped in only after the database records its new IV, and an interrupted rotation is repaired on the next sync or restart by keeping whichever copy authenticates. Cloud vaults in Cache mode now rewrite their local copies too, remote-only files are re-encrypted without writing anything locally, and empty files no longer abort a rotation. File overwrites through the web and API also replace ciphertext atomically.

### Cloud vaults: local copies first, remote-only files readable

**Reading a cloud file that is stored locally no longer downloads it from S3.** Share-link downloads and previews and the built-in S3 gateway read the local encrypted copy, which costs no requests or egress (gateway range requests read only the requested bytes). **Files that exist only in the bucket (Cache mode) can now be previewed and downloaded:** the first read fetches the object once, after the same price-budget check sync uses and under a strict request cap, verifies it in full, and keeps it as a local encrypted copy (an object stored unencrypted upstream is encrypted on the way in; nothing decrypted touches the disk). Budget refusals are reported as unavailable instead of spending. Operators who would rather not keep copies can opt into metered range reads (`preview.media.remote: ranged`; note that individual ranges are not integrity-checked) or turn remote reads off (`off`). Fetched copies are not evicted yet.

### STEP/STP models in the 3D viewer (optional package)

Install `vaulthalla-preview-cad` to preview STEP and STP CAD models: the server converts each model to glTF once, and the web console shows it in the 3D viewer. Conversion runs in a separate, sandboxed helper process, never inside the daemon: it gets the file's bytes over a private channel (nothing decrypted is written to disk), cannot open files for writing, reach the network, start programs or interfere with the daemon, and is killed if it exceeds its memory, CPU-time, thread, wall-clock or output limits (`preview.derive.*` in `config.yaml`). A malformed or hostile model fails that one conversion and nothing else. The sandbox needs a kernel with Landlock enabled: without it the helpers refuse to run and conversions report "converter unavailable" (the daemon log says why). Helpers run only from root-owned locations, and `preview.derive.helper_dir` can be changed only in `config.yaml`, not from the web console.

`vaulthalla-preview-cad` and `vaulthalla-preview-media` are separate packages that `vaulthalla` only suggests, so the core package still installs without Open CASCADE or FFmpeg's libraries. Every new `preview.*` setting is optional; the shipped `config.yaml` lists them, commented out, with their defaults.

#### Optional media helper (`vaulthalla-preview-media`)

- A new optional helper probes video and audio files (container, codecs, duration, and whether Chrome, Firefox
  and Safari can play them directly), renders poster frames, and transcodes to browser-safe H.264/AAC as
  fragmented MP4 or HLS. It runs out of process, reads plaintext only through the daemon's range channel (no
  plaintext temp files, and MP4 files with the index at the end are read in place), and sandboxes itself before
  touching input. Output size, duration, dimensions and wall time are capped.
- Hardware encoding (`preview.media.hwaccel`: VAAPI, Quick Sync, NVENC) is probed and falls back to software on
  any failure. Hardware paths have not yet been validated on real GPUs; software (libx264) is the tested path.

#### Converted previews are cached encrypted

- Converted models, posters and transcodes are produced once per file version by a small background queue
  (`preview.derive.max_concurrency` at a time, at most `preview.derive.max_queue` waiting) and stored encrypted
  with the vault key. Editing a file makes the old conversion invalid automatically; deleting a file (moving it
  to the trash included) or removing a vault deletes its conversions; a finished key rotation drops conversions
  sealed under the old key. A file that cannot be converted is not retried until it changes (or for
  `preview.derive.failure_ttl_hours`).
- The cache stays within `caching.max_size_mb`, and conversions unused for `caching.thumbnails.expiry_days` are
  removed. On the first start after upgrading, thumbnails that older versions stored unencrypted are deleted;
  they are regenerated, encrypted, when next viewed.

### Web console
#### Previews in the web console

The preview sheet now opens far more than images and PDFs, in the console and on share links:

- **Video and audio** play in the browser with seeking, straight from the encrypted vault (no autoplay). When
  your browser can't decode a format you get a Download button and, when the optional media converter is
  installed on the server, a "Convert for playback" option.
- **PDFs** page through every page (buttons or PageUp/PageDown), fitted to the page or the width.
- **3D models** (GLB, glTF, STL, OBJ, and STEP when the optional CAD converter is installed) open in an interactive viewer you can
  orbit, pan and zoom. The viewer only downloads when you open a model.
- **Text, code and Markdown** files open as text (Markdown rendered safely: no embedded HTML, no remote images).
  In the console you can edit and save them in place; if someone else saved the file since you opened it, you
  choose whether to reload their version, overwrite it, or copy your text, and nothing is lost silently.
- **SVG and WebP** images show as they are.
- Share links respect their permissions: a preview-only link shows image and PDF previews, and explains that
  video, audio, 3D and text need a link that allows downloads.
- Downloads of any size stream directly; the console checks a download with a lightweight request first instead
  of starting it twice.

#### 3D models in the browser

GLB, glTF, STL and OBJ files open in an interactive 3D viewer: drag to orbit, right-drag or Ctrl-drag to pan,
scroll or pinch to zoom, with Fit, Reset, a model-sized ground grid, a wireframe toggle and a readout of meshes,
triangles, vertices, materials and bounding-box size. glTF files that keep their buffers and textures in separate
files, and OBJ files with a `.mtl` material library and textures, load those files from the same vault folder
(a missing texture shows the model untextured instead of failing). Draco- and meshopt-compressed glTF work offline:
their decoders ship with the console, and the viewer never contacts a third-party host (a model that points at
another host is not followed). Models over 20 million triangles, and glTF files that require KTX2/Basis compressed
textures, show an explanation instead of freezing the tab. The viewer (Babylon.js) loads only when a model is
opened, so the file browser and share pages load no extra JavaScript for it.

<!-- vl-release:entry version=1.9.2 -->
## 1.9.2 — Quiet package upgrades

_Released 2026-10-05_

`apt upgrade` no longer prints a fifteen-line status report for Vaulthalla. A clean upgrade now prints one line:

```
[vaulthalla] Upgraded 1.9.1-1 -> 1.9.2-1: services restarted, daemon healthy. Log: /var/log/vaulthalla-package.log
```

A second `Action:` line appears only when something is waiting on you (for example, the generated web `admin` password file still exists). Warnings still print, one line each. A hard failure, such as the daemon not running after the restart, a missing CLI socket, no TPM backend or a failed database bootstrap, prints an error and the full summary. Fresh installs and reinstalls still print the full summary with the database, TPM, nginx and web console next steps.

Every step, the full summary and systemctl output are now kept in `/var/log/vaulthalla-package.log` (root-readable, rotated at 1 MiB, removed on purge). To see everything on the terminal, run `sudo env VH_PACKAGE_VERBOSE=1 dpkg-reconfigure vaulthalla`. `apt remove` now prints a single line when the services stop cleanly.

<!-- vl-release:entry version=1.9.1 -->
## 1.9.1 — A rebuilt web console, readable files on the mount, correct times on non-UTC servers

_Released 2026-10-04_

### The web console, rebuilt

The web console has a new look and a new structure. It keeps the dark theme with cyan accents, now with one
consistent visual language on every page, and it is much lighter: pages load about a third less JavaScript,
and the console only asks the daemon for what the page on screen needs.

- **One navigation for everything.** A single sidebar groups the console into Files, Shares, Vaults, Access
  (users, groups, roles), Storage & cost (provider credentials, cost control, S3 gateway) and System (health,
  notifications, settings). It only shows what your role can use. Press `⌘K` / `Ctrl+K` anywhere to jump to a
  page, vault, user or action.
- **Files.** Upload with the new Upload button (files or whole folders) or drop several files and folders at
  once; every dropped item now arrives. Rename, move, copy and delete from a menu on each row, by right click, or
  from the keyboard (arrows, Enter, F2, Delete, Ctrl+A); deleting always asks first. Folder paths are part of the
  address, so back, refresh and links to a folder work. Large folders stay fast. Transfers show progress, speed
  and time left, can be cancelled, retry briefly interrupted files, and the browser warns before you close a tab
  mid-upload. A refused download (for example over the size limit) is reported in the transfers panel instead of
  replacing the page.
- **Vaults** open as one page with tabs: overview (live stats), access (assign, change and remove roles for users
  and groups, plus path-scoped permission overrides), shares, sync & cost, gateway and settings.
- **Health** (formerly the dashboard) shows only what the daemon reports: when a value is unknown or the daemon
  is unreachable it says so, and never shows green. Polling stops when you leave the page or hide the tab.
  The daemon's own health ratings were corrected too: a value it can't measure (slow queries without
  `pg_stat_statements`, connection errors) is rated unknown instead of healthy, the oldest database transaction
  warns only after an hour (it used to warn on every idle install), and FUSE errors that are part of normal
  operation (a lookup of a name that doesn't exist yet) no longer raise a warning.
- **Shares.** Recipients get the same file browser, with paths in the address. The new "Upload dropbox" preset
  lets people send files into a folder without seeing what's already there. Rotating or revoking a link asks first.
- **Safer by default.** Every destructive action asks for confirmation. Logging out clears everything the browser
  held for the session, and the access token is no longer stored in the browser. When the daemon restarts, the
  console says it is reconnecting instead of sending you to the login page.
- **Fixes:** users can be deactivated again (choosing "Inactive" used to save the user as active); editing a user
  no longer fails; any admin role can be assigned; "Last login" shows "Never" instead of 1969; the version in the
  sidebar is the real one; vault owners show on the vault list; light-mode browsers no longer get an unreadable
  login page.
- **Password age is recorded.** The daemon now stores when each account's password was last set (by the user,
  by an admin reset, on the CLI or with `vh setup set-super-admin-password`), so the console can show it. It was
  always empty before. Accounts whose password hasn't changed since the upgrade show no date.
- Old console addresses (for example `/dashboard`, `/api-keys`, `/pricing-budget`, `/operator-email`) redirect to
  their new pages.

### Files on the mount are always readable, and always encrypted on disk

Vault files are stored encrypted on disk, and the mount at `/mnt/vaulthalla` is where you read them in plain form.
Until now the mount handed out the stored bytes as they were. Any file uploaded through the web console, synced
down from S3, or renamed or moved (on the mount or in the console) read back as **encrypted bytes** with `cat`,
editors, `tar` or `rsync`. Files written through the mount were left **unencrypted** on disk until something renamed
them. Web downloads were never affected.

- The mount now decrypts files when they are opened and encrypts changes when they are closed or synced
  (`fsync`). `close` returns once the change is encrypted on disk, so the console shows it right away. Renaming or
  moving a file no longer re-encrypts it.
- `ls -l`, `stat` and `du` report the real file size. They used to show 0 for files written through the mount and
  the encrypted size (16 bytes more) for others, after a restart.
- `truncate` works on the mount. It used to be silently ignored.
- Opening a file for writing now needs write permission on it, and a refused write changes nothing. A user with
  read-only access could open a file for writing, and a refused write had already been written to disk.
- **On the first start after the upgrade** each vault's files are checked once: files left unencrypted are
  encrypted, and wrong sizes are corrected. This takes longer on vaults with many files written through the
  mount, and an S3 vault may upload those files once more. Nothing needs to be done by hand.
- Temporary decrypted copies (for downloads and previews) are now readable only by the daemon.
- `ls -l` and `stat` on the mount pick up changes made elsewhere (a file replaced in the console, a sync download)
  right away. They used to keep showing the old size until the kernel dropped the file from its cache.
- A vault no longer disappears from the mount when the kernel frees cached directory entries (under memory
  pressure, or `echo 2 > /proc/sys/vm/drop_caches`). The vault and everything in it used to answer "No such file or
  directory" until the daemon restarted.

### Faster page loads, previews and downloads

Every check of a signed-in session cost the daemon about half a second, because session tokens were stored with
the same slow hash as passwords. A console page load paid that twice, and every preview, download and upload
paid it once. Session tokens are now stored as a SHA-256 digest, which is the right tool for long random values
the server mints itself, so the check takes well under a millisecond. Existing sessions keep working: each
stored token is upgraded the first time it is used.

The console also stopped asking the daemon about the session before loading every page. It only checks that you
have a session cookie; the console then confirms the session over its connection, sends you to the login page if
it was revoked, and shows its reconnecting state (not the login page) while the server is unreachable.

The cost-alerts bell is lighter and more accurate. It fetches the 8 newest open alerts and a summary from the
server instead of 50 alerts every minute, and its count and colour cover every open alert you can see, so an
older critical alert is never hidden. When more alerts are open than shown, "View all N alerts" opens Cost
control.

### An optimized, hardened daemon

The daemon and CLI in the packages are now compiled with full optimization (`-O3`) and Debian's standard hardening:
`_FORTIFY_SOURCE=3`, stack protector, stack clash protection, control-flow protection, and full RELRO. Packages up
to 1.8.x shipped them unoptimized and without those protections, because of a build-configuration mistake, so this
release is faster across the board (the server binary is also about 30% smaller).

### Times on servers outside UTC

On a server whose PostgreSQL time zone isn't UTC, most times the daemon reported were off by the UTC offset: a
file uploaded a minute ago showed as "7 hours ago" on a Mountain Time host, and `vh user list` printed local times
marked as UTC. The daemon now talks to PostgreSQL in UTC, and the upgrade converts every stored time to a
time-zone-aware value.

- **Before you upgrade:** the upgrade reads times already in the database as the database's current time zone
  (`SHOW timezone` in `psql`). If you changed that setting after installing, times written before the change stay
  off by the difference.
- The first start after the upgrade rewrites the tables that hold times once, so it takes longer on large
  installs. Servers already on UTC skip the rewrite.

### API keys

- Editing an API key in the web console now changes the key in place. It keeps its id, and every vault that
  uses it keeps its S3 binding. Saving an edit used to delete the key and create a new one, which silently
  removed the bucket binding (and upstream encryption setting) from every vault using the key. Leave the secret
  empty to keep the stored one. New credentials are checked against the provider before they are saved, and
  running vaults switch to them right away.
- Removing an API key that a vault still uses is refused, on the CLI and in the web console, and the message
  names those vaults. Deleting a user is refused the same way while another vault still uses one of their API
  keys. The database enforces this as well: a schema migration changes the vault-to-key reference from
  "delete the vault's binding" to "refuse".

### Uploads and downloads

- Browser uploads no longer fail after 30 minutes. An upload session used to expire 30 minutes after it
  started, so long uploads on slow links failed at the end and lost their partial data. A session now stays
  open while data keeps arriving, expires after 30 minutes without activity, and ends after 24 hours at most.
- Downloads keep their file names. Names with non-ASCII characters (`naïve 日本.pdf`) arrive intact in current
  browsers, and names that start with a dot (`.env`) keep the dot instead of downloading as `env`.

### Link shares

- Folders that received uploads through a share link can be deleted again. Deleting such a folder (or anything
  above it) used to fail with a database error; the link's upload history is now kept without its folder.
- The "Upload Dropbox" share role is upload-only on new installs: recipients can upload but can't list the
  folder, so they don't see each other's submissions. Existing installs keep their `share_upload_dropbox` role
  unchanged. To make it upload-only there too, run `vh role vault update share_upload_dropbox --deny-dirs-list`.

### Vault permission overrides

Path-scoped allow/deny overrides on a vault role assignment (for example "deny downloads under `/finance/**`")
can now be listed, added, changed and removed from a vault's Access tab, not only with `vh vault role override`.

### Folder sizes and item counts

- Moving or renaming a file or folder into another folder now updates the size and item count of both folders
  (and the folders above them), as uploads always did. A folder that received files by a move used to show
  "0 items", and the folder they came from kept counting them. Copies and deletes update them too.
- Moving or renaming a folder into another folder now works when the folder it leaves holds anything else. It
  used to fail with an I/O error. Files inside a folder moved under a newer folder keep working: their location
  on disk was worked out from the wrong folder order.
- Deleting an empty folder (or one holding only empty folders) from the web console removes it. It used to stay
  listed after its contents on disk were gone.
- Counts that are already wrong on an existing install are not recomputed by this release.

### Vault sizes and quotas

- Each vault now reports its own size. Every vault used to report the size of the whole storage directory,
  which is mostly the default vault's data, so an empty vault (or an S3 vault with nothing cached locally) showed
  the default vault's usage in the vault overview, the Health storage view and `stats.vault`.
- Vault quotas are checked against that vault's own data. A vault with a quota used to be charged for every other
  vault's files and the preview cache, so uploads and syncs into it could be refused as over quota while it was
  nearly empty.
- For an S3 vault the reported size is what is stored on this server (the local cache), not the bucket's total.
- The vault list now includes each vault's owner name.

### Idle CPU

The daemon no longer keeps one CPU core busy while it waits for the next vault sync. A background loop
re-checked the sync schedule nonstop, so an idle server showed a constant load of about 1.0 with one core at
100% (1.8.0 and earlier). It now sleeps until the next sync is due and still starts on-demand syncs
immediately.

<!-- vl-release:entry version=1.8.0 -->
## 1.8.0 — One rulebook for the CLI and the web console

_Released 2026-10-03_

The CLI and the web console now share one implementation of every account, role, group, vault, API key, S3
gateway, budget and settings operation, so both apply the same permission rules. The audit that started this
found eleven places where the two disagreed; all are closed.

### Before you upgrade

- **The universal admin password is gone.** If the web `admin` account still uses the old default password,
  the first start of 1.8.0 replaces it with a random one, ends admin's web sessions and writes the new password
  to `/var/lib/vaulthalla/super_admin_initial_password`. Read it with
  `sudo cat /var/lib/vaulthalla/super_admin_initial_password`. Passwords you set yourself are not touched.
- New installs get a random admin password in the same file. Change it with `vh setup set-super-admin-password`
  (run as the Linux user bound as the super admin, without `sudo`), or keep it and delete the file. Nothing
  forces a password change at sign-in any more.
- Deleting a user now asks first, and their vaults are destroyed unless you transfer them:
  `vh user delete <user> --transfer-to <other>`. Scripts need `--yes`.

### Security

- Admin accounts are judged by what their role actually grants. Nobody can assign a role above their own, or
  manage an account whose role exceeds theirs; the super admin can't be renamed or have its password reset by
  others.
- Deleting, deactivating, re-roling or resetting a user ends that user's sessions immediately, and deactivated
  users can't sign in.
- List commands refuse SQL injected through `--sort`.
- S3 gateway role grants can't exceed the person granting them, bucket names aren't revealed before
  authorization, and a vault name never resolves to another owner's vault.
- Vault budgets need vault edit rights, so an owner can't drop a budget an administrator set. Only administrators
  can transfer vault ownership.

### Fixes

- Accounts on built-in roles can use their vaults through their role's global policy again. Every account had
  been written with an empty one, which also left the S3 gateway bucket list empty. Startup repairs existing
  accounts.
- Vault changes take effect without a restart, and `vh status` and the web console agree when PostgreSQL is down.
- Login rate limiting sees real client addresses behind nginx (#125), and login bursts no longer stall other
  connections (#132). Intermittent nginx 502s during the periodic session sweep are fixed.
- Stopping the S3 gateway or preview service no longer risks a crash while connections are open.
- Role permission flags, `vh role admin create --from` and vault role overrides work as documented, and unknown
  CLI options are rejected instead of ignored.

### New

- The web console's delete-user dialog asks the same question as the CLI and can transfer the user's vaults; the
  vault form picks a new owner by username.
- New roles can start from an existing one (`--from`, or "Start from" in the web console) and then keep their own
  copy of its permissions.
- `vh setup nginx` warns before exposing the console while the generated admin password's plaintext file still
  exists, and offers to change the password or delete the file.
- `vh user update --disable|--enable`; `vh user create` creates the user's default vault, as the web console does.
