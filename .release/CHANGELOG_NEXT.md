<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- macOS: `uninstall.sh` (also run by `brew uninstall --cask vaulthalla-server`) says which daemon it is waiting on
  while launchd stops it (up to 75 s), instead of pausing silently.
- CLI tables (`vh fs ls` and every other `vh` table) measure, truncate and pad cells by display width instead of
  bytes, so long names with accents, CJK or emoji are never cut mid-character and columns stay aligned; malformed
  UTF-8 in a name shows as U+FFFD (#273).
- FUSE: every request is answered, even when its operation fails unexpectedly. A database pool timeout (or an
  unknown inode in rename) during unlink, rmdir, rename or any other op used to leave the kernel request unanswered, so
  `rm`, `mv` and the like hung; they now fail with EAGAIN (database unreachable) or EIO. FUSE stats count such ops
  as errors, not successes (#263).
- FUSE stats: a refusal by the permission model (a calling uid with no Vaulthalla user, or an RBAC denial) counts as
  an expected error for every op, not an alertable one. System processes that stat every mount (MOTD scripts, ssh
  logins) no longer put the Health dashboard's FUSE card into error. EACCES from anything else stays alertable.
- `vh device pair --json`: opens the caller's pairing window without waiting (a terminal attached or not) and prints
  `window` (`opened_at`, `expires_at`), `port`, `remote`, `listening`, `node_id` and `server_spki_sha256`, what
  Vaulthalla Desktop on the same Mac reads to pair itself through `vh` with no code; `--close --json` prints
  `{"closed": bool}`. Refusals stay exit 2 on stderr.
- macOS: the `vaulthalla` meta cask's `postflight_steps` open Vaulthalla Desktop once on first install (a marker in
  its Caskroom; upgrades don't reopen it, the open may fail without failing the install). Desktop 0.5.0+ then pairs
  with the local server through `vh` as the console user (trust model: the macOS account is the authenticated space).
  cask-smoke checks the marker and quits Desktop before zapping it.
- macOS: master keys are sealed with the Secure Enclave by default (`secrets_backend` `secure-enclave`; #290): a
  non-permanent SE P-256 key per secret (AfterFirstUnlockThisDeviceOnly, private-key usage), ECIES X9.63-SHA256
  AES-GCM, stored as `<state>/.sealed_<name>.blob/<name>.se`; created and opened only by the daemon under launchd.
  - Secrets sealed by the `file` backend (macOS 1.18.0-1.20.x) move into the Secure Enclave on the daemon's first
    unseal; the plaintext `.key` file is removed after the new blob is verified.
  - Where no Secure Enclave key can be used (checked once per start with a throwaway key) the daemon falls back to
    `file`, logged and reported. `-Ddarwin_sealer=file` builds the development backend.
  - cask-smoke checks the reported backend, the blob format and that secrets reopen after a daemon restart.
- Security: a folder's size no longer reveals how much it holds that the caller cannot see. `fs.metadata` and FUSE
  `stat` of a directory cover only entries the caller can Lookup, as `fs.dir.list` already did (lookup's attributes
  withhold the size for such callers). Super admins and vault owners still see the stored totals (#269).
- Filesystem change journal (#259): migration 115 `fs_change_log` + `fs_change_revision`, written by row triggers on
  `fs_entry`/`files`/`directories`/`symlinks` in each mutation's transaction (every write path) and on the RBAC rows
  that decide Lookup (resets); commit-ordered revisions assigned by a lock-free-for-writers sequencer.
  - ws `fs.changes.list {vault_id, since?, limit?}` → `{vault_id, revision, changes[], more, expired}` (model
    `FsChange`), filtered by Lookup visibility; needs List on the vault root. Janitor prunes after 7 days / 1M revisions.
  - Contract test `test_fs_change_journal_contract.py` keeps every SQL writer of the entry tables classified; vhbench
    gains a FUSE seal scenario (`--only seal`).
