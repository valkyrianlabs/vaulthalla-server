# Vaulthalla release notes

<!-- vl-release:entry version=1.22.1 -->
## 1.22.1 — MFA for administrators, step-up confirmation, opaque S3 storage and customer-held recovery

_Released 2026-11-06_

- **HTTPS by default on Linux.** A new install (and an upgraded host still on the unmodified packaged site) serves
  the web console over HTTPS with a certificate generated for the host, and `http://` redirects to `https://`.
  Browsers ask you to accept that certificate once; `sudo vh setup nginx` prints its SHA-256 fingerprint to compare.
  The package renews it on upgrades, and `sudo vh setup local-tls` does so on demand. For a certificate browsers
  trust right away, use `vh setup nginx --certbot` (now with HSTS) or `--certbot-dns-cloudflare`. A host behind
  another TLS terminator keeps plain HTTP with `vh setup nginx --plain-http`. A site you edited, or one
  `vh setup nginx` generated without a certificate, isn't changed on upgrade; the upgrade prints a reminder.
- The console and its file lanes now send `X-Content-Type-Options`, `Referrer-Policy: no-referrer` (share links
  carry their token in the address), `X-Frame-Options: DENY` and `frame-ancestors 'none'`.
- The web socket refuses connections opened by pages on other sites. If you serve the console from a different host
  than the daemon, list it under `websocket_server.allowed_origins`.
- **The S3 gateway now listens on loopback by default** (`127.0.0.1:39000`), and a config without a `host` setting
  never binds every interface. Remote S3 clients use the HTTPS S3 hostname (`vh setup nginx --s3-domain` or Caddy).
  Existing `config.yaml` files keep their settings.

- **Files in use are no longer stored as plaintext.** While a file is open through the mounted filesystem, and while
  an upload or `vh fs put` is in flight, its working copy on disk is now encrypted with a key that exists only in the
  daemon's memory and changes every time the daemon starts. Nothing a crash or power loss leaves behind can be read,
  and the next start deletes it.
- **If a change can't be saved back to its vault**, the daemon now keeps it (encrypted) and retries every minute, on
  the next save or close of the file, and once more when it shuts down; reopening the file shows the change, and a
  file deleted in the meantime comes back as a new file where it was. The log says when that happens and when it
  succeeds. **The trade-off:** such a change lives only as long as the daemon process. If the daemon stops before a
  retry succeeds, or crashes, the change is lost, and the log names how many files were affected at shutdown or at
  the next start. Earlier versions kept these changes in plaintext in `/var/lib/vaulthalla/.fuse-plaintext/unsaved/`
  across restarts; if you see a log warning that plaintext files are still there, recover what you need from them
  and delete them (the upgrade never deletes them).

- **Clearer wording about upstream encryption.** The console, the docs and the README now say exactly what an S3/R2
  vault with upstream encryption protects: file contents are encrypted before upload, while file and folder names are
  visible to your storage provider. The Encryption page adds a table of who can read what for local and S3/R2 vaults
  and states that a vault can't be restored from its bucket alone.

- **Groundwork for provider-blind storage.** Every vault and every file now gets a permanent random identifier, and
  each S3/R2 vault records its storage layout. `vh vault info` shows both, and the vault details the API returns
  include the layout: encrypting vaults report `path (v0)` (encrypted objects under their file paths, as before) and
  the others `transparent`. The layout follows the vault's upstream encryption setting; there is nothing to choose.
  Nothing changes in your buckets: object names, contents and sync behave exactly as before. The upgrade assigns the
  identifiers to existing vaults and files once, in the same database transaction as the schema change.

- **New file content is stored in an authenticated, chunked format (VHF1).** Every file written from this release
  on (saves through the mount, web and device uploads, resumable uploads, the S3 gateway, restores, sync downloads and
  key rotation) is sealed in VHF1: a 120-byte authenticated header that names the vault and the file's generation,
  then 64 KiB AES-256-GCM chunks, each authenticated with its position and with whether it is the last one. Truncated,
  reordered, spliced or swapped content is refused instead of served, and partial reads (video seeking, previews,
  downloads with a range, `preview.media.remote: ranged`) now authenticate every byte they return. Uploaded objects
  of encrypting S3/R2 vaults are the same bytes: still one object per file version (multipart is only transport, never
  one object per chunk), about 0.025 % larger for big files and 120 bytes larger for small ones; an empty file is a
  136-byte object.
- **Existing content keeps reading normally.** Files, local versions and snapshots written by earlier releases are
  converted to VHF1 in the background after the upgrade (see "Existing files and recovery points are converted to
  VHF1"); bucket objects of existing encrypted S3/R2 vaults keep their format until the layout migration of a later
  release. A later release retires the old format (#376). A resumable upload that was in progress during the upgrade
  finishes in the format it started in.
- The upgrade adds a generated `content_format` column to the file and recovery tables (one table rewrite); it changes
  no data.

- **Very large uploads to S3 and R2 no longer stop at about 48.8 GiB.** Multipart uploads now grow their part size
  with the object (5 MiB parts up to 48.8 GiB, larger parts above), so a single file can use the provider's full
  object size within the 10,000-part limit. Smaller uploads are unchanged.

- **Existing files and recovery points are converted to VHF1 in the background.** After the upgrade, the daemon
  re-seals every file, snapshot, local version and upstream backlog entry still stored in the legacy encryption format
  as VHF1, under the key version it already had: no key is rotated, and generations kept under a retired key stay
  under it. Each item is verified before its old form is removed (the old authentication tag over the whole file,
  then the new file read back in full with a matching plaintext digest), no plaintext is written to disk, and a crash
  at any point leaves everything readable and the conversion resumes. A snapshot that shares a file's bytes is
  converted once, with the file. The conversion pauses during a key rotation or salvage, is rate-limited
  (`vaults.format_conversion`: 32 MiB/s and 25 % of one CPU core by default), and `vh vault format status all` shows
  what is left per vault in items and bytes. S3/R2 vaults with upstream encryption convert their live files together
  with the bucket's layout migration in a later release; their recovery points convert now. Nothing needs to be done:
  converted files read exactly as before. The legacy format is retired in a later release (#376), which will refuse
  to install while anything legacy is left.

### Before you upgrade

- **Administrators must use a second factor.** Under the default `admins` policy, the super admin and every account
  whose role can change accounts, roles, settings or encryption keys must sign in with a passkey or an authenticator
  app. Their password-only sessions end at the first request after the upgrade, and the next sign-in walks them
  through setting one up. Passkeys need the console on a host name, not an IP address; an authenticator app works
  anywhere. Keep the recovery codes it shows you.
- **Sensitive actions ask you to confirm again.** Key export and import, account and role changes, secrets,
  settings and destructive actions need a fresh passkey or password-and-code confirmation in the console. `vh` on the
  server itself is unaffected.
- **Vaulthalla Desktop:** already-paired Macs keep syncing and backing up keys without prompts. Key import and vault
  removal started from Desktop are refused until Desktop supports device approvals; do them in the console or with
  `vh`.
- **Health may show `recovery_material_missing`.** An encrypted S3/R2 vault without a recovery recipient or a
  current key export now marks the node degraded until you add one (`vh vault keys recipient add`) or export its
  keys (`vh vault keys export`).
- **New encrypting S3/R2 vaults use the opaque layout** (no file names, paths or metadata visible to the provider).
  Existing vaults keep their layout until you move them with `vh vault migrate-layout <vault>`, which converts and
  verifies everything before cutover and removes the old objects only after a waiting period.
- **Local content converts in the background** to the authenticated VHF1 format after the upgrade, rate-limited;
  `vh vault format status all` shows progress.
- **Back up before upgrading,** as always: this release adds database migrations 117 to 131. To restore onto a new
  host later, keep the state directory or the exports from `vh secret export` (including `mfa-seal` and
  `mfa-pepper`).

### Also in this release

- Uploading a file of 5 MiB or more to an S3 or R2 vault could fail partway (a timeout, a SlowDown, a dropped
  connection) and still be treated as uploaded. Vaulthalla cancelled the incomplete upload at the provider but then
  carried on as if the file had arrived, so the bucket could be missing a file that the vault showed as synced. A
  failed part now fails the upload, and the file stays pending for the next sync pass.
- The installation guide now opens with an optional "Don't Trust Vaulthalla. Verify It." step. It shows how to
  clone the source and have your own AI coding agent audit it before you install, using the read-only prompt in
  `SECURITY_AUDIT_PROMPT.md`. The audit runs entirely on your side: nothing in Vaulthalla starts it or sends
  anything to Valkyrian Labs.
- Vaulthalla now starts its web console and HTTP listeners on hosts without outbound internet access. Until now
  the daemon downloaded password lists from GitHub every time it started, and on an offline, firewalled or
  air-gapped host that download failed and the web console and Desktop's HTTP lanes never came up. The lists now
  ship in the package (`/usr/share/vaulthalla/password-lists`) and change only with a release.
- Setting a password no longer fails when the server can't reach the Have I Been Pwned breach check. The check
  gives up after a few seconds, the bundled lists and the password rules decide, and the server log notes it. A
  password the service reports as breached is still refused.
- The access-token lifetime set in `config.yaml` (`auth.access_token_expiry_minutes`) now takes effect. The
  daemon was reading a different key, so a changed value was ignored and tokens always lasted 60 minutes.
  Configs that use the older `token_expiry_minutes` keep working, and the daemon logs a note to rename it.
- The sign-in cookie now lasts as long as `auth.refresh_token_expiry_days`. It was fixed at 7 days.
- Contributor docs: a security-first compatibility policy (`docs/contributors/compatibility-policy.md`). Security
  and recoverability of customer data take precedence over backward compatibility. Breaking changes are allowed
  where they remove a real risk, but never at the cost of data, keys or recovery material.
- The web console now signs you out after 30 minutes without use. Only keyboard, pointer and scroll input counts,
  so a tab left open in the background doesn't keep the session alive. After an idle sign-out, reloading the
  page shows the sign-in screen instead of signing you back in from the saved session. Change or turn off
  (`0`) the timeout with `services.connection_lifecycle_manager.idle_timeout_minutes` or under Settings →
  Services → Connections. Vaulthalla Desktop and share links aren't affected.
- Share links are now verified with a key that is sealed under the server's master key, like vault keys,
  instead of being stored in the database in readable form. The first start converts the existing key, so every
  existing link keeps working. **Downgrading to an earlier release after this one makes existing share links stop
  working** (they need to be created again). Share links also need the master key to be restored with a backup;
  see "Backup and recovery".
- Email-verified share links now work. Vaulthalla emails the 6-digit code to the address the visitor enters, if
  that address is on the link's list, through the email provider set up under `vh email` (Resend or SES). Until
  now no code was ever sent, so these links couldn't be opened. Every address gets the same reply, and the email
  contains only the code, with no file or folder names. Without email set up, Vaulthalla refuses to create
  email-verified links instead of making links nobody can open.
- A failed sign-in now always shows "Invalid username or password". The console used to say whether the account
  existed, was deactivated, or had a different password, which let anyone check which usernames exist. The exact
  reason is still in the server log.

### S3 gateway

- MinIO `mc` and the AWS Java SDK can now upload to the gateway over plain HTTP, for example to the direct listener
  at `http://127.0.0.1:39000`. Over HTTP these clients sign every chunk of the upload. The gateway checks each chunk
  against the one before it as the data arrives. It stores nothing until the whole upload has verified, so a chunk
  that is altered, missing or out of order fails the upload with `SignatureDoesNotMatch` and leaves any existing
  object untouched. Signed trailing checksums are verified too. `docs/s3-gateway/clients.md` lists the signing modes
  each client uses.
- An upload whose `aws-chunked` body is cut short or malformed now gets an S3 error: `IncompleteBody`, or
  `InvalidRequest` for bad framing or a chunk over 16 MiB. The gateway used to close the connection without answering.
- The S3 gateway checks request signatures with vl-sigv4, Valkyrian Labs' shared AWS Signature Version 4 library.
  AWS CLI, boto3, rclone and MinIO mc requests, presigned URLs included, are accepted exactly as before.
- Refused requests now carry the error code AWS S3 would send, so clients report the real cause instead of a
  signature mismatch: `RequestTimeTooSkewed` when the client's clock is off by more than 15 minutes (SDKs that correct
  their clock react to it), `InvalidAccessKeyId` for an unknown, disabled or expired gateway key,
  `AuthorizationHeaderMalformed` or `AuthorizationQueryParametersError` (HTTP 400) for a malformed signature,
  `XAmzContentSHA256Mismatch` when the body doesn't match its declared hash, and `AccessDenied` for an unsigned request
  or an expired presigned URL. A wrong secret is still `SignatureDoesNotMatch`.
- Requests that break SigV4 rules AWS S3 enforces are now refused too: an unsigned `Host` header, a credential date
  that differs from the request date, a presigned URL with `X-Amz-Expires=0` (it used to never expire), and a
  presigned URL that also carries an `Authorization` header. No client that works with AWS sends these.
- Requests whose credentials don't check out no longer cause a credential lookup: a request with a bad date, a stale
  timestamp or a mismatched body is refused before the gateway reads or decrypts any key.

### Under the hood

- Requests to S3, R2, SQS and STS for bucket administration, event notifications, full bucket listings and
  file-version recovery are now signed by vl-sigv4, Valkyrian Labs' shared AWS Signature Version 4 library, instead
  of a copy inside Vaulthalla. The signed requests are byte-for-byte the same, so nothing changes for providers or
  keys.
- Operator email sent through Amazon SES is signed by vl-sigv4 too. The requests are the same as before, so SES
  credentials and settings need no change.
  An SES endpoint configured with a path (an SES proxy such as `https://proxy.example.com/aws`) now works: sends
  through it used to fail with a signature mismatch because the path was left out of the signature.
- The everyday traffic of S3 and R2 vaults (uploads, downloads, listings, deletes, multipart uploads) is signed by
  vl-sigv4 as well, so all of Vaulthalla's AWS request signing now goes through that one library. The requests are
  the same as before. One rare failure is gone: a request signed at the very moment UTC midnight passed could carry
  two different dates and be refused by the provider; both dates now come from the same instant.

### Security

- **Tamper-evident audit trail.**
  - Every audit event is stored in the database as a link in a SHA-256 hash chain.
  - The server signs the end of the chain every 15 minutes and at shutdown, with its Ed25519 attestation key, and writes each signed head to `audit.log` (and syslog), so changed, inserted, reordered or removed events are detectable.
  - Review the trail in the console under **System › Audit trail**, or with `vh audit list|verify|export`. All of these need the **view audits** permission and are themselves recorded.
  - An export verifies offline with `tools/audit/verify_export.py`.
- **More events are recorded.**
  - Sign-ins (successful and refused, with the reason and address), sign-outs and idle sign-outs.
  - Password changes, role, assignment, override and group changes, and S3 gateway credential changes.
  - Deletes, renames, moves, copies and new folders from the web console. Files are named by entry id, never by name.
- **Retention and forwarding.**
  - Audit events are kept six years by default (`auditing.trail.retention_days`, minimum 30), the HIPAA documentation retention period.
  - `auditing.trail.syslog: true` also sends them to the local syslog for forwarding to a SIEM.
  - The unused `audit_log` table from early releases is removed. It was never written; any rows it held are kept as `audit_log_legacy`.

- **A lost master secret is never replaced silently.**
  - If the sealed secret that protects vault keys, provider API keys or S3 gateway credentials is missing while those records exist, Vaulthalla now refuses to generate a new one and says how to recover.
  - Before, it generated a new secret, which left every existing key undecryptable.
- **macOS: no silent fallback to unprotected files.**
  - Without a usable Secure Enclave, sealing refuses and health reports the backend as `unavailable`.
  - Breaking: a Mac that was running on the file fallback (an Intel Mac without T2, or a daemon outside launchd) must either move to a Mac with a Secure Enclave or set `secrets.allow_development_file_backend: true` in config.yaml. That setting is for development only. Existing secrets are kept as they are.
- **The sealing posture is visible.** `vh status`, health and the console show whether secrets are protected by `hardware` (a TPM or the Secure Enclave), `software` (swtpm) or `development` (files). The new `secrets.require_hardware: true` setting refuses anything but hardware sealing.

- **File names stay out of logs and URLs.**
  - `vaulthalla.log` and `audit.log` now name a file by its entry id (`entry 42`). A path with no entry yet appears as an opaque tag that is stable only while the daemon runs.
  - The new `logging.file_paths: full` setting adds vault paths back, for hosts that hold nothing sensitive.
  - The console addresses downloads and previews by entry id, so file names no longer reach web server access logs, proxies or browser history.
  - Breaking: scripts that read paths from `audit.log` must look them up by entry id (`vh fs`) or set `file_paths: full`.
- **Share links keep their token after `#`** (`https://host/share#vhs_…`). Browsers never send that part to the server or to other sites, so the token stays out of access logs and `Referer`. Links issued earlier keep working: they redirect once to the new form.
- **nginx access logs are redacted.** The Vaulthalla site (packaged, and generated by `vh setup nginx`) logs old `/share/<token>` paths as `/share/[redacted]`, replaces every query string with `?[redacted]`, and no longer logs `Referer`. Run `sudo vh setup nginx` to regenerate a site that `vh setup nginx` wrote before.

- **The S3 gateway no longer writes object data to disk as plaintext.**
  - Request bodies of streamed PUT and UploadPart requests are staged encrypted under a key that exists only in the daemon's memory, and deleted once the request is answered. Nothing a crash leaves behind can be read.
  - Multipart upload parts are stored encrypted under the vault's key, each bound to its vault, upload and part number, so an upload in progress can still be resumed after a restart or a vault key rotation. CompleteMultipartUpload streams the parts into the object without writing a plaintext copy.
  - A stored part that fails its integrity check makes CompleteMultipartUpload answer `InvalidPart`. Nothing is written, the upload stays open, and the client can upload that part again.
  - Part ETags, part sizes and object ETags are unchanged.
- **Upgrading converts what older versions left behind.**
  - On the first start, the daemon encrypts every part of in-progress multipart uploads that an older version stored as plaintext, after checking it against its recorded checksum, and then deletes the plaintext. Uploads in progress keep working.
  - A plaintext part that no longer matches its checksum is left as it is and logged. CompleteMultipartUpload refuses it, and it is deleted when the upload is aborted or expires.
  - Leftover plaintext request bodies (`<state dir>/s3-request-body/`) and the plaintext temporary file of an interrupted completion are deleted.
  - No operator action is needed. Downgrading after the conversion isn't supported: older versions can't read the encrypted parts, so complete or abort in-progress multipart uploads first.

- **Master secrets stay in locked memory and are wiped when released.**
  - The daemon's sealed master secrets (vault master, API key and S3 gateway masters, the JWT master, the DB password, the key attestation seed and the device identity), the share-token pepper and unwrapped vault keys are now held in memory that is kept out of swap where the OS allows it and zeroed before it is freed.
  - Code that uses them borrows them in place instead of copying them into ordinary buffers. The short-lived copies other libraries insist on are wiped on every path, including when an operation fails partway.
  - The DB password is no longer kept as plain text in the connection settings between connects.
  - Nothing changes in how secrets are sealed or stored, and no operator action is needed.

- **Optional: bind sealed secrets to Secure Boot (Linux, TPM PCR 7).**
  - Off by default. With `secrets.tpm_pcr_policy: pcr7` in config.yaml, secrets sealed from then on open only while the TPM's PCR 7 (the secure-boot state) is unchanged. The setting alone never rebinds existing secrets.
  - `sudo vh secret reseal --pcr7` binds the existing ones. It refuses unless a hardware TPM seals the secrets, every vault's keys have a confirmed backup and a `vh secret export all` is under 24 hours old. Each secret is sealed again beside the old one, opened and compared before it replaces it; no secret changes and nothing is re-encrypted.
  - After a firmware or Secure Boot change the bound secrets do not open. Vaulthalla refuses to start with an error naming PCR 7 and the recovery paths (the exports, or a recovery boot and `vh secret reseal --none`), and never creates replacements. The docs describe the update drill.
  - `vh secret policy`, `vh status` and health show the policy, and warn when secrets are PCR-bound and no export is newer than 30 days. macOS is unaffected: the Secure Enclave has no PCRs.

- **The vault master can be rotated.** `vh secret master rotate` replaces the installation secret that wraps every vault key, without re-encrypting any file.
  - The new wraps are staged and verified against each key's recorded key check before anything switches, and every key row switches in one step. An interrupted rotation resumes where it stopped.
  - The previous master is kept for a 7-day recovery window: `vh secret master rollback` returns to it, `vh secret master finalize` ends the window sooner. When the window ends, every key is verified again before the previous master is deleted.
  - Super admins only, from a terminal (never agents or the console), and every step is audited. `vh secret master status` shows the version and any rotation in progress.
  - A database backup taken before a rotation needs the previous master: after the window ends, restore it through the vault key exports.

- **The API key and S3 gateway masters can be rotated, and so can the JWT secret and the device identity.**
  - `vh secret master rotate --slot api-keys` and `--slot s3-gateway` replace the masters that wrap provider API key secrets (and Cloudflare provider tokens) and S3 gateway credential secrets, the same way as the vault master: staged, verified, switched in one step, with a 7-day recovery window (`rollback`, `finalize` and `status` take `--slot` too; `status --slot all` shows every master). The secrets themselves don't change and S3 clients keep their credentials. After the window, a database backup from before the rotation needs its API keys entered again and its gateway credentials reissued.
  - `vh secret jwt rotate` signs everyone out: a fresh JWT secret replaces the old one and every refresh token is revoked in one step, then every open console connection closes. Everyone signs in again. TOTP factors, recovery codes and share links are not affected.
  - `vh secret device-identity rotate` replaces the device listener's key. Every paired device is revoked and disconnected and pairs again with a new pairing code; a device is never trusted under the new identity silently.
  - Each is its own command with its own warning, for super admins from a terminal only (never agents or the console), and every attempt is audited (`secrets.master.*` with the slot, `secrets.jwt.rotate`, `secrets.device_identity.rotate`). None of them has a rollback except the master rewraps, inside their window.

- **See and sign out your sessions.**
  - **Account › Security › Sessions** lists every browser signed in to your account: where it signed in from, when, how, and when it was last used.
  - Sign out any one of them, or every other one at once. A signed-out browser loses access immediately, including previews, downloads and uploads already open in it.
- **Session fixation is closed.**
  - A connection now signs in once. Signing in again on a connection that is already signed in is refused (`already_signed_in`), and a session cookie is only ever adopted from its stored record, never from another open connection.
  - A sign-in cookie planted in someone's browser can no longer turn into their session when they sign in.
- **Groundwork for multi-factor sign-in.** Each session now records how its sign-in was proven (a password today), and every use of the session is checked against the account's sign-in policy. Nothing is required yet: this prepares the coming passkey and authenticator-code sign-in.

- **Groundwork for passkeys and security keys (not MFA yet).** The server now contains a WebAuthn verifier for
  registering passkeys and checking sign-in assertions (ES256, Ed25519 and RS256 keys of 2048 bits or more). Nothing
  uses it yet: passkey sign-in and enrollment arrive in a later release, and until then Vaulthalla has no multi-factor
  authentication.
- **New settings: `auth.webauthn.rp_id`, `rp_name` and `origins`** (**Settings › Security › Passkeys / security
  keys**, or `config.yaml`). Passkeys are tied to the host name people open the console at, so it is set explicitly
  and never taken from request headers. Leave `rp_id` empty (the default) until passkeys ship. `rp_id` must be a
  host name, never an IP address, and each origin must be exactly `https://host[:port]` under it
  (`http://localhost:<port>` for development). The daemon refuses to start, and the settings page refuses to save,
  when the values break these rules. Changing `rp_id` later makes passkeys registered for the old one unusable; the
  settings page warns before you save such a change.

- **Groundwork for multi-factor sign-in: factor storage.** The server can now store authenticator-app (TOTP) factors and one-time recovery codes, and keep passkeys on record. Nothing asks for a second factor yet: sign-in with passkeys and authenticator codes comes in a later release.
  - Authenticator seeds are sealed under a new internal key, `mfa_seal`, protected by this host's master key and bound to the account and factor they belong to. Recovery codes are stored only as keyed hashes under `mfa_pepper`, and each works once.
  - Neither key is ever regenerated while anything depends on it. If one can't be unsealed (for example a database restored without this host's sealed master), only that kind of factor stops working; passkeys and the local CLI recovery are unaffected.
  - Back them up with the other internal secrets: `vh secret export mfa-seal` and `vh secret export mfa-pepper` (both are included in `vh secret export all` once they exist).

- **Administrators now sign in with a second factor: a passkey or an authenticator app.**
  - Who must use one: the super admin and every account whose admin role can change accounts or admins, roles, settings, or export or rotate encryption keys (the `admins` policy, on new and upgraded installs). Other accounts may add one in **Account › Security**; once an account has a factor, it is always asked for.
  - **Breaking: existing administrator sessions end.** A session that signed in with a password alone is not carried over for an account that must use a second factor: its next request is refused, and the next sign-in leads through a guided setup. Desktop devices paired with the server are not affected and never ask for a second factor.
  - **First sign-in:** after the password, choose **Create passkey** (recommended: works with 1Password, your device's passkey manager, and security keys) or **Use an authenticator app** (the QR code is drawn in your browser). Then save the ten recovery codes shown once; confirming you saved them finishes the sign-in. Adding a second passkey (another device or 1Password) is suggested.
  - **Every later sign-in:** password, then the passkey, an authenticator code, or one of the recovery codes.
  - Until the second step succeeds, nothing is signed in: the half-finished sign-in can't be refreshed, reopened in another tab or used for downloads, and it ends after 5 minutes (10 while setting up), after 5 wrong attempts, or when the page closes. Repeated wrong codes on an account delay its next attempt (see the MFA policy notes).
  - **A recovery code** works once, signs out every other browser of the account (paired devices are left alone), and asks you to set up a new factor and new codes in **Account › Security**.
  - **Passkeys need the server's address configured** (Settings › Security, `auth.webauthn.rp_id` and `origins`). Without it, authenticator apps still work.
  - Keep the recovery codes somewhere other than your passkey manager. Without them, another administrator (or `vh user mfa reset` on the server) resets a lost second factor. The local `vh` CLI keeps working as before.

- **Sign in with a passkey alone.** The sign-in page has a **Sign in with passkey** button, and browsers that support it offer your passkeys right in the username field. Pick the passkey, unlock it (Touch ID, Windows Hello, your security key's PIN, or 1Password), and you're in: no username or password. It works with any passkey already added to your account (1Password, your device's passkey manager, or a security key), and counts as a full second-factor sign-in.
  - The passkey must be unlocked with a PIN or biometric (user verification). A passkey made for another server address is never accepted, and a failed attempt says only that the passkey couldn't sign you in.
  - Passkeys synced across devices (1Password, iCloud Keychain, Google Password Manager) work from every device that holds them.
  - Needs the server's address configured for passkeys (Settings › Security, `auth.webauthn.rp_id` and `origins`); without it passkey sign-in is unavailable and the password sign-in works as before. Paired Desktop devices are not affected.

- **Sensitive changes in the web console now ask you to confirm it's you (step-up).** Right before the change runs, a
  dialog asks for your passkey, or your password together with a code from your authenticator app. What asks:
  - changing accounts, roles, groups and their members, and creating or deleting accounts;
  - changing passwords, adding a second passkey or authenticator app, removing one (new: **Account › Security ›
    Remove**), and replacing recovery codes;
  - API keys, the email provider's credentials, S3 gateway credentials and turning on provider administration;
  - any **Settings** change (including the passkey settings `auth.webauthn`);
  - approving a new device and turning on remote device connections;
  - deleting a vault or a recovery point, suspending provider versioning, cleaning up, unprotecting or setting a
    destructive lifecycle rule on a bucket;
  - exporting or importing vault keys outside a paired device's automatic backup.
- Confirming covers similar changes in that browser tab for 5 minutes (`auth.mfa.step_up_ttl_seconds`, 60 to 900; reloading the page asks again). Device approvals, key
  operations and data removal confirm exactly one change each time. Signing in with a passkey or an authenticator code
  counts as a confirmation for the next 5 minutes.
- An account that doesn't need MFA and has no second factor confirms with its password, but never for vault keys,
  device approvals or removing data: add a passkey or an authenticator app for those.
- Recovery codes, a remembered session, and Vaulthalla Desktop's connection never count as a confirmation. Five failed
  confirmations within 15 minutes sign that browser out.
- **Not affected:** the local `vh` CLI (it is trusted as the server's own account) and Vaulthalla Desktop's sync and
  automatic 1Password key backup. Actions above that Desktop starts itself (removing a vault, importing keys) are
  refused until device approvals arrive in a later release; do them in the web console or with `vh`. Agent tools
  (`/mcp`, `vh mcp`) can't confirm and are refused these actions.

- **Multi-factor sign-in policy is now a setting** (**Settings › Security › Multi-factor sign-in**, `auth.mfa.policy`):
  `admins` (the default, unchanged), `all` (every account) or `optional` (nobody, except accounts you require). Raising it
  signs affected password-only sessions out at their next request; they set up a factor at their next sign-in.
  Weakening it is recorded in the audit trail and emailed to the security recipients
  (`operator_emails.recipients.security`).
  - New: hold administrators to **passkeys only** (`admin_webauthn_only`), or to **device-bound passkeys only**
    (`admin_device_bound_only`: security keys, not synced passkeys). Both need passkeys configured. An administrator
    whose only factor is no longer allowed is signed out and sets up a passkey at the next sign-in.
  - **Require MFA for one account** whatever the policy: on the account's page in **Users**, or `vh user mfa require
    <user>`.
- **Resetting a lost second factor.** An administrator who may reset an account's password can now reset its MFA
  (**Users › a user › Sign-in factors › Reset MFA**, with a reason; a super admin's only another super admin). On the
  server, `vh user mfa reset <user>` does the same, run as the Linux user bound to your own account or to one allowed
  to reset the target's password, never with `sudo`: it is the way back in for a sole super admin who lost every factor.
  A reset disables the account's passkeys and authenticator apps, voids its recovery codes, signs every session out
  and revokes its paired devices' key-backup grants (the devices stay paired and keep syncing). The account sets up a
  new factor at its next sign-in. A password reset never touches factors.
- **Signing in with a recovery code** now also revokes the key-backup grants of your paired devices, and lists them
  in **Account › Security** so you can revoke any you lost (nothing is revoked for you). Every other browser is still
  signed out.
- **Recovery cooldown:** for 24 hours after a recovery-code sign-in or an MFA reset (`auth.mfa.recovery_cooldown_hours`,
  1 to 168), key export, device approval, account and role administration, API keys and other secrets, and settings
  changes are refused for that account. A passkey or authenticator app set up during the recovery doesn't count as a
  confirmation for those until it ends. The local `vh` CLI is not held back.
- **Repeated wrong codes:** after 5 failed second factors in a row an account waits 1 minute before the next attempt,
  then 2, 4, 8 and at most 15 minutes. It is never locked. The 10th failure emails the account and the security
  recipients.
- **Emails:** the account (when it has an email address) and the security recipients are told about recovery-code
  sign-ins, MFA resets, repeated failures and suspended passkeys; the account alone about factors added, renamed or
  removed and new recovery codes. Operator email must be configured.
- Every recovery can be followed in the audit trail alone (`vh audit list --action auth.mfa.`), and `vh audit verify`
  checks it. See **Audit trail › Reconstruct an MFA recovery**.

- **Vaulthalla Desktop can get your approval for sensitive actions (device approvals, server side).** A paired Mac's
  connection still never counts as you being there. What counts:
  - **Touch ID on the Mac**, through a second key Desktop keeps in the Secure Enclave (its *approval key*), for
    vault-key operations and approving devices only. Each approval is signed for one action and one target, and expires
    after two minutes.
  - **Your passkey in the web console**, for anything else Desktop asks for: the request shows up for every console tab
    you're signed in to, and only a passkey can approve it (an authenticator code or a password can't).
- **Approve a new Mac from a Mac you already paired**, with Touch ID, instead of from the web console. Pairing from the
  console and with `vh device pair` (including `--json`) works as before.
- Desktop's sync, file access and automatic 1Password key backup still never ask for anything.
- Every approval, refusal and decision is recorded in the audit trail (`vh audit list --action device.approval.` and
  `--action auth.approval.`).
- The Desktop side (Touch ID prompts, registering the approval key, the console's Pending approvals list) ships in
  Vaulthalla Desktop and a later console update. Until then, do these actions in the web console or with `vh`.

- **Automatic 1Password key backup is now a key-backup grant you can see, confirm and turn off.** A grant lets one
  paired Mac back up the keys of the vaults it names with no prompt, on every reconnect and after every key rotation.
  Any other key export from the Mac (another vault, a manual export) needs your approval each time: Touch ID on the
  Mac or your passkey in the web console.
- **Nothing stops when you upgrade.** Every Mac already paired keeps backing up: it gets a *migrated* grant over
  exactly the vaults its account could export at upgrade time, never more. **Devices › My devices** shows a Key backup
  column: confirm the grant or turn it off. A Mac you pair from now on asks once, when you turn backup on.
- **A new vault is added deliberately.** A grant never widens on its own; Desktop asks once to add a vault.
- **A Mac sweeping keys is stopped.** More than 60 vault key exports in an hour pauses the grant and notifies you;
  confirm it to resume.
- **Grants end automatically** when the Mac is unpaired, the account is deactivated, deleted or loses the export
  permission, its MFA is reset, someone signs in with a recovery code, or the Mac hasn't connected for 90 days. After
  a recovery-code sign-in, the same Mac can turn its backup back on with Touch ID during the cooldown, for the same
  vaults only.
- Every grant change and every backup under a grant is in the audit trail (`vh audit list --action keys.backup.`).
- The Desktop side (turning backup on per vault, the confirm prompt) ships in Vaulthalla Desktop.

- **Recovery kits and recovery recipients for S3 vaults.** Create a recovery kit on your own computer with the new
  offline tool `vh-recovery kit create`, then enroll its public key on a vault with
  `vh vault keys recipient add <vault> --public-key <key>`. Vaulthalla wraps every key version of the vault to that key,
  now and at every future rotation, and stores the wrapped keys in the vault's own bucket (`.vaulthalla/key/`), so a
  rotation no longer leaves the newest key on the host alone until you export again. A rotation writes the new
  version's wrapped key before the new key encrypts anything; if the bucket can't be reached, the rotation doesn't
  start.
- **Recovery stays under your control.** The server only receives the public key; the kit's seed never leaves your
  device, wrapped keys go to the vault's bucket and nowhere else, and Valkyrian Labs receives no recovery keys or
  decryption authority. No account, payment, subscription or upgrade enrolls a recipient. `vh vault keys recipient
  list|revoke` show and revoke recipients; revoking stops new wrapped keys, and status tells you when a key rotation is
  needed to cut a revoked recipient off from new data. Enrolling and revoking work from the local `vh` CLI (and from a
  paired device once device approvals arrive), never from the web console or an agent.
- **`vh vault keys import <vault> --recovery-kit <kit>`** restores a vault's keys from its bucket after this host's
  vault master was lost. Only key versions this server's own records and signatures prove the vault had are restored;
  anything else in the bucket is ignored.
- **New health warning: `recovery_material_missing`.** A self-hosted S3 vault that encrypts its bucket and has neither
  a recovery recipient nor an export of its current key version now shows as degraded in `vh status`, the console's
  health and `vh vault keys status`. After upgrading, existing vaults without a current export show this until you
  enroll a recipient or export the keys (`vh vault keys export`). A key rotation makes an export stale.
- Key exports now include each signing key's public key (`attestation.public_key`). Older exports still import on the
  server that made them.

- **Restore a vault from its bucket and your recovery kit: `vh vault recover`.** When the server that ran an S3 vault is
  gone (its database, its TPM, everything), a new Vaulthalla server you run rebuilds the vault from the vault's bucket
  and your recovery kit (or a key export): files, folders, names, the trash, provider versions, snapshot records and
  every key version. No account or payment is needed, and nothing goes anywhere but your server and your bucket.
  `--dry-run` shows what a restore would do and writes nothing; the restored vault downloads a file only when it is
  read. See *Restore A Vault From Its Bucket* in the key export docs.
- **Only keys your material proves come back.** A key version is restored only when the original server's signature
  of it verifies against a signing key your kit (or export) pins; the new server's own keys never count, and a key
  someone planted in the bucket is ignored. Anything that can't be proven stops the restore, and `--salvage`
  re-encrypts what the supplied keys decrypt under a new key, without storing them. The kit's checkpoint protects
  against a bucket that presents an older state of the vault (`--accept-rollback` to restore it anyway).
- **New encrypting S3/R2 vaults use opaque storage.** Your storage provider only ever sees encrypted, opaquely named
  objects. It can't see your file names, folders or contents. It can see how many objects you store, their sizes and
  when they change. Vaults created before this release keep their current layout (names visible to the provider) until
  you migrate them with `vh vault migrate-layout` (below); nothing changes for them on upgrade.
- Pin each vault in your kit (`vh vault keys status <vault> --json`, then `vh-recovery kit add-vault`) and refresh it
  after a restore: the restored server signs the key versions it creates with its own key.

#### Restore drill (release gate for opaque storage)

The catastrophic restore drill of design spec 03 §7 passed on 2026-11-06 (`vhh drill recover`, fake S3 with
versioning): node A wrote 2,000 files (2,123 entries: nested folders, 0-byte, small and multipart-sized files, a
symlink, renamed files and folders, a purged file, overwrites, 5,920 provider versions, a snapshot, two key rotations,
a recovery recipient enrolled after the first, an export before the second, a checkpoint, an abandoned multipart
upload); node A's daemon, database, swtpm state and backing store were destroyed; node B, with its own database and
swtpm, restored the vault from the bucket and the kit in 4.2 s with 19 requests and 0 content bytes (2.8 MB of
manifest, 450 bytes of envelopes): every file's path, kind, size, mode, mtime, symlink target and bytes equal node A's,
key versions 1-3 verified against the kit's pinned key and shown with their origin, freshness verified against the
checkpoint; the restored vault rotated to version 4 and synced; a second restore on node C proved node A's versions
with the original kit and all four with a kit refreshed from node B. 30/30 checks, including the negative drills:
deleted root (versioned → the newest retained root; unversioned → blind rebuild under /Recovered), corrupt segments,
rollback refused against the checkpoint and accepted explicitly, wrong seed, a kit for another vault, an export alone
after a rotation (the later version reported missing, never invented), and kits with no, another node's or the
restoring node's own attestation keys (salvage only).

The same drill ran live on Cloudflare R2 the same day (`tools/harness/drill_recover_r2.sh`, 300 files, nodes A, B and C
as independent private instances on one host, bucket `vh-test-recover-drill` deleted afterwards): 16/16 checks; the
restore took 5.8 s and read 0 content bytes (469 kB of manifest) before the first file read, key versions 1-3 verified,
freshness verified.

- **Move older S3/R2 vaults to opaque storage: `vh vault migrate-layout`.** Encrypting vaults created before this
  release name each object after the file's path, so your storage provider sees file and folder names. Migrating one
  re-seals every object, every version your provider keeps and every pending upload under random ids in the newer
  encrypted format, under the same keys (not a key rotation). Afterwards the provider sees what it sees for new vaults:
  encrypted, opaquely named objects, their count, sizes and change times. Nothing migrates on upgrade: you start each
  vault yourself (`vh vault migrate-layout <vault>`), it runs in the background, and the vault's files stay readable and
  writable meanwhile (its sync waits until the migration is done). See *Migrating A Vault To Opaque Storage* in the
  encryption docs.
- **Every byte stays recoverable.** Each new object is authenticated before it is uploaded, the provider has to prove
  it holds exactly those bytes (or it is read back and decrypted), and a sample is always read back. If anything fails
  before the switch, the vault stays as it was and nothing is deleted: run the command again to resume. The cost is
  estimated and checked against your price budget before anything is written (`--accept-unpriced` when it can't be
  priced). The migration needs recovery material that doesn't depend on the server: a recovery recipient or a current
  key export.
- **The old objects go only when you say so.** They stay untouched in the bucket for 7 days after the switch
  (`vaults.layout_migration.cleanup_wait_days`). Then `--cleanup` lists what would be deleted and
  `--cleanup --confirm <vault name>` deletes exactly those versions, one by one. A bucket with a protection lock is
  never cleaned, and a version under Object Lock retention or a legal hold stays until its date. Versions that can't be
  migrated (an archive storage class, a key this server doesn't hold, another application's object) are kept and
  listed with the reason; the migration says `complete` only when no path-named object, version or delete marker is
  left.
- The server's health now reports `legacy_content`: whether any content in the earlier format is left on this server.
  A later release will refuse to upgrade while it is.
- Once a vault has been migrated, downgrading the package below this release is unsupported: earlier releases can't
  read opaque storage.

#### Layout migration drill

`vhh drill migrate` passed on 2026-11-06 (fake S3 with versioning, one private instance with its own database and
swtpm): a path_v0 vault of 300 files (301 path-named keys, 305 versions with an overwrite and a delete marker) was
migrated in 6 s while a sync pass ran and a writer kept writing through the FUSE mount (47 files written meanwhile);
it cut over with the manifest verified from the bucket alone, nothing path-named was deleted before the cleanup, every
file read back identical, the writer's files were all there, the cleanup was refused before the waiting period and,
after it, left no path-named key, version or delete marker (11/11 checks). On live Cloudflare R2
(`LiveR2.LayoutMigrationPrimitives`, a `vh-test-*` bucket deleted afterwards) a re-sealed object's ETag was the
predicted MD5 for a single and a multipart upload, so R2 needs no read-back beyond the sample.

- **A lost host master is no longer replaced silently.** The host master wraps the internal secrets: the MFA keys that seal TOTP seeds and hash recovery codes, the share-link pepper, email provider credentials and the JWT secret. When its sealed blob was missing, earlier versions created a new one without a word, which left the MFA keys and the share pepper unreadable for good (TOTP, recovery codes and share links then failed). Now Vaulthalla refuses to start while such secrets are on record, and the log names them and the way back: restore the state directory with its sealed blob, or give those secrets up explicitly ([A Lost Host Master](/vaults/secrets-and-key-export#a-lost-host-master)). A fresh install still creates the host master, and a database that holds only the JWT secret still starts (everyone signs in again).
  - **Restoring a database onto a new host** now includes that explicit step before the first start, after which users enroll TOTP and recovery codes again, share links are reissued and email credentials entered again. Vault keys are restored from their exports as before.

- **Restoring a database onto a new host no longer means enrolling everyone in two-factor sign-in again.** `vh secret set mfa-seal <file>` and `vh secret set mfa-pepper <file>` import the keys that `vh secret export` wrote, after checking them against what the database stores: the TOTP key must open a stored authenticator seed, and the recovery code key must reproduce the stored hash of one of your own recovery codes (`--code`). Only super admins can import, after a confirmation, and every attempt is recorded in the audit trail. A key that does not match is refused and changes nothing, a working key on the host is never replaced, and no key is ever printed. See [A Lost Host Master](/vaults/secrets-and-key-export#a-lost-host-master).

- **Thumbnail URLs no longer carry file names.** `POST /preview/batch` now answers with `entry=<id>` URLs instead of `path=` URLs, for vaults and share links, so file names stop leaving through thumbnail requests in proxy access logs, browser history and Referer headers. The ids resolve through the same permission checks as paths, and a share link still only reaches entries inside its scope.

### Reliability

- **Clean exits.** The server can no longer crash while exiting after a stop or restart when web or device sessions were still connected (seen as a segmentation fault on Linux and an abort on macOS).
- **Share-link uploads.** A share-link upload could rarely be refused with "Malformed share token prefix" while another request on the same link was being handled. Fixed.
- **Upstream event sync.** Stopping the server in the middle of applying bucket events no longer counts the interrupted object as a failed attempt; it is applied on the next start.

<!-- vl-release:entry version=1.21.1 -->
## 1.21.1 — macOS package and Homebrew casks for 1.21

_Released 2026-11-02_

The macOS installer package and the Homebrew casks of 1.21.0 were held back by a check in the release's cask test;
this release publishes them. Everything in 1.21.0 is included.

- The `vaulthalla` meta cask opens Vaulthalla Desktop once, on its first install. Uninstalling and reinstalling it
  doesn't open Desktop again; Desktop still sets itself up with this Mac's server whenever it starts.

<!-- vl-release:entry version=1.21.0 -->
## 1.21.0 — Secure Enclave keys, a live change feed and automatic Desktop pairing

_Released 2026-11-02_

### Master keys on macOS are sealed with the Secure Enclave

The macOS server now seals its master keys (the vault master key, the database password, API-key, S3 gateway and
device secrets) with the Mac's Secure Enclave, and `vh status` reports `secrets backend: secure-enclave`. Until now
they were plain `0600` files in the state directory, protected only by permissions and FileVault.

- **Upgrading keeps everything.** On its first start after the upgrade the daemon moves each existing key file into
  the Secure Enclave and deletes the plaintext file. No action is needed.
- **Only the daemon can open the keys**, and only on this Mac: they are bound to the context launchd starts it in, so
  not even root can open them from a terminal or `sudo`. Copying the state directory to another Mac no longer carries
  the keys with it; GPG-encrypted vault key and secret exports are the way to move or recover them. See macOS Key
  Recovery in the backup docs.
- **Restarts with FileVault on:** a cold boot waits at the FileVault login before any service runs. For an unattended
  restart use `sudo fdesetup authrestart`; Vaulthalla then starts at the login window, before anyone logs in.
- If the Secure Enclave can't be used (the daemon checks at startup), it keeps using key files, logs why, and
  reports `secrets backend: file`.

Linux TPM2 sealing is unchanged.

### Change feed for sync clients

Every change to a vault's files and folders is now recorded in a change journal, in the same database transaction as
the change itself, whichever way it was made: the mounted filesystem, uploads, the web console, sync, recovery or a
manual database edit. A new WebSocket command, `fs.changes.list`, returns what changed in a vault since a revision,
oldest first, so sync clients such as Vaulthalla Desktop's Finder integration can follow a vault without listing its
folders again.

- Anyone who can browse a vault can follow it, and sees only changes to entries they are allowed to see. A rename or
  move into or out of what they can see reads as a create or a delete.
- When a role, group membership or permission override changes what someone may see in a vault, their cursor
  expires and their client lists the vault again. So does a cursor older than the journal's retention (7 days or the
  last million changes).
- Clients can subscribe instead of polling: `fs.changes.subscribe` makes the server tell a connected session when a
  vault it follows has changed (`fs.changed`). Events are merged per vault for slow clients, and a subscription
  ends when its user loses access to the vault.
- The journal adds one row per change. The database migration (115) is safe on upgraded installs.

### Vaulthalla Desktop sets up this Mac's server on its own

`brew install --cask valkyrianlabs/tap/vaulthalla` now ends with Vaulthalla Desktop open and already connected to
the server on the same Mac. There is no pairing code to compare: your macOS account is the proof. Desktop (0.5.0 and
later) pairs through the server's own `vh` as you, so the device acts as the Vaulthalla user your account is bound to
(the person who installed the server is `admin`), and it shows up in your device list like any other.

- The meta cask opens Desktop once, on its first install; upgrades don't open it again. Desktop also does this
  whenever it starts, or when a server is installed on its Mac while it runs, so installing the two casks separately
  works too. A Mac with only one of them is unchanged.
- Nothing on the network is trusted more than before: it is the same number-matched pairing you could run in
  Terminal, approved over the local `vh` socket, and the connection is pinned to the server key `vh` reports.
- New for scripts: `vh device pair --json` opens your pairing window without waiting and prints its expiry, the
  device port, the node id and the server key.

### Fixes

- **Security: folder sizes no longer reveal hidden contents.** A folder's size (in the web console, `vh` and `stat`
  on the mount) now counts only what you are allowed to see in it. Super admins and vault owners still see the full
  totals (#269).
- **The mounted filesystem never leaves a request hanging.** If the database was briefly unreachable, `rm`, `mv` and
  `rmdir` on the mount could hang forever. They now fail with an error you can retry (#263).
- **Health dashboard: FUSE permission denials are no longer errors.** A system process with no Vaulthalla account
  that looks at the mount (an ssh login's MOTD scripts, for example), or a user refused by RBAC, is the filesystem
  enforcing access as designed. These now count as expected errors, so they no longer raise "FUSE alertable error
  rate is above 10%". They still appear under all errors and errors by errno.
- **CLI tables** line up with accented, CJK and emoji names, and never cut a character in half (#273).
- **macOS uninstall** says which service it is waiting on while it stops (up to 75 s), instead of pausing silently.

<!-- vl-release:entry version=1.20.2 -->
## 1.20.2 — The macOS package and Homebrew casks of 1.20.1

_Released 2026-11-01_

1.20.1 published its Debian packages and docs, but not its macOS package or Homebrew casks: a check in the release's
Homebrew smoke test named casks the way `brew list` doesn't accept, and the release stopped before publishing them.
1.20.2 publishes them. Everything in the 1.20.1 notes applies: `valkyrianlabs/tap/vaulthalla` is now a meta cask over
`vaulthalla-server` and `vaulthalla-desktop`, it needs `brew trust valkyrianlabs/tap` once, and if you installed the
old `vaulthalla` cask, uninstall it and install it again rather than `brew upgrade` it (vault data is kept).

<!-- vl-release:entry version=1.20.1 -->
## 1.20.1 — Vaulthalla on macOS installs as a meta cask

_Released 2026-11-01_

### Homebrew

`valkyrianlabs/tap/vaulthalla` is now a meta cask. It installs nothing itself and depends on
`valkyrianlabs/tap/vaulthalla-server` and `valkyrianlabs/tap/vaulthalla-desktop`, so the server and Vaulthalla
Desktop each install and upgrade to their own latest release. The server package no longer carries a copy of the
Desktop app: 1.20.0 shipped Desktop 0.2.0 inside it, and upgrading the old `vaulthalla` cask replaced a newer,
self-updated app with that copy. The casks no longer conflict with each other.

Homebrew loads a dependency cask only from a trusted tap, so the meta cask needs `brew trust valkyrianlabs/tap` once.
`vaulthalla-server` and `vaulthalla-desktop` named in full still need no trust step.

**If you installed the `vaulthalla` cask before 1.20.1**, move to the new one with an uninstall and a fresh install.
Both keep vault data, the database and configuration:

```bash
brew uninstall --cask valkyrianlabs/tap/vaulthalla
brew trust valkyrianlabs/tap
brew install --cask valkyrianlabs/tap/vaulthalla
```

Don't `brew upgrade` it: Homebrew installs the new dependencies first and then runs the old cask's uninstall, which
removes the server and the app it just installed. If that already happened, `brew reinstall --cask
valkyrianlabs/tap/vaulthalla-server valkyrianlabs/tap/vaulthalla-desktop` restores them, data intact.

The installer package (`vaulthalla-<version>-arm64.pkg`) installs the server only and no longer offers Vaulthalla
Desktop under Customize; download Desktop from its own releases.

<!-- vl-release:entry version=1.20.0 -->
## 1.20.0 — Direct device connections and resumable uploads

_Released 2026-11-01_

### Vaulthalla Desktop connects directly

Vaulthalla Desktop can now find the fastest way to reach a node on its own. A paired Mac asks the node where it can be
reached (`device.endpoints`): its addresses on this machine, the local network and VPNs such as Tailscale or
WireGuard, `<hostname>.local` where mDNS runs, and any names an operator lists under the new
`device_server.advertise` section of `config.yaml` (port forwards, tunnels, TLS passthroughs). The node never asks an
outside service for its public address. The web console's "Pair a device" dialog gets the same list, the node id and
the server key fingerprint, so a pairing link can carry them.

With remote connections on, the device listener now accepts IPv6 as well as IPv4 (`[::]`, falling back to
`0.0.0.0` where IPv6 is disabled); loopback-only listens on `::1` too. For super admins, `device.remote.status` adds
diagnostics: every bound address, the addresses devices are told, a read-only look at the host firewall (ufw,
firewalld, nftables, the macOS application firewall; "unknown" rather than a guess) and when a device last
connected from a public address. Paired devices can measure a route's throughput with the new `/transfer` probe,
sink and source lanes on the device listener; nothing they send is stored.

### Web console

- **Large uploads survive interruptions.** On servers that offer resumable uploads, the console sends files in parts
  of up to 64 MiB (under Cloudflare's 100 MB request limit), up to three at a time, each checked with a SHA-256
  digest on HTTPS. A dropped connection, a busy server or a daemon restart no longer restarts the file: the console
  waits, asks the server which bytes it already has and sends only the rest. After a page reload, choosing the same
  file again in the same place picks up where it stopped ("Resuming … already on the server"). Shared upload links
  get the same behavior. Older servers keep the previous whole-file uploads.
- When some files of a batch fail, the transfers panel now names each one and why (already exists, no room left in
  the vault, the vault key changed so the file must be uploaded again, and so on).
- **Pair a device** lists the addresses this server can be reached on (copyable) and offers **Open in Vaulthalla
  Desktop**, which fills in Desktop's Add Node sheet with those addresses and the server key. The six-digit code match
  stays the proof that you are pairing with the right server.

### Uploads resume where they stopped

Vaulthalla now offers resumable uploads (`/upload/sessions`, capability `http.upload.resumable`) on the web console
listener and on the Vaulthalla Desktop device listener, share links included. A client uploads a file in parts, in
any order and in parallel; every acknowledged part is durable, survives a dropped connection or a daemon restart,
and a client resuming asks which byte ranges the server holds and sends only the gaps. Resending a part is
harmless (same bytes are accepted, different bytes are refused), and an optional `Content-Digest` catches corruption
in transit.

- Files may now be as large as the vault format allows (about 64 GiB per file) instead of 8 GiB.
- Nothing is stored in plaintext while an upload is in flight: each part is encrypted the moment it arrives, and the
  server seals the file in the background as its parts come in, so finishing a large upload takes seconds instead of
  re-encrypting the whole file.
- Create-only and compare-and-swap replacement work per file, exactly as on `PUT /upload/content`; a file that
  appears at the target before the upload commits is reported, never overwritten or silently dropped.
- Sessions expire 24 hours after their last part (at most 7 days after they began) and their temporary data is
  removed. New `transfer:` settings in `config.yaml` tune part sizes and limits; out-of-range values are refused.

The existing upload lanes keep working unchanged for older clients.

<!-- vl-release:entry version=1.19.0 -->
## 1.19.0 — Clients and servers negotiate a protocol version

_Released 2026-10-30_

The server, the web console and Vaulthalla Desktop release on their own schedules, so a client now starts its
WebSocket session with `meta.hello` (on the web socket, once signed in: the server still tells no one its version
before login). It says which protocol versions it speaks; the server answers its product version,
the protocol version the session will use, the features it has (capabilities such as `fs.entry.metadata_version` or
`device.mcp`) and every command it offers. A client that has no version in common with the server gets a clear
`protocol_unsupported` answer naming the server's range instead of failing on a changed shape later. A paired device's
reported app version now stays current in the device list instead of keeping the version it paired with.

An unknown command now carries the error code `unknown_command` (the message is unchanged). The rules for what may
change within a protocol version are in [WebSocket Protocol](/reference/ws-protocol).

<!-- vl-release:entry version=1.18.0 -->
## 1.18.0 — Vaulthalla moves to the Valkyrian Labs organization

_Released 2026-10-30_

Vaulthalla's source, issues and roadmap now live under Valkyrian Labs LLC on GitHub:
[valkyrianlabs/vaulthalla-server](https://github.com/valkyrianlabs/vaulthalla-server) and
[valkyrianlabs/vaulthalla-desktop](https://github.com/valkyrianlabs/vaulthalla-desktop). Old `vaulthalla/server` links
redirect. Nothing changes for installs: the APT repository, `apt.vaulthalla.sh` and `brew install --cask
vaulthalla/tap/vaulthalla` keep working.

### S3 gateway behind Cloudflare

The S3 gateway now works through a proxied Cloudflare record with the AWS CLI's CRT transfer client. Cloudflare drops
`Content-Length: 0` from GET, HEAD and DELETE requests that the client signed with it, which failed with
`SignatureDoesNotMatch`; the gateway now treats the missing header as `0` when the request had no body. Every gateway
response also carries `Cache-Control: private, no-store`, so a CDN never caches an object or a presigned GET. See
[Behind Cloudflare Or Another CDN](/s3-gateway/setup#behind-cloudflare-or-another-cdn).

### Parallel uploads no longer exhaust the TPM

Under parallel S3 multipart uploads the daemon could log `Esys_Load failed ... out of memory for object contexts`:
several secrets were unsealed at once, and a TPM without a resource manager in front (the managed swtpm) holds only three
transient objects.
TPM operations now run one at a time, each flushing its objects before the next starts, and a TPM that another process
has momentarily filled is retried a few times instead of failing the request.

### Stats history no longer fills the database

The 5-minute trend rollups behind the health dashboard were kept for 365 days whatever `stats_snapshots.retention_days`
said, and on a busy install they grew to gigabytes. Each rollup tier now has its own setting:
`stats_snapshots.rollup_5m_retention_days` (default 30 days; the dashboard reads this tier only for windows up to 7
days) and `stats_snapshots.rollup_1h_retention_days` (default 365 days). Both are also under **Settings → Health
history**. The first daily purge after upgrading deletes the backlog; PostgreSQL keeps the freed space in the table file,
so [reclaim it once](/reference/configuration#reclaiming-disk-space-after-the-first-purge) with `VACUUM (FULL)` or
`pg_repack` during a maintenance window.

<!-- vl-release:entry version=1.17.0 -->
## 1.17.0 — macOS crash durability

_Released 2026-10-27_

On macOS, every write Vaulthalla needs to survive a power loss now reaches the disk itself, not just the drive's
volatile cache. Covered: file saves and seals, key rotation, recovery snapshots and versions, cloud hydration, `vh fs
put`, durable preview artifacts and the bootstrap secret. Plain `fsync` on macOS does not guarantee this, so an
interrupted write could previously leave a file that didn't match its database row. Linux behaviour is unchanged.

### No server mount on macOS

The macOS server never mounts vaults, and no longer carries the unused macFUSE build path. Finder access belongs to
Vaulthalla Desktop, which is building it on Apple's File Provider. `vh status` and the console's Runtime page now say
so on the mount line. If an older `config.yaml` on a Mac sets `mount.mode` to `multiuser` or `service_private`, the
daemon runs with the mount disabled and logs a warning instead of reporting degraded health. `vh fs`, the web console
and the S3 gateway remain the ways to reach vault files on a Mac. Linux is unchanged.

### Item versions for sync clients

Every file and folder the console, Desktop and other ws clients list or look up now carries a `metadata_version`, and
every file a `content_version`. The content version is exactly the strong ETag `/download/content` serves for the
file's current bytes, so a client can tell from a listing which files changed without asking for each one, and send it
back as a precondition. It changes on every write and stays the same across rename and move. The metadata version
changes on rename, move, mode change and any change of the modification time. An entry's id stays the same across
rename and move, so it can serve as a stable item identifier. Renaming or touching an empty file no longer changes its
ETag. Nothing else changes for existing clients: the fields are additive.

### Saving over a file from a client

A new upload lane, `PUT /upload/content`, lets Desktop and other clients of the HTTP and device lanes save a file of
any size, up to the 8 GiB upload limit, safely:

- **Replace** a file with `If-Match: <content_version>`. It succeeds only if nobody changed the file since that
  version. Otherwise it answers 412 with the current version, and nothing is lost. A file open through the mounted
  filesystem is never replaced underneath the program editing it.
- **Create** a file with `If-None-Match: *`. It succeeds only if nothing is there yet.

The body is streamed to disk, so memory use doesn't depend on the file size. The answer carries the file's new entry
and versions.

Uploads through `/upload/session` (the web console's uploads) no longer hold each file in memory while it is stored.
Their results are the same. A file whose upload request failed partway, for example on a dropped connection, can now
be sent again within the same upload session instead of restarting the whole session.

### Security

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

### A Valkyrian Labs product

Vaulthalla is now owned and published by Valkyrian Labs LLC, the company its creator founded to build it. The
license does not change: Vaulthalla stays free software under the AGPL, version 3 or later. The package's copyright
file, `NOTICE` and `TRADEMARKS.md` name Valkyrian Labs LLC as copyright holder and owner of the Vaulthalla name and
logo, and the copyright file now credits the third-party code bundled with the server.

### One package repository, one signing key

Vaulthalla now ships from the Valkyrian Labs APT repository, `apt.valkyrianlabs.com`, together with PDFium, the
libpqxx SDK and the other Valkyrian Labs tools, all signed by the Valkyrian Labs LLC key
(`494D 71A1 EEDD F87B D48E  5048 6D64 CB7B DFC3 0EC6`). `apt.vaulthalla.sh` keeps working: it now serves that same
index, so existing sources need no edits.

- **Existing installs:** run `sudo apt update && sudo apt upgrade` (or `apt-get dist-upgrade`; a plain `apt-get
  upgrade` holds `vaulthalla` back). `vaulthalla-archive-keyring` 2026.10.27-1 adds the Valkyrian Labs LLC key to
  `/usr/share/keyrings/vaulthalla.gpg`, which your `apt.vaulthalla.sh` source already trusts. If `apt update` reports
  `NO_PUBKEY 6D64CB7BDFC30EC6`, rerun `curl -fsSL https://apt.vaulthalla.sh/install.sh | bash`.
- **New installs** (`install.sh`, `bin/setup/install_deps.sh`, the manual steps in the docs) configure
  `apt.valkyrianlabs.com` with `/usr/share/keyrings/valkyrianlabs.gpg`. A source line written by an earlier
  `install.sh` is retired, so the host ends up with one entry for the one index; a hand-edited one is left alone.
- `vaulthalla` now recommends `valkyrianlabs-archive-keyring`, which keeps that key current through upgrades.

<!-- vl-release:entry version=1.16.0 -->
## 1.16.0 — Pair Vaulthalla Desktop, and let AI agents operate Vaulthalla

_Released 2026-10-22_

### Paired devices

The daemon now serves Vaulthalla Desktop through its own **device listener** on port 36972: TLS 1.3 with a
certificate on both sides, each side pinning the other's key. No browser cookie, nginx or certificate authority is
involved. The listener answers on **loopback only** until a super admin runs `vh device remote enable`, which opens
it to the network at once (no restart) and keeps it that way across restarts and upgrades; `vh device remote
disable` closes it again.

Any signed-in user can pair a Mac with their own account: `vh device pair` opens a 10-minute pairing window, lists
the Mac when it asks, and offers three codes. Pick the one the Mac shows; a wrong pick denies the request. A paired
device acts as its account with that account's permissions, and follows it: role changes apply at once,
deactivation refuses it, and a password reset or role change closes its open connections. Manage devices with
`vh device list | rename | revoke` (super admins: `vh device list --all`). Revoking is final: the device's
connections close immediately and its key is never accepted again.

A paired Mac also downloads, previews and uploads files over the same connection, with the same permission checks
as the web console (share links aren't offered there), and its AI agents can use **remote MCP** at `/mcp`: the same
tools, limits and confirmations as `vh mcp`. Agents can never approve pairing requests, turn remote connections on or
off, or export keys or secrets.

#### In the web console

**Devices** (in the main navigation and the account menu) lists your paired Macs with their platform, app version,
when they were paired and last seen, the last address and the device id, and lets you rename or revoke them. **Pair a
device** is one click: the dialog opens a pairing window, shows the Mac's request with three codes as large buttons,
and you click the one the Mac shows. A wrong click declines the request; if another user is pairing on the node at
the same time, the dialog says so and leaves their window alone. The dialog shows the address and port to enter
in Desktop and counts down by the server's clock. Closing the dialog closes your window.

Super admins also get **Devices → All devices**: every user's devices with their owners, and a **Remote connections**
card with the listener's live status (address, port, connections, any bind error, the server key fingerprint) and an
on/off switch. Settings → Device listener links there.

### Vault key backup, status and restore

`vh vault keys status` shows each vault's key backup state without printing key material: the current key version
and its **key check** (a public fingerprint that identifies a key without revealing it), the last exported version,
whether a rotation is under way, and every key version the vault still needs. Deleted vaults whose key is still
retained are included. A paired Vaulthalla Desktop uses the same information to back keys up to 1Password: it exports
over its paired connection and confirms each backup by its key check, and the server records the backup only if the
key is still current.

Key exports are now complete during a rotation: an export taken before the rotation finished re-encrypting the vault
used to omit the previous key, which still decrypts the files not yet re-encrypted. Every export now carries all
versions the vault needs (the current key, an unfinished rotation's previous key, and retired keys recovery data
uses), each with its key check, and a deleted vault's export carries them too. Keys still leave the server only
through the local `vh` CLI or a paired device, never the web console or an AI agent.

**Restoring keys.** `vh vault keys import <vault> --file <export>` is a recovery mechanism: it puts back key
versions a vault already had when this host can no longer use them, after the master key was lost or replaced (for
example a database restored onto a new host), after a database restore that predates a key rotation, or for a
deleted vault that can still be restored. It can't be used to set your own key: every export now carries the
server's **attestation** of each key version (a signature by a signing key sealed on the host, never exported), and
a version is restored only when its attestation verifies and the vault's records show it had that version. A key
the host can still use is never replaced, and a version the vault has no record of is refused. `vh` reads the export
on your side (`--file -` reads standard input, so a GPG export can be decrypted into a pipe). Writing asks you to type
the vault's name (`--confirm-name` without a terminal); the vault starts again right away. A paired Vaulthalla
Desktop restores from 1Password the same way. **Export your vault keys again after upgrading**: older exports carry
no attestations.

**Salvage.** A key version that can't be proven (an older export, another server's key) is reported as needing
salvage, and nothing is written for it. `--salvage` then makes a best effort: the server creates a fresh key of its
own, re-encrypts every file the supplied key decrypts under it (crash-safe, resumable), reports the files it couldn't
decrypt as unrecoverable, and never stores the supplied key. Files that exist only in an S3 bucket go through the
vault's price budget, and are reported as skipped with the estimate when it refuses.

**No new key over encrypted data (behavior change).** Vaulthalla used to create a fresh key at startup for a vault whose
key record was missing, even when the vault held encrypted files that key could never decrypt. Now such a vault (or one
whose key doesn't unseal, or whose files need a key version that is gone) does not start: `vh status` reports degraded and
names it, the console's health turns degraded, `vh vault keys status` says why, and the log names the import
command. New and empty vaults still get their first key automatically.

See [Secrets And Key Export](https://vaulthalla.io/docs/vaults/secrets-and-key-export).

### See every vault you can reach

`vh vault list --accessible` lists every vault you can reach and how: as its owner, through a vault role assigned to
you or to one of your groups, through your admin role, or as a super admin. Each vault says whether you can browse its
files and whether you can manage it, decided by the same permission checks that apply when you open it. `vh vault
list` is unchanged and still shows only the vaults your admin role lets you view, so an account whose access comes
from a vault role or from owning a vault finds those vaults with `--accessible`. Vaulthalla Desktop's file browser
uses the same list (ws `storage.vault.accessible.list`), and AI agents get it as the read-only tool
`vaults_accessible_list`.

**More than 100 vaults.** At startup the daemon brought up only the first 100 vaults (by id): after a restart, any
vault beyond those was unreachable on every surface until it was changed. `vh vault keys status all`, `vh vault keys
export all` and resolving an S3 gateway vault by name also stopped at 100. They all cover every vault now.

### Let Claude Code or Codex operate Vaulthalla

`vh mcp` is a Model Context Protocol server built into the `vh` CLI, and `vh skill install --agent claude|codex`
sets an agent up in one step: it writes a `vaulthalla` skill (safety guidance plus a reference of every command
agents may run) and registers the server with the agent's CLI, or prints the command when that CLI isn't installed.

- **The agent acts as you.** Every tool call is an ordinary, non-interactive `vh` command, so your Vaulthalla roles
  and permissions decide what works.
- **Destructive commands need your OK every time.** Deleting, revoking, purging, rotating keys or restoring over files
  is refused by the MCP server until the agent passes an explicit destructive acknowledgement, which it is told to
  give only after you approve, even where the command itself wouldn't ask without a terminal.
- **Confirmations stay with you.** A command that would ask you to confirm (deleting a user or vault, an encryption
  waiver, a restore over files, a bucket cleanup) refuses first; the agent has to show you the message and may only
  pass the confirmation after you approve. The server never adds `--yes` or `--accept-*` itself.
- **Keys and secrets stay out of reach.** Vault key export, secret export, `secrets update`, `setup`, `teardown`
  and `fs get|put` are never available to agents.
- Tools: `vh_help` to browse commands, `vh_read` for read-only commands, `vh_run` for the rest, and typed tools such
  as `users_create`, `vaults_delete` and `recovery_restore`. Each is marked read, write or destructive, so clients
  can run read-only tools freely and ask before destructive ones.

Calls run side by side, can be cancelled by the agent, and are abandoned after 10 minutes without a result
(`VAULTHALLA_MCP_TIMEOUT`).

See [AI Agents And MCP](https://vaulthalla.io/docs/admin/mcp-and-agents).

### Every command now says what it does

Each `vh` command declares whether it reads, writes or is destructive. The machine-readable contract
(`vh_usage --json`) carries it as `effect`.

### Every ws command is in the published contract

The ws contract the daemon publishes (`vh_usage --json`, identified by `meta.contract.get`) now describes every
command it answers on `/ws`: 223 commands, up from 76. File management, vaults and API keys, roles and permissions,
shares and share sessions, stats and dashboards, sync conflicts, pricing budgets, the S3 gateway, settings,
operator email, paired devices and vault key backup are covered, each with its payload, response, session
requirement, refusals and client timeout. Native clients can be generated from it, and the web console now takes
every command's timeout from the server.

The contract also publishes the shape of every object those commands send: 170 named models (users and roles,
vaults, devices, vault key status and exports, files and folders, share links, stats, recovery plans, upstream
buckets, S3 gateway credentials, budgets, settings sections and more), with unions and patch payloads spelled out.
A daemon unit test serializes each model with the real code and fails if the published shape and what is sent ever
differ. `meta.contract.get` adds `models_hash`.

Refusals are now machine-readable almost everywhere: file, share, pricing, email, settings, S3 gateway, vault and
dashboard commands answer refusals with a `data.code` (`denied`, `not_found`, `invalid`, `conflict`) instead of
bare text, with the same messages as before. The contract lists, per command, the questions it may ask before
proceeding (confirmations such as the encryption waiver) and which request field accepts each one.

Malformed or failing requests no longer leave clients waiting: a frame the daemon can't route is answered with an
error that carries the request's id, an internal fault answers the request it belongs to with an ordinary error
instead of an "Unknown" response, and a command sent without a payload is treated as an empty one. The contract
documents the request and answer frames.

### Security fixes

- **Global vault policy read in the right scope.** An account's global vault policy has three scopes: its own vaults,
  vaults owned by admins, and everyone else's. File access decided by that policy (when no vault role applies) always
  used the account's own-vault scope, for every vault. An account whose own-vault scope granted more than its scope
  for other accounts' vaults could therefore use those rights on other accounts' vaults, and one whose own-vault scope
  granted less was refused there. File access now uses the scope the vault falls under, the same rule vault
  management already used, on every surface (web console, `vh`, FUSE, downloads and uploads, paired devices, shares
  and the S3 gateway). The built-in roles give every scope the same rights, so accounts on them see no change; only
  accounts whose policy rows were edited per scope directly in the database are affected.

### Fixes

Event-driven sync for Cloudflare R2 buckets can now be turned on: subscribing a vault to its bucket's event
notifications failed against real Cloudflare with "R2 accepted the event rule … but does not list it", and the first
subscription on a new account could fail while Cloudflare was still creating the queue.

### Lab pentest fixture

The authorized lab pentest tools verify the installed command contract, complete disposable file operations,
and check known-content hashes. Transport errors no longer count as authorization denials, and skipped deletes
no longer count as passes. Published handoffs include their verification report and command contract, with
repeatable checksums and an offline readiness check. Snapshot names alone no longer claim a tested restore;
operators may explicitly record acceptance of disposable lab data loss instead.

<!-- vl-release:entry version=1.15.0 -->
## 1.15.0 — File recovery: snapshots, local versioning and provider versioning

_Released 2026-10-17_

Vaulthalla can now bring back earlier versions of files and folders. Each vault chooses a recovery preference in
**Vault settings → Recovery** or with `vh vault recovery set <vault> --mode …`:

- **Local snapshots.** Explicit, named recovery points of a file or a whole folder, taken with **Recovery history →
  Create snapshot** or `vh snapshot create <vault> <path> --name …`. Snapshots are stored encrypted, deduplicated (an
  unchanged file costs nothing twice), count against an optional snapshot quota and the vault quota, and survive the
  deletion of the files they captured. Nothing is ever snapshotted automatically.
- **Provider versioning (AWS S3).** For S3 vaults, the bucket itself keeps every version. Vaulthalla turns versioning
  on only after showing an estimate of what it will cost — **Provider Versioning — Estimated Monthly Cost** — and
  after you acknowledge it (and, when costs can't be estimated, a separate acknowledgement of unpriced recurring
  charges). AWS versioning can't be undone, only suspended; Vaulthalla says so before you enable it, never suspends it
  on its own, and never deletes old versions when you remove a vault. You choose how long old versions are kept
  (30, 90 or 365 days, or indefinitely). Cloudflare R2 doesn't support object versioning and is refused.
- **Local versioning** (optional, any vault). Every change to a file keeps its previous version on this server, with
  limits you set (keep the last N, a maximum age, a size quota). For S3 vaults these versions also queue up while the
  provider is unreachable and are sent in order once it is back, so a versioned bucket ends up with the full history.

**Recovery history.** Right-click a file or folder in the web console (or `vh recovery list <vault> <path>`) to see
its snapshots, local versions and provider versions. Restoring always shows a preview first — what will be created,
overwritten or skipped, and what it costs — and asks you to type RESTORE before anything is overwritten. A folder can
be restored to a point in time from provider versions; that is a reconstruction from each file's version timestamps,
not an atomic snapshot, and the preview says so. Restoring from the provider in a smart-cache vault copies the old
version inside the bucket: nothing is downloaded to list versions and nothing is uploaded twice.

**Costs you can see.** The cost panel in **Sync & cost** and `vh recovery costs <vault>` show the estimated monthly
versioning surcharge, month to date, the 30-day forecast, how much history is retained, and what drives its growth.
Estimates are computed on this server from its own measurements and the signed price catalog — no usage is sent
anywhere — and they are labelled as estimates, not invoices. You can set a monthly threshold; going over it raises a
notification and never blocks writes.

**Fixes.** Editors can save over files on the mount again (renaming a temporary file over the original failed with an I/O error); with local versioning on, the version the save replaces is kept. Vault keys load again after a restart in the middle of a key rotation. S3 bucket listings past 1,000
objects no longer fail their signature. Deleting a folder no longer leaves its subfolders cached. A sync pass whose
bucket listing fails part-way now stops instead of working from a partial view, and S3 vaults with more than 1,000
objects index all of them. Unsent versions of a deleted file no longer stay pending in `vh vault recovery status`:
maintenance sends them to a versioned bucket (the file stays deleted) or drops them where there is no history to keep.

<!-- vl-release:entry version=1.14.1 -->
## 1.14.1 — APT signing key kept current through upgrades

_Released 2026-10-16_

`vaulthalla` now depends on `vaulthalla-archive-keyring`, which owns `/usr/share/keyrings/vaulthalla.gpg`: the
`signed-by=` key that `install.sh` and the documented manual setup have always configured. When the repository's
signing key is renewed (for example a new expiry date), the keyring package updates it on the next upgrade, so
existing installs keep verifying `apt.vaulthalla.sh` without downloading the key again or editing their APT sources.

**Upgrading.** `sudo apt upgrade` (or `apt-get dist-upgrade`) installs the new dependency. A plain `apt-get upgrade`
never installs new packages and holds `vaulthalla` back until you run one of those, or
`sudo apt install vaulthalla-archive-keyring` first. The signing key fingerprint is
`0657 4F63 2342 3EBC 99A1  DF7B E906 C69B 29C0 E706`.

No daemon, database or configuration changes.

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
