# Link sharing

Merged to `main` in PR #61 (`7786acae`). Later HTTP upload/download convergence landed with PR #78.
The full per-PR history (44 specs) lives in the gitignored `.claude/scratch/link_share/`. Read it only
for archaeology, because parts of it are stale (for example, it says uploads stay on `/ws/share`, which is no longer true).

## Model

- Public/email-validated recipients are constrained **`rbac::Actor::Share`** actors
  (`rbac/Actor.hpp`, `Kind{Human,Share}`). They are never synthetic users.
- Share links assign **persisted vault role templates** to `public` or `actor` subjects, with
  per-assignment filesystem overrides (`072_share_vault_role_assignments.sql`).
  `link_share_vault_role` is legacy and read-only.
- Core: `core/include/share/*`: `Manager`, `TargetResolver`, `PrincipalResolver`, `Scope`, `RateLimiter`.
- Web: `/share/[token]/[[...path]]` renders `features/share/SharePage.tsx`, which reuses the console
  `features/files/FileBrowser` with a share `FsSource` (`features/files/source.ts`: share caps, `share=1` URLs, no
  `edit`). `features/share/shareSession.ts` (zustand) holds **only** bootstrap, session and email-challenge state and
  its own `WsClient`.

## Invariants

- **Operator switches (`sharing.*`, #164) are enforced by `share::policy` (`share/Policy.hpp`), fail closed with
  `ops::Denied` (ws code `denied`, HTTP 403).** `enabled` gates every link; `enable_anonymous` gates access mode
  `public`; `enable_email_validated` (formerly `enable_public_links`, still read as an alias) gates
  `email_validated`. Signed-in vault users' access is RBAC policy, not a switch. Checked in `share::Manager` on
  create, update (an update can't move a link into a disabled kind), `resolvePublicLink`/`openPublicSession`, both email-challenge steps and
  `resolvePrincipal`, and in `share::TargetResolver::resolve` on every file access, so principals cached by the HTTP
  lane (and live ws share sessions) stop too. `Principal::access_mode` carries the link's mode for that. Management
  (get/list/revoke/rotate) is never gated. A settings change that touches `sharing` bumps `rbac::policyEpoch()`.
  The console reads the switches from `settings.policy.get` (any signed-in user) and hides what would be refused.
  There is no CLI for share links, so there is no CLI/web parity surface here.
- Share sessions never set `Session::user`. Admin/superadmin bypass is human-only (`canUseHumanPrivileges()`).
- ws Router allowlists are exact per session mode. Adding a share-callable command means an explicit allowlist edit.
- Link creation (`canGrant`) requires the human creator to hold every delegated filesystem permission.
- **Overwrite goes through filesystem RBAC `FilesystemAction::Overwrite`** and must never become a
  share-only boolean or shortcut (`Grant.cpp`).
- Public preview, download, media and derived requests use `/preview*?share=1` and `/download*?share=1` with the
  `Secure` `share_refresh` cookie.
  Raw tokens never go in URLs. Manual QA therefore needs the HTTPS origin (Caddy, `https://vh.home.arpa:8443`).
- Uploads use the HTTP lane `/upload/session?share=1` (`features/files/transfers.ts`, `http/upload/Coordinator.cpp`).
- Resumable uploads (`/upload/sessions?share=1`, `http/upload/Resumable.cpp`) keep the same share rules: share-relative
  paths, reject / create-only only (no replace), `startUpload` limits at create (`max_upload_size_bytes` → 403),
  `recordUploadChunk` once per stored part, re-resolved principal + scope at commit as the link creator,
  `finishUpload`. A session belongs to one share session (others: 404). The 6 h stale share-upload sweep still fails
  an idle share file.
- Directory thumbnails use scoped HTTP preview, never per-row ws preview.
- Upload-only ("dropbox") shares never list or preview beyond what they were granted. A share upload needs only the
  `upload` op (parent resolves as Write → directory Upload, the file as Write → file Upload); no `metadata`/`list`.
  The seeded `share_upload_dropbox` role has no directory List on installs seeded after #151 (older installs keep
  their row; `vh role vault update share_upload_dropbox --deny-dirs-list` fixes one). The web dropbox preset should
  send `allowed_ops: ['upload']`.
- HTTP upload sessions (`http/upload/Coordinator.cpp`) expire 30 minutes after the owning session's last request or
  body chunk (sliding), with a 24 h ceiling; `Coordinator::setClockForTesting` drives the tests.
- Download `Content-Disposition` is `attachment; filename="<ASCII fallback>"; filename*=UTF-8''<pct-encoded>`
  (`Router::attachmentContentDisposition`); leading dots are kept. Single-file downloads stream with no size cap:
  positioned reads decrypt only the requested ciphertext with the GCM CTR keystream, and the whole message is
  authenticated once per file version (`IntegrityRegistry`, see `architecture.md` "Byte-serving spine"). Folder ZIPs
  stream too (STORE, exact `Content-Length`, ≤ 50,000 entries, no byte cap; `architecture.md` "Folder ZIPs"), on the
  same path with share scoping and one `max_downloads` unit per logical GET. A chunked AEAD at-rest format would only be needed for
  *authenticated* random access to remote-only objects (`preview.media.remote: ranged`).
- **Preview ≠ Download.** The share op `preview` gets only lossy server renders (`/preview` JPEGs, PDF pages,
  `poster-jpg`); `download` gets original bytes and full-fidelity derivatives (`/download`, `/download/content`
  inline media/models/text, SVG/WebP originals, `/preview/derived` `model-glb`/`transcode-*`/`probe-json`). The
  capability per file comes from the server's preview plan (`preview::classify`, `"requires"`); the web shows
  "Preview not available with this link's permissions" instead of fetching. Share editing (`PUT /upload/text`) is
  refused (403) for every share session.
- **Accounting and `max_downloads`.** `http::access::recordShareAccess` coalesces per share session × entry × source id
  × event type (`share.preview.http`, `share.content.http`, `share.download.http`, `share.derived.http`) per 30 min:
  one audit event, and for Download-capability accesses one `max_downloads` unit via `share::Manager::consumeDownload`
  (a single conditional UPDATE; previously stored but never enforced). Over the limit: HTTP 403
  `max_downloads_reached` and a `share.download.limit` Denied audit. HEAD, 304 and further ranges of the same
  playback don't count. The resolved share principal is cached 15 s keyed to `rbac::policyEpoch()`, which share link
  update/revoke/rotation bump. The console share dialog doesn't set `max_downloads` (ws `share.link.create/update`
  accept it).

## Open items (verified 2026-09-30)

1. **Email-challenge codes are never delivered.** `share::Manager::startEmailChallenge` returns a
   `verification_code`, but the ws handler drops it and nothing calls `email::Provider`. Email-validated shares
   can't be completed by a real recipient. This is the highest-value gap, and the email providers already exist.
2. Actor-native RBAC is incomplete. `rbac/resolver/vault/Context.hpp` and `rbac/fs/policy/Request.hpp`
   still carry `shared_ptr<identities::User>`.
3. `fs.dir.create` isn't in the share allowlists, so share mkdir is unsupported.
4. Duplicate policy: `rename` and `overwrite` throw "not supported in this pass"
   (`ws/handler/share/Upload.cpp`, `http/upload/Coordinator.cpp`); only `reject` works.
5. The legacy `share.fs.*`, `share.download.*`, `share.upload.*`, and `share.preview.get` ws commands are still
   registered but unused by the frontend. They can be retired.
