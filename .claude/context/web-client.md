# Web client (`web/`)

- Next.js 16 app router + React 19, TypeScript strict, Tailwind 4. `output: 'standalone'`.
- Toolchain: Node `24.13` (`web/.nvmrc`), `packageManager: pnpm@11.0.8`. `web/package.json` also carries `version`
  (release-managed, kept in sync with `VERSION`).
- Scripts: `dev` (turbopack), `dev:e2e`, `build`, `start`, `typecheck` (`next typegen && tsc --noEmit`: generates `next-env.d.ts`, so it works without a prior build), `lint` (`eslint src`),
  `colors` (design-token guard), `test` (= typecheck + lint + colors; **there is no unit test runner**),
  `budgets` (first-load JS gate, needs a `build`), `test:e2e` (Playwright, `web/tests/e2e`).

## Architecture (since the 2026-10 overhaul)

- **Transport:** `src/lib/ws/client.ts` — one `WsClient` class for the console socket (`/ws`) and the anonymous
  share socket (`/ws/share`): connect deadline, exponential backoff with jitter, reconnect on `online`/visible,
  per-command timeouts (`COMMAND_TIMEOUTS`; a timeout means "no answer yet", never "failed"), stale-socket guards,
  typed `WsError` kinds (`unauthorized | denied | not_found | invalid | conflict | needs_confirmation | error |
  timeout | disconnected | aborted`) from the envelope `status` + `data.code`.
- **Session:** `src/lib/session.ts`. The access token lives **in memory only**; the HttpOnly `refresh` cookie set at
  the ws handshake re-issues it (`auth.refresh`) on every page load. Single-flight refresh; an `UNAUTHORIZED`
  response refreshes and retries once (the router never ran it). Logout sends `auth.logout`, runs every
  `onSessionReset` handler, clears legacy `vaulthalla-*` keys and hard-navigates to `/login`.
- **Server data:** TanStack Query over ws (`src/lib/query.ts`: `useWs`, `useWsMutation`, `invalidate`, `fetchWs`).
  Polling = `refetchInterval` (deduped, ref-counted, paused in hidden tabs). No Zustand stores for server data;
  Zustand only for client state (transfers, UI prefs, confirm/palette state).
- **Server policy:** `src/lib/serverPolicy.ts` `useServerPolicy()` reads `settings.policy.get` (any signed-in user:
  `sharing.*` switches and `vaults.s3.*` defaults). `features/shares/policy.ts` turns it into the share kinds that
  may be created: FilesPage drops "Share link…" when none, the share dialog offers only allowed kinds, and
  `SharingNotice` (`data-testid="sharing-disabled-notice"`) explains on link lists. The new-vault form seeds its S3
  strategy/conflict from the defaults unless the user changed them. The daemon enforces all of it; the UI only hides.
- **Permissions (UI only):** `src/lib/permissions.ts` `useCan({superAdmin|permission|anyOf|prefix})` over the
  session user's admin-role permission bits. Gate on the permission core checks: Health, the health dot and system
  storage sizes use `STATS_VIEW` (`admin.stats.view`, core `ops::stats::canViewSystem`, #166); vault pages just ask
  for `stats.vault.*` and render the typed denial. `isAdminUser`/`useIsAdmin` mirror core `User::isAdmin()` and only
  remain inside `isSuperAdminUser` and the vault owner pickers. Nav items declare `requires`; pages render a typed denied state.
- **Design system:** tokens in `src/app/globals.css` (dark only; one cyan accent; `surface-1/2/3`, `line`,
  `fg/-muted/-subtle/-faint`, status `ok|info|warn|danger|unknown`; utilities `glass`, `glass-strong`, `panel`,
  `tabular`, `skeleton`). Primitives in `src/components/ui/*` (Button, IconButton, Field/Input/Select/Textarea,
  Choice (native Checkbox/Switch), Dialog/Sheet, `confirm()`, Menu (Dropdown + pointer-anchored context menu, Radix
  lazy-loaded on first interaction), Popover (lazy), CSS-only Tooltip, Tabs/LinkTabs/Segmented, Badge, Panel/
  PageHeader, Empty/Error/QueryState, Stat tiles/Meter/Sparkline/SegmentBar, DataTable, `notify`, `icons.ts`).
  `bin/check-colors.mjs` fails on raw palette/arbitrary colors outside `components/ui`. `/dev/ui` (development
  builds only) renders every primitive.
- **Shell:** `src/components/shell/*` — permission-filtered rail (collapsible), top bar (⌘K command palette, health
  dot from `stats.dashboard.severity` for `admin.stats.view`, Sync Conflicts button, transfers, cost-alerts bell, user
  menu), session gate (reconnecting state, never
  an endless spinner), initial-password warning (`data-testid="initial-password-warning"`).
- **Cost-alerts bell** (`features/cost/NotificationsBell.tsx`, super admins only): `pricing.notifications.list`
  `{limit: 8, include_acknowledged: false}` every 60 s (paused in hidden tabs). The badge count (capped "9+") and tone
  come from the response's `summary` (`open_count`, `worst_severity`), which core computes over every open alert in
  scope, never from the shown rows (#172); "View all N alerts" links to `/cost#budget-alerts` when more are open. The
  cost page's alert list (`useNotifications`, limit 50, optional acknowledged rows) is separate.
- **Features:** `src/features/<area>/*`; route files in `src/app/**/page.tsx` are thin and render a feature
  component. Areas: `files` (FileBrowser over an `FsSource` adapter — vault or share — with capability-driven UI,
  URL-addressed paths, virtualized list/grid, transfer manager), `shares`, `share` (anonymous recipient page),
  `health`, `vaults`, `access`, `account`, `credentials`, `cost`, `gateway`, `notifications`, `settings`, `auth`,
  `syncConflicts`, `recovery`.

## Server-owned ws contract

- The daemon's usage module (`core/usage`: `WsCommandUsage` book, operation catalog) defines the ws commands;
  `vh_usage --json` publishes them (`build/core/usage.json`).
- `web/src/util/generated/wsContract.{json,ts}` is generated from it: `python3 tools/contracts/ws_contract.py --write
  --vh-usage build/core/vh_usage`. Never edit by hand. `web/src/util/wsContractCheck.ts` type-checks
  `WebSocketCommandMap` against it, naming each mismatch in `pnpm typecheck` output.
- `COMMAND_TIMEOUTS` = the server-declared `WS_CONTRACT_TIMEOUTS` plus local entries for commands not in the book.
- Drift fails the meson test `ws_contract_drift` and `tools/contracts/test_ws_contract.py` (which also checks every
  book command is registered in core and typed in the web map).
- `meta.contract.get` (signed-in sessions only; no pre-login build fingerprinting) returns `{contract_version,
  contract_hash, ws_hash}`. The console checks `ws_hash` after login/refresh and on reconnects of a signed-in page,
  and shows one "server was upgraded, reload" notice per server contract.

## Sync conflicts (#187)

`features/syncConflicts/*`, route `/sync-conflicts`. Open conflicts recorded under the remote `ask` policy, only in
vaults where the account holds `vault.sync.action.resolve_conflicts` (core filters; resolving also needs filesystem
Overwrite, reported per row as `can_overwrite`).
- **One poller:** `summary.ts` `useSyncConflictSummary()` reads `sync.conflicts.summary` every 60 s (paused in hidden
  tabs; stops on denied/"Unknown command"). The top-bar `SyncConflictsButton` (count badge capped "9+",
  `data-testid="sync-conflicts-button"`) and the System → "Sync Conflicts" nav item (`NavItem.shownWhen:
  'syncConflicts'`, filtered in `useVisibleNav`, so rail, mobile nav and ⌘K agree) both hide while the total is 0 or
  the query fails.
- **Page:** `sync.conflicts.list {vault_id?}` in a DataTable with checkboxes + select-all (rows without Overwrite
  can't be selected), a vault filter from the summary's vaults (only vaults with conflicts), per-row and bulk Keep
  local / Keep remote (bulk behind `confirm()`), and a results panel listing every item that was not resolved with
  its status and message (`sync.conflicts.resolve` is per item; batches over 500 ids are split client-side; 10 min
  client timeout). Lists and summary are invalidated after every resolve.
- **Preview sheet** (`ConflictSheet`, lazy): metadata comparison (size, modified, hash, type, ETag, encrypted in
  bucket) always; images/video/audio side by side (local `src=/download/conflict?conflict_id&side=local`, remote
  fetched once into a Blob/object URL); text/markdown as an aligned side-by-side line diff (`lineDiff.ts`, Myers with
  common prefix/suffix trimming, gives up past 1000 differing lines; `TextDiff` is its own lazy chunk) when both sides
  are ≤ 2 MiB and strict UTF-8; other types metadata only. The remote side is metered: it loads with the sheet only
  when ≤ 2 MiB, larger copies need a "Load the bucket copy" click, and anything over the daemon's 32 MiB cap is not
  requested. 409/413/503 from the lane become messages.

## Vault deletion (#162)

`features/vaults/DeleteVaultDialog.tsx` (lazy, from Settings → Delete vault) is one dialog: it reads
`storage.vault.remove.plan` (re-read on window focus, so a key exported from a terminal clears the warning), shows the
restore and key windows, the S3 upstream choice (keep by default), the key-loss warning with the export command and a
required "I understand" checkbox, then Delete or Delete now (typed name). `features/vaults/DeletedVaults.tsx` (lazy, Vaults
page, accounts with a vault remove permission) lists `storage.vault.deleted.list` with Restore / Purge now and keeps the
"export this key" warning on records with `upstream_key_at_risk`. Keys are never exported through the browser.

## File previews (renderer registry)

- **The server decides.** Every file entry carries `preview: {kind, renderer, requires, thumbnail, derived?}`
  (`IPreviewPlan` in `models/file.ts`; normalized to `Entry.plan` in `features/files/entries.ts`, `derived` always a
  list). `planOf(entry)` (`preview/plan.ts`, lazy side) falls back to the old MIME rules (server JPEG for `image/*`
  and PDF) only when a daemon sends no plan; `hasThumbnail` asks `/preview/batch` only for `plan.thumbnail`
  entries. `categoryOf` maps renderers to icons (`model` → cube). Path helpers live in `features/files/paths.ts`
  (re-exported by `entries.ts`): the shell's transfer manager imports only those, so `entries.ts` stays out of
  every console route's first-load JS.
- **Capability gate (PreviewSheet).** `requires: 'preview'` needs `caps.preview` (lossy server renders only);
  `requires: 'download'` needs `caps.download` (original bytes: native media, SVG/WebP, text, 3D, derived
  artifacts). Otherwise the sheet shows "Preview not available with this link's permissions" plus metadata and
  never requests original bytes. `caps.edit` (console only) + `FsSource.textSaveUrl` enable text editing.
- **Registry** (`features/files/preview/registry.tsx`): `image` and `svg`/`image-native` ship with the sheet
  (`ImageRenderers.tsx`); `pdf`, `video`/`audio` (`MediaRenderer.tsx`), `text`/`markdown` (`TextRenderer.tsx`) and
  `model:*`/`derived:step-glb` (`ModelRenderer.tsx`) are nested `next/dynamic` chunks under the already-lazy
  `PreviewSheet`. Inside them, CodeMirror (`TextEditor.tsx`, per-extension language chunks), react-markdown
  (`MarkdownView.tsx`) and the 3D engine (`ModelViewer.tsx`, the only module allowed to import `@babylonjs/*`)
  are lazy again. Nothing under `preview/` may be imported statically from `FileBrowser`, `entries.ts`, `FileIcon`
  or the share page (first-load headroom is ~5 KB on `/files`, ~6.5 KB on `/share`).
- **HTTP per renderer** (all same-origin with the cookie; `FsSource` builds the URLs, `share=1&path=` on links):
  image `GET /preview?size=1024`; PDF `GET /preview?page=N&size=1536|2048` → blob URL, page count from
  `X-Vaulthalla-Page-Count`; SVG/WebP/video/audio `src=/download/content?disposition=inline` (Range is the
  browser's); media error → `HEAD` the same URL to tell refusals from codecs; "Convert for playback" polls
  `GET /preview/derived?kind=transcode-*` with `Range: bytes=0-0` (202 + Retry-After backoff, 503
  `converter_unavailable`, 422 `reason`); 3D `GET /download/content` (≤ 512 MiB, streamed progress) or
  `/preview/derived?kind=model-glb` for STEP, glTF/OBJ side files resolved to sibling paths (never above the vault
  or share root; ≤ 256 files and 512 MiB with the model, aborted when the viewer closes). Babylon itself never
  fetches: OBJ `mtllib`/MTL texture statements are rewritten to object URLs or removed (`model/scan.ts`, matching
  Babylon's own tokenisation and text decoding), and `model/urlGate.ts` gates every Babylon URL hook
  (`Tools.PreprocessUrl`, `ScriptPreprocessUrl`, `WebRequest.CustomRequestModifiers`) to `data:` plus URLs the
  viewer registered; text `GET /download/content` with `cache: 'no-store'` (≤ 2 MiB, no NUL, strict UTF-8) and the
  `ETag`, saved with `PUT /upload/text` + `If-Match` (412 → conflict dialog: reload / overwrite against the current
  ETag / copy; 403 → read-only).
- **Keys and unsaved work.** The sheet's ←/→ file navigation ignores keys owned by inputs, editors, media and
  canvases; PDF pages use PageUp/PageDown. Renderers report unsaved edits through `setDirty`; the sheet confirms
  before switching files or closing, and the text renderer adds a `beforeunload` guard.
- Media elements are released on switch/close (pause, remove `src`, `load()`), so the ranged connection closes.

## File recovery (`features/recovery`)

Typed ws `recovery.*` / `vault.recovery.*` (`models/recovery.ts`, `RECOVERY_CODES` = the `NeedsConfirmation` codes of
`core/include/ops/Recovery.hpp`); every piece is a `next/dynamic` import (no SSR), so it stays out of route budgets.
- **History sheet** (`RecoveryHistorySheet`): FileBrowser's `onRecoveryHistory` ("Recovery history…" context-menu
  item, passed only by `FilesPage`, never by share pages) and PreviewSheet's **History** button. Grouped by backend,
  "Check provider for versions" (`refresh_provider`), snapshot create (mode local_snapshots), point delete, Restore…
  with an alternate destination, and the folder point-in-time form (shown for every folder; ops refuses it in local
  vaults).
- **Restore preview** (`RestorePreviewDialog`): plan items/counts/consistency note/estimate/blockers; typed `RESTORE`
  when anything is overwritten or removed; separate unverified acknowledgement; `recovery_plan_expired` re-plans and
  shows the fresh plan before anything runs.
- **Vault settings → Recovery** (`RecoveryPanel`, mounted by `VaultSettings`): mode, provider state, snapshots, local
  versioning, backlog, retained keys, cost alert, suspend. `update.ts` `sendRecoveryUpdate` asks for retention
  shortening / bucket adoption and resends; disclosure/unpriced go to `DisclosureDialog` (every acknowledgement ticked,
  re-fetched when the token expired or the figures changed).
- **Costs:** `RecoveryCostPanel` under the sync policy form on **Vault → Sync & cost** (`VaultSync`, anchor
  `#recovery-costs`); the Cost page's `ProviderVersioningCard` only links to each S3 vault's panel (estimates are never
  summed). Unknown money renders "not estimated"/"cannot be estimated", never $0.00 (`costParts.tsx`).

## Routes

`/login`, `/files/[vaultId]/[...path]`, `/shares`, `/vaults` (+ `/new`, `/[id]` tabs: overview, access, shares,
sync, gateway, settings), `/users` (+ `/new`, `/[name]`), `/groups`, `/roles` (+ `/new?type=`, `/[type]/[id]`),
`/credentials` (+ `/new`, `/[id]`), `/cost`, `/s3-gateway`, `/health` (+ runtime, filesystem, storage, activity),
`/notifications`, `/settings`, `/sync-conflicts`, `/account`, `/share/[token]/[...path]` (public, no shell). Old URLs (`/fs`,
`/dashboard/*`, `/api-keys/*`, `/pricing-budget`, `/operator-email`, `/users/add`, `/vaults/:id/edit|assign`,
`/roles/admin|vault/*`) redirect (`next.config.ts`).

## Performance gate

`pnpm budgets` (`bin/check-budgets.mjs` + `perf-budgets.json`) measures first-load JS per route (gzip; root chunks +
layout/page entry chunks; dynamic imports and legacy polyfills excluded) from the production build and fails over
budget. CI runs it after `pnpm build` (hard gate); `tools/dev/verify.sh web` runs it with `VERIFY_WEB_BUILD=1`.
Next 16 + React 19 alone are ~143 KB. Keep dialogs/editors/charts/menus behind `next/dynamic` or lazy primitives.
The same script fails if Babylon.js code (content markers `BABYLON.`, `ArcRotateCamera`, `babylonjs.com`,
`@babylonjs/core/`) lands in any route's first load, and budgets the 3D model viewer's lazy chunks separately
(`lazy.modelViewer`: the `next/dynamic` group of the chunk carrying the `vh-model-viewer` marker, ~282 KB on open;
`lazy.modelViewerReachable`: everything it can load on demand, an over-counting ceiling). Babylon is imported only
in `features/files/preview/ModelViewer.tsx` and `preview/model/**`; Draco/meshopt decoders are bundled (Draco's
wasm + wrapper emitted to `/_next/static/media` via `new URL(..., import.meta.url)`), never fetched from a CDN.

## Wiring and env

- `middleware.ts` makes no upstream call: public paths (`/login`, `/share`, static files) pass; any other path
  needs a non-empty `refresh` cookie or it redirects to `/login?next=<path+query>`. Whether the cookie is still valid
  is decided by the websocket session gate (`SessionGate` → `auth.refresh`): a refusal sends the user to
  `/login?next=…`, while an unreachable daemon shows the reconnect state, never the login page. Pages carry no data
  (everything loads over the socket after the gate), so the presence check is all the middleware needs. Until #171
  it verified the cookie against the daemon's `GET /auth/session` on each document load, which cost a ~0.57 s Argon2
  verify per page; that path (`src/lib/server/authCheck.ts`, `/api/auth/session`) is gone. The daemon's
  `GET /auth/session` itself still exists. Guard: console e2e "middleware only checks for a refresh cookie".
- The WS URL is `ws(s)://<location.host>/ws` unless `NEXT_PUBLIC_VAULTHALLA_WS_ORIGIN` is set. The app expects a reverse
  proxy that routes `/ws` → 36969 and `/preview|/download|/upload` → 36970 (nginx in prod, `Caddyfile` in dev).
  HTTP uploads: `POST /upload/session[?share=1]` → `PUT /upload/<id>/files/<fileId>` → `POST /upload/<id>/finish`
  (`DELETE` on failure); the client splits large drops into several sessions. Downloads are preflighted with a
  `HEAD` of the same `/download` URL (status → failed-task message; a folder's 413 means too many entries) before
  handing the URL to the browser with `anchor.download`. Folder ZIPs report their exact size like files. Browsers
  strip a leading dot from saved names themselves (Chromium `SanitizeGeneratedFileName`, Firefox
  `ValidateFileNameForSaving`); the server and the console keep it, and ZIP members keep it.
- `next.config.ts`: SVGR loader (webpack + `turbopack.rules`), `images.localPatterns /preview**`, redirects,
  `devIndicators: false`. `package.json` `sideEffects: ["**/*.css"]`.

## Private icons (build gotcha)

FontAwesome Pro icons aren't in git (`/web/public/icons/fa/` is ignored). `web/bin/sync_private_icons.sh` (CI:
`.github/actions/sync_web_icons`) copies only the icons the code imports (`@/fa-*/…svg`, mostly via
`src/components/ui/icons.ts`) from `$VAULTHALLA_WEB_ICON_SRC` (default `~/vaulthalla-web-icons`). A fresh checkout's
`pnpm build` fails without them; any new icon must exist in that store.

## Testing

`tests/e2e/console.spec.ts` is the console dogfood suite (route sweep, redirects, ws budget and poller shutdown,
file lifecycle, multi-item drop, shares incl. upload-only dropbox, logout hygiene); run it against a reverse-proxied
install (`VAULTHALLA_E2E_BASE_URL=https://localhost VAULTHALLA_E2E_NO_WEB_SERVER=1`). `lab-first-run.spec.ts` is the
packaged-install proof; `s3-gateway.spec.ts` drives the gateway page by `data-testid`, records the budget policies it
saves (from the `*.budget.policy.upsert` responses on `/ws`) and in `afterAll` acknowledges their "policy <id> was
saved|disabled" alerts on `/cost` before deleting the vaults it created. `preview.spec.ts` covers the rich previews (plans in the listing,
PDF paging, ranged video/seek, audio, codec fallback, text edit/save and 412 conflict, markdown safety, 3D canvases,
no 3D engine chunk on an image preview, preview-only vs download share links) with fixtures from
`tests/e2e/fixtures/preview/generate.mjs`; a preview-only link is made by rewriting the `share.link.create` frame
(`page.routeWebSocket`), since the share dialog only offers presets. `recovery.spec.ts` scripts the `recovery.*` /
`vault.recovery.*` answers on the console socket (`page.routeWebSocket`; everything else reaches the real daemon) and
proves the console's own rules: history sheet, typed `RESTORE`, disclosure acknowledgements, unknown costs never $0.

## Packaging

`web/bin/install_web.sh` (source installs) and `web/bin/build_package.sh` stage `.next/standalone` + `.next/static` +
`public` into `/usr/share/vaulthalla-web`, which runs as `vaulthalla-web.service` (`node server.js`).
