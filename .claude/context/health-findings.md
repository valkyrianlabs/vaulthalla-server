# Health findings (classes, acknowledge, silence)

Design: `design/health/findings.md` (server half of the "Round out the Mac experience" epic,
valkyrianlabs/vaulthalla-desktop#75; server issues #482, #483).

- **A finding is computed, never stored.** The dashboard cards raise it with `dashboardOverviewAddIssue`
  (`core/src/stats/model/DashboardOverview.cpp`). Its code is its **class** and is a contract: never reuse one for
  another meaning.
- **`health::Catalog`** (`core/src/health/Catalog.cpp`) lists every class: card, title, worst severity, whether it is
  worth interrupting someone (`notifies`: every error; a warning only when it is not normal work, so not
  `system.operations.active_work`), and remedies. A new code without a catalog entry fails
  `HealthCatalog.CoversEveryCodeTheCardsRaise`.
- **State** is `health_finding_state` (migration 172), one row per (class, subject): `acknowledged` (this occurrence;
  removed when it clears or gets worse) or `silenced` (the class; optional expiry; does not cover a higher severity).
  The rules are `health::resolve` (pure); `health::snapshot()` applies them and deletes stale rows.
- **Severity is never rewritten** ("stats never fake health"). Clients get `state` per finding and the
  `unattended_*` counts; `overall_status`, `error_count` and `warning_count` are what they always were.
- **Who:** read = `admin.stats.view`; acknowledge, silence, unsilence = `admin.stats.manage` (bit 1 of
  `admin_role.stats_permissions`; built-in super_admin only).
- **Surfaces:** `ops::health` behind ws `health.*` and `vh health`; the push below. `stats.dashboard.overview` / `.severity` are
  annotated in the ws handler (`health::annotate`).
- **Agents read only:** `vh health ack|silence|unsilence` are in `mcp::exclusions()`, and `health.finding.` is in
  `Router::isScopedDeviceForbidden`. Tests: `HealthFindingAgents.*`.
- **Remedies** are data naming a place (`open`) or an existing ws command (`command`); there is no remedy endpoint.
  Today every class has an `open` remedy only: findings have no subjects yet, so no command can be named with its
  payload.
- **Push** (§6; `protocols::ws::HealthNotifier`, service `HealthNotifier` in runtime::Manager next to
  `FsChangeNotifier`): ws `health.subscribe` → `{revision}` (admin.stats.view; effect read, so a read-scoped device
  may) and `health.unsubscribe`. While any session is subscribed the service evaluates `health::snapshot()` every
  15 s on its own thread and bumps the revision when `health::digest` changes; no subscriber, no evaluation. The first
  subscriber after none evaluates on its own thread, so its answer's revision is current. `ops::health` calls
  `health::stateChanged()` after each acknowledge, silence and unsilence, which reaches the notifier
  (`health::setStateListener`) and makes the next pass (every 250 ms) evaluate at once. Event
  `{"command": "health.changed", "data": {revision, overall_status, error_count, warning_count,
  unattended_error_count, unattended_warning_count}}`, no findings. Permission re-checked every 30 s; a session that
  lost it gets `{revision, "subscribed": false}` and nothing else. One pending event per session, built from the
  newest evaluation when it goes out, held while `Session::queuedFrames()` is at 64. The subscription lock is never
  held while the findings are read. Capability `health.push`.
- **Tests:** `core/tests/unit/test_health_findings.cpp` (`HealthPushDb.*` for the push, driven by explicit times
  through `tick(now)` and the delivery seam), `contract/models_health.cpp`. A test replaces the source of findings
  with `health::setActiveSourceForTesting`.
- **Console** (#483, `web/src/features/health/findings/`): the Overview's "Needs attention" (`FindingsPanel`, from
  `health.findings.list {include_catalog: true}`) shows each finding's state; `can_manage` accounts get Acknowledge,
  Silence (`SilenceDialog`, lazy: 1 h, 24 h, 7 d, until turned back on; note up to 500 UTF-8 bytes as the server counts
  it), Turn back on and each `open` remedy whose href is a console path. "Silenced" lists silenced findings and the
  answer's `silences` (titles from the catalog). Change answers replace the cached list (catalog kept) and the
  severity rollup. The top bar dot (`HealthIndicator`) reads the unattended counts (`badgeFor`: all seen = "Nothing
  new", never green); the Hero and section badges keep the true counts. `push.ts` holds one ref-counted
  `health.subscribe` while the top bar or any health view is mounted (capability `health.push` via `lib/hello.ts`),
  invalidates the findings and severity on each `health.changed`, resubscribes on every socket open, and reports
  "subscribed" so those reads stop polling; `"subscribed": false`, a dropped socket or no capability means polling.
  Words in `copy.ts`, rules in `model.ts` (both unit-tested); `tests/e2e/health.spec.ts` scripts it offline.
- **Not built yet:** email following findings.
