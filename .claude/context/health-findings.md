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
- **State** is `health_finding_state` (migration 170), one row per (class, subject): `acknowledged` (this occurrence;
  removed when it clears or gets worse) or `silenced` (the class; optional expiry; does not cover a higher severity).
  The rules are `health::resolve` (pure); `health::snapshot()` applies them and deletes stale rows.
- **Severity is never rewritten** ("stats never fake health"). Clients get `state` per finding and the
  `unattended_*` counts; `overall_status`, `error_count` and `warning_count` are what they always were.
- **Who:** read = `admin.stats.view`; acknowledge, silence, unsilence = `admin.stats.manage` (bit 1 of
  `admin_role.stats_permissions`; built-in super_admin only).
- **Surfaces:** `ops::health` behind ws `health.*` and `vh health`. `stats.dashboard.overview` / `.severity` are
  annotated in the ws handler (`health::annotate`).
- **Agents read only:** `vh health ack|silence|unsilence` are in `mcp::exclusions()`, and `health.finding.` is in
  `Router::isScopedDeviceForbidden`. Tests: `HealthFindingAgents.*`.
- **Remedies** are data naming a place (`open`) or an existing ws command (`command`); there is no remedy endpoint.
  Today every class has an `open` remedy only: findings have no subjects yet, so no command can be named with its
  payload.
- **Tests:** `core/tests/unit/test_health_findings.cpp`, `contract/models_health.cpp`. A test replaces the source of
  findings with `health::setActiveSourceForTesting`.
- **Not built yet:** the push (`health.subscribe`, `health.changed`), the console UI (#483), email following
  findings.
