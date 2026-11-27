# Health findings: classes, acknowledge and silence, remedies, push

Design for the server half of the "Round out the Mac experience" epic (valkyrianlabs/vaulthalla-desktop;
its Desktop half is `docs/mac-experience.md` there). Status: design, 2026-11-26. Nothing here is built yet.

The goal: a warning or error should lead somewhere. A person can say "I have seen this" (acknowledge), "stop
telling me about this kind of thing" (silence), or do something about it (a remedy), and every surface (the web
console, every paired Mac, the CLI) shows the same state because the server holds it.

## 1. What exists (audited at `400c7102`)

- **Findings are computed, not stored.** `stats::model::DashboardOverview::build` asks each card for its state and
  each card adds issues with `dashboardOverviewAddIssue(card, code, severity, message, metricKey)`. There are 27
  codes today (11 always errors, 15 always warnings, and `system.health.unhealthy`, which is either), all
  system-wide, for example `system.fuse.error_rate_high`, `system.db.disconnected`, `system.retention.overdue`,
  `system.pricing.critical_alerts`.
- **The code is already a stable class name.** `DashboardIssueSummary.code` and `DashboardAttentionItem.code`
  travel to every client. Nothing else identifies a finding.
- **The backend owns severity** and never fakes health: an unmeasured value is `unknown`, never healthy.
- **Reading** needs `admin.stats.view` (`ops::stats::requireSystem`). `stats.dashboard.severity` answers
  `{overall_status, error_count, warning_count, checked_at}` and is cheap enough to poll.
- **No state on findings.** The only acknowledgement in the product is for cost alerts
  (`pricing.notifications.ack`), which are rows, not findings.
- **Operator email** (`OperatorEmailService`) watches `SystemHealth`, not findings, with its own repeat
  suppression (`dedupe_window_minutes`, `repeat_after_hours`, `send_recovery`).
- **Push exists for one thing.** `ChangeNotifier` pushes `fs.changed` to sessions that called
  `fs.changes.subscribe`; the event says only "ask again". Nothing pushes health.
- **Audit.** `vh::audit::record` writes to the hash-chained trail; `ops::audit` reads it.
- **Agents.** MCP tools come from the CLI command book, each leaf with an effect (read, write, destructive) and an
  exclusion list (`mcp::exclusions()`) of commands agents can never reach. On the ws, a scoped device is held to
  its effect ceiling and to `Router::isScopedDeviceForbidden`.
- **No CLI for findings.** `vh status` reports runtime state and an exit status; it does not list findings.

## 2. A finding and its class

- **Class** = the issue code, unchanged: `system.fuse.error_rate_high`. Codes become a contract: they are listed
  in one catalog, a code is never reused for a different meaning, and a renamed code is a breaking change noted in
  the release notes.
- **Subject** (optional) = what the finding is about when it is not the whole server: `vault:12`. Every finding
  today is system-wide and has no subject. The field exists so a later vault-level finding does not need a new
  shape.
- **Occurrence** = one continuous period during which a class (and subject) is active. It starts when the class
  appears and ends when a check no longer reports it.
- **Catalog** (`health::Catalog`, in code, not in the database): for each class its card, a title, whether a
  notification is worth it (`notifies`), and its remedies. A code raised by a card but missing from the catalog
  fails a unit test, so the catalog cannot drift.

`notifies` is the server's opinion of whether a class deserves to interrupt someone. It is `true` for every error
class and for the warning classes that mean something is wrong or waits on a person (a degraded vault, a pending
budget override). It is `false` for warnings that describe normal work: `system.operations.active_work` is raised
by every upload. The full table is written with the catalog.

## 3. State: acknowledged and silenced

Stored in the database so it is the server's and survives a restart (migration 172, `health_finding_state`):

| Column | Meaning |
| --- | --- |
| `class`, `subject` | what it applies to (`subject` is `''` for system-wide); primary key together |
| `state` | `acknowledged` or `silenced` |
| `severity` | the class's severity when the state was set |
| `set_by`, `set_by_name` | the account that set it, and its name at that time |
| `set_at`, `expires_at` | when; `expires_at` is null for "until cleared" (acknowledge) or "until turned back on" (silence) |
| `note` | optional, up to 500 characters |

**Acknowledge** means "I have seen this occurrence". It
- applies to the occurrence that is active now, and is refused when the class is not active;
- ends by itself when the finding clears, so the next occurrence is new again;
- ends when the class's severity rises above what was acknowledged (a warning that becomes an error is news).

**Silence** means "do not tell me about this class". It
- may be set whether or not the class is active;
- lasts until `expires_at`, or until someone turns it back on when there is no expiry;
- does not cover a rise in severity: a class silenced as a warning speaks again when it becomes an error;
- survives the finding clearing and returning, which is the difference from acknowledge.

**What the state changes, and what it never changes**

- Severity is never rewritten. `overall_status`, `error_count` and `warning_count` stay the truth, exactly as
  today. A silenced error is still an error on the health pages.
- Each finding gains `state` (`active`, `acknowledged`, `silenced`) with who, when and until.
- The overview and the severity answer gain `unattended_error_count` and `unattended_warning_count`: the counts
  without acknowledged and silenced findings. Clients use these for "does something need a person" (a menu bar
  badge, a notification) and keep using the true counts for health.
- A silenced finding is always listed, under "Silenced", with who silenced it and until when. Nothing disappears.

Expired rows and acknowledgements of cleared findings are removed by the same pass that evaluates findings.

## 4. Who may do it

- **Reading** state and the catalog: `admin.stats.view`, as for the dashboard.
- **Acknowledging, silencing and turning back on:** a new permission bit, `admin.stats.manage`
  (`StatsPermissions::Manage = 1 << 1`, appended; "Allows acknowledging and silencing health findings."). It
  changes what every operator is told, so seeing the dashboard is not enough. The built-in `super_admin` role holds
  it (the migration adds it there on upgraded installs); no other role gains it.
- **A paired Desktop** acts as its approving user, by RBAC alone, as everywhere else.
- **Remedies** need whatever the underlying command needs. Listing a remedy grants nothing.

## 5. Commands

One operation layer, `ops::health`, used by the ws handlers and the CLI.

| ws command | Effect | Does |
| --- | --- | --- |
| `health.findings.list` | read | Active findings (class, subject, card, severity, title, message, href, metric, `notifies`, state and its details, remedies), silences that are set but not active, and the counts of §3. Optional `include_catalog` returns every class. |
| `health.finding.acknowledge` | write | `{class, subject?, note?}` → the finding |
| `health.finding.silence` | write | `{class, subject?, for_seconds? \| until?, note?}` → the silence |
| `health.finding.unsilence` | write | `{class, subject?}` → the finding as it stands now |
| `health.subscribe`, `health.unsubscribe` | read | see §6 |

CLI: `vh health` (list, with the same exit status meaning as `vh status`), `vh health ack <class>`,
`vh health silence <class> [--for 24h | --until <time>] [--note …]`, `vh health unsilence <class>`.

`stats.dashboard.overview` and `stats.dashboard.severity` keep their shape and gain the optional members of §3,
so the console's dashboard and older Desktops are unaffected.

## 6. Push: `health.changed`

The same pattern as `fs.changed`.

- `health.subscribe` (any signed-in web session or paired device whose user has `admin.stats.view`) →
  `{revision}`. From then on the session gets an unsolicited
  `{"command": "health.changed", "data": {"revision": R, "overall_status": …, "error_count": …,
  "warning_count": …, "unattended_error_count": …, "unattended_warning_count": …}}`
  whenever the set of findings or their state changes. The event carries no findings; the client calls
  `health.findings.list`.
- **When it is evaluated.** While any session is subscribed, a `HealthNotifier` service evaluates the findings
  every 15 seconds (the same aggregation as `stats.dashboard.severity`, no trend series) and compares a digest of
  (class, subject, severity, state). No subscriber, no evaluation. An acknowledge, silence or unsilence pushes at
  once.
- **Permission is re-checked** every 30 seconds; a session that lost `admin.stats.view` gets one last event with
  `"subscribed": false`.
- **Backpressure** as in `ChangeNotifier`: one pending event per session, the newest wins, held while the
  session's write queue is long.
- A client that cannot subscribe (an older server) keeps polling `stats.dashboard.severity`.

## 7. Agents

Deliberate rule: **an agent may read findings and may not change their state.**

- `vh health` (list) is a read tool. `vh health ack`, `silence` and `unsilence` are in `mcp::exclusions()`
  ("whether a warning has been dealt with is decided by a human"), so no MCP transport lists or runs them: the
  local `vh mcp`, the device listener's `/mcp` that Desktop's bridge uses, and connector grants.
- On the ws, `health.finding.` is added to `Router::isScopedDeviceForbidden`, so an AI app's own pairing is
  refused whatever its scope.
- Remedies are not new agent powers. A remedy names an existing command; an agent can run that command exactly
  when it could before, under its ceiling and the destructive gate, and not otherwise.
- Tests assert all three refusals.

## 8. Remedies

A remedy is data on a finding: `{id, label, kind, …}`. The server only names it. The client runs it through the
ordinary path, so permission checks, confirmations and audit are the command's own. There is no remedy endpoint.

- `kind: "open"`: a place (`href`, the console's route, which Desktop maps to its own section).
- `kind: "command"`: one existing ws command with a fixed payload (`command`, `payload`, `effect`).

First set (what existing operations can honestly offer):

| Class | Remedy |
| --- | --- |
| `system.pricing.warnings`, `system.pricing.critical_alerts` | open Cost ▸ Alerts (acknowledging a cost alert is `pricing.notifications.ack`, per alert) |
| `system.pricing.pending_overrides` | open Cost ▸ Overrides |
| `system.pricing.blocked`, `system.pricing.vault_overage` | open Cost ▸ Spend |
| `system.pricing.catalog` | open Cost ▸ Alerts |
| `system.storage.degraded_vaults`, `system.storage.error_vaults` | open Storage; per affected vault, command `storage.vault.sync` |
| `system.operations.stalled`, `system.operations.failed_recent` | open Activity ▸ Operation queue |
| `system.retention.*` | open Storage ▸ Retention |
| everything else | open the card's own page (`href`) |

There is no command today that clears a stalled operation, runs retention now, or remounts FUSE. Those findings
get "open" only. A new remedial command is its own piece of work with its own permission; this design does not
add one through the side door.

## 9. Audit

`health.finding.acknowledge`, `health.finding.silence`, `health.finding.unsilence` go to the audit trail through
`vh::audit::record`, with the class, subject, the severity at the time, the expiry and whether a note was given. The
note itself is free text and stays out of the trail, which never carries names. Expiry by time
is not an event (nobody did it); the silence's own record carries when it ends.

## 10. Operator email

Unchanged in this work. The watchdog email follows `SystemHealth`, not findings, and has its own suppression.
Making email respect a silence is a separate change once findings, not the health status, drive the email.

## 11. The web console

- The health Overview's "Needs attention" list shows each finding's state and offers Acknowledge, Silence and
  the remedies, to accounts with `admin.stats.manage`.
- A "Silenced" list with who, when, until and "Turn back on".
- The nav badge uses the unattended counts; the health pages keep the true severity.
- The console subscribes to `health.changed` and stops polling the severity while subscribed.

## 12. Compatibility

- Additive on the wire: new commands, optional response members. `contract_version` and the capability list
  gain `health.findings`.
- Migration 170 creates one table and adds no bit to any existing role.
- No data, key or recovery material is involved.

## 13. Tests

- Catalog covers every code the cards raise.
- State rules: acknowledge refused when inactive, cleared on clear, broken by escalation; silence survives a
  clear, expires, is broken by escalation; counts and `unattended_*`.
- Permissions: view without manage is refused; a scoped device is refused; the MCP catalog excludes the three
  commands at every ceiling.
- Audit lines for the three actions.
- `HealthNotifier`: no subscriber no evaluation, digest change pushes once, coalescing, permission loss.
- Contract tests for the new commands and members, both generators.
