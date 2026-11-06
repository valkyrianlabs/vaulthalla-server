---
title: Audit Trail
description: The tamper-evident record of who did what in Vaulthalla, how it is protected, and how to review, verify, export and forward it.
order: 7
status: published
tags:
  - admin
  - audit
  - security
  - compliance
---

# Audit Trail

Vaulthalla records security-relevant actions in a tamper-evident audit trail. Every event is stored in the database as a link in a hash chain, the server signs the end of the chain at regular intervals, and the same lines go to `audit.log` and, optionally, to syslog.

## What Is Recorded

| Area | Events |
| --- | --- |
| Sign-in | Successful and refused sign-ins (with the reason and client address), sign-outs, idle sign-outs, password changes and resets |
| Multi-factor sign-in | Second-factor challenges and results, delays after repeated failures (`auth.mfa.lockout`), factors enrolled, renamed, suspended and removed (flagged when enrolled during a recovery), recovery codes made, saved and used, recovery-code sign-ins (`auth.mfa.recovery.signin`, with the sessions signed out and device key backups paused), MFA resets and requirements by an administrator or `vh` (`auth.mfa.admin.reset`, `.require`, with the channel and reason), policy changes (`auth.mfa.policy.change`), step-ups granted, failed and required (refusals during a recovery cooldown say so) |
| Access control | Admin and vault role changes, role assignments, permission overrides, group changes and membership |
| Files | Folder creation, deletes, renames, moves and copies from the console; downloads, previews and uploads over HTTP; `vh fs get` and `vh fs put` |
| S3 gateway | Credential creation, revocation, scope, vault, role and override changes |
| Keys and vaults | Key export, import and rotation, vault deletion and restore, recovery actions |
| Settings | Changes to sharing, the S3 gateway and device connections |
| The trail itself | Viewing, verifying and exporting the trail, retention purges, and gaps |

Files and folders are named by their entry id, never by name or path. A file name can itself be sensitive (see the `logging.file_paths` setting in [Configuration](/reference/configuration)).

## How It Is Protected

- **Hash chain.** Each event's SHA-256 hash covers all of its fields and the hash of the event before it. Changing, inserting, reordering or deleting an event breaks every hash after it.
- **Append-only table.** The database refuses updates and deletes on the audit tables. The one exception is the retention purge, which first records where the remaining chain starts.
- **Signed heads.** Every `auditing.trail.head_interval_minutes` (15 by default), and at shutdown, the server signs the newest event's hash with its Ed25519 attestation key. A signed head shows when events were removed from the end of the chain, which a hash chain alone cannot show.
- **Copies outside the database.** Each signed head is also written to `audit.log` and, when enabled, to syslog. Forward syslog to another system, such as a SIEM, so that someone who controls this server cannot rewrite every copy.

:::callout[What this does not prevent]{variant="warning"}
Anyone with database owner rights or root on the server can disable the trigger and rewrite the chain, or stop the daemon from recording at all. The trail makes such tampering **detectable**, by verification and by comparison with forwarded copies. It does not make tampering impossible. Forward events off the host if you need evidence that survives a compromised server.
:::

Writes never block a request. Events go into an in-memory queue that a background service writes in batches. While the database is unreachable, events wait in the queue and in `audit.log`. If the queue overflows, the oldest events are dropped and an `audit.gap` event records how many. Verification then shows the gap instead of a silently shorter history.

## Review And Verify

Reading the trail needs the **view audits** admin permission (`admin.audits.view`). Super admins have it. Every view, verification and export is itself recorded.

::::tabs{default="console"}

:::tab[Console]{value="console"}
Open **System › Audit trail**. Filter by action prefix (`auth.`, `rbac.`, `fs.`, `s3.`) or outcome. **Verify chain** checks the whole retained trail. **Export** downloads it as NDJSON.
:::
:::tab[CLI]{value="cli"}
```bash
vh audit list --action auth. --since 2026-11-01
vh audit verify
vh audit export --since 2026-01-01 > audit-2026.ndjson
```
`vh audit verify` exits with status 1 when the trail fails verification, and names the first bad event.
:::
::::

### Reconstruct an MFA recovery

Every recovery path can be followed from the trail alone. `vh audit list --action auth.mfa.` (add `keys.backup.` for the
device side) shows, in order:

- **A recovery-code sign-in:** `auth.mfa.challenge`, `auth.mfa.recovery.use` (the batch and the codes left),
  `auth.login.success`, `auth.mfa.verify` (method `recovery_code`), one `keys.backup.grant.revoke` per paired device,
  `auth.mfa.recovery.signin` (sessions signed out, grants revoked, the cooldown's end), then any refusals during the
  cooldown (`auth.stepup.required`, denied, reason `recovery_cooldown`), the replacement factor
  (`auth.mfa.factor.enroll` with `during_recovery: true`) and the new codes (`auth.mfa.recovery.generate`,
  `.acknowledge`).
- **An administrator's or `vh` reset:** one `auth.mfa.factor.remove` per disabled factor and one
  `keys.backup.grant.revoke` per device (the administrator or CLI user as actor, the account as `target_id` /
  `user_id`), `auth.mfa.admin.reset` (channel `admin_reset` or `cli_reset`, the reason, the counts), then the
  account's guided enrollment at its next sign-in. Refused resets are recorded too (outcome `denied`).

Run `vh audit verify` afterwards: it proves nothing in between was changed or removed.

A verification reports how many events it checked, the first event that fails (if any) and why, how many signed heads are valid, and how many events came after the newest signed head. Those events get signed at the next interval.

## Verify An Export Offline

An export (`vh-audit-export-v1`) contains every event with its hashes, plus the signed heads that cover them. You can check it on any machine, without Vaulthalla:

```bash
python3 tools/audit/verify_export.py audit-2026.ndjson --public-key <hex>
```

`--public-key` takes the server's attestation public key, and can be repeated for retired keys. With it, the script also checks the head signatures, which needs the Python `cryptography` package. Without it, the script checks the hashes only.

## Retention And Forwarding

```yaml
auditing:
  trail:
    retention_days: 2190         # six years; minimum 30
    head_interval_minutes: 15    # 1..1440
    syslog: false                # also send audit events to the local syslog
    syslog_facility: authpriv    # auth | authpriv | local0..local7
```

The daemon purges events older than `retention_days` once a day. It always keeps the newest signed head and the events after it. The default of six years matches the HIPAA documentation retention period (45 CFR 164.316(b)(2)). Shorten it only if your own policy allows.

With `syslog: true`, each audit line goes to the local syslog as `vaulthalla-audit`, and journald or rsyslog can forward it. `auditing.audit_log` keeps controlling the rotation of `audit.log` itself.
