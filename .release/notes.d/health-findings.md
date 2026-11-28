## Health findings you can acknowledge and silence

A warning or error on the Health pages now leads somewhere. Each finding has a stable class (the code it has always
carried, such as `system.fuse.error_rate_high`), and an operator can say two things about it:

- **Acknowledge** ("I have seen this"): marks the finding that is active now. The mark ends by itself when the
  finding clears or gets worse.
- **Silence** ("stop telling me about this"): silences a class of finding, active or not, for a time or until it is
  turned back on. A silence does not cover the finding getting worse.

The server keeps this state, so every operator, the CLI and every paired Mac see the same thing. Nothing is hidden
or made to look healthy: a silenced error is still an error on the Health pages and in `overall_status`, and it is
listed as silenced with who did it and until when. What changes is the new "unattended" counts
(`unattended_error_count`, `unattended_warning_count`): the findings that still ask for a person.

- `vh health` lists the findings and their state (exit status 0 when nothing is unattended, 1 for a warning, 2 for
  an error). `vh health ack <class>`, `vh health silence <class> [--for 24h]` and `vh health unsilence <class>`
  change it.
- **A new permission, `admin.stats.manage`,** is needed to acknowledge, silence and turn back on. Seeing the
  dashboard (`admin.stats.view`) is not enough. The built-in `super_admin` role has it; add it to any other role
  that should (`--allow-stats-manage`).
- Every change is recorded in the audit trail (`health.finding.acknowledge`, `.silence`, `.unsilence`).
- AI agents can read findings and cannot change their state, on any path.
- Each finding also names what can be done about it: today, the page to open.
- **Paired Macs and other clients hear about changes by push.** A client that subscribes (`health.subscribe`) is told
  within 15 seconds when a finding appears, clears or changes, and at once when someone acknowledges, silences or
  turns one back on. Nothing about the findings is sent to an account that can no longer see them.
