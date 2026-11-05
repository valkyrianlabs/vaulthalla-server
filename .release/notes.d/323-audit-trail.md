## Security

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
