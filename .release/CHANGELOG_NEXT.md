<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- upstream: provider administration for AWS S3 and Cloudflare R2 API keys (#237): capability probe, bucket
  inventory, managed bucket creation (collision-safe) and adoption (read-only admission check), Vaulthalla-owned
  lifecycle rule, detach, preflighted cleanup of buckets Vaulthalla created; `vh upstream …`, ws `upstream.*`,
  `storage.vault.add` `provision`, console credential/bucket/vault screens.
- upstream: hard bucket protection locks keyed to (provider, account, bucket), enforced in every metered S3 request,
  the admin adapters and the ops; loaded at startup (fail closed).
- sync: event-driven upstream sync (#96): AWS S3 → SQS Standard (queue policy, DLQ, notification GET-merge-PUT keeping
  foreign rules) and R2 → Cloudflare Queues (HTTP pull); durable deduplicated inbox written before ack, per-key
  ordering, self-write suppression, event-scoped sync passes, adoption baseline, bounded abortable long polls.
  `vh vault sync events --file` uses the same inbox.
- sync: a provider removal event deletes a local copy unchanged since the last agreement instead of re-uploading it.
- rbac: admin.upstream permission module (view, configure, provision, protect, unprotect, destroy); migration 110 adds
  it with the api_keys admin columns, upstream_bucket, upstream_audit and the event channel/subscription/inbox/intent
  tables.
- fix: an object without Vaulthalla metadata overwriting a known file read as encrypted with the old IV and failed to
  sync; vaults that encrypt upstream still refuse it unless their event subscription imports foreign objects.
- storage: new SigV4 signer (any service/region) and an HTTP client with connect/total timeouts and cancellation for the
  admin and queue APIs.
- fix(shell): the CLI router's debug log no longer contains credential option values (`--secret`, `--password`,
  `--token`, …); they were logged verbatim when shell debug logging was enabled.
