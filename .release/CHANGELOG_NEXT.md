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
- fix(vaults): changing an S3 vault's API key or bucket inserted a second binding row (`s3_pkey` violation), and
  creating a vault on a key + bucket another vault used moved that vault's binding to the new one
  (`upsert_s3_vault` conflicted on (api_key_id, bucket)); bindings are now updated per vault and a pair that belongs
  to another vault (live or pending deletion) is refused.
- fix(storage): remote-only files indexed from objects that were plaintext from the start (an adopted or waivered
  bucket's data, another tool's upload) could not be read in vaults that encrypt upstream (the hydrate called them a
  downgrade); they are now sealed on the way in. A sealed file whose object turns plaintext is still refused.
- upstream: a create-new attempt claims nothing until CreateBucket succeeded and the bucket listed empty (a transient
  HeadBucket/CreateBucket failure no longer leaves a "created by Vaulthalla" record that cleanup would trust); retries
  resume only a bucket the same record really created.
- upstream: cleanup holds its own lease (adoption, create retries, detach and other cleanups are refused meanwhile; a
  lock or binding set during the run stops it), and a provider error part way is reported and audited as partial with
  the bucket left recoverable.
- upstream: lifecycle writes rebuild only `vaulthalla-managed`; every other rule round-trips verbatim and is verified
  after the write; an externally customised `vaulthalla-managed` rule is refused rather than rewritten; re-enabling a
  disabled expiration needs the destructive confirmation.
- vaults: deleting a vault on an adopted bucket refuses `--delete-upstream` (the retention purge refuses it too).
- rbac: provisioning with a lifecycle rule or event subscription needs admin.upstream.configure; unprotect needs key
  consume; the upstream audit log shows only entries for keys the reader may view; repointing an administrative key
  (provider, endpoint or access key) turns administration off, and is refused while it operates event subscriptions.
- fix(upstream): bucket names are validated before they reach a provider (vault create/update, every upstream op,
  the AWS/R2 adapters) and Cloudflare REST paths are percent-encoded; a name such as `x/../prod` could address another,
  protected bucket through the Cloudflare API, whose paths no signature covers. Legacy names can still be locked.
- fix(upstream): bucket identity (and so protection locks) follows the credential's endpoint: an R2 or AWS endpoint
  saved under another provider label is treated as R2/AWS (unknown AWS account fails closed); new keys whose provider
  contradicts their endpoint are refused.
- fix(upstream): provisioning regions are validated (AWS region codes, R2 location hints) before they become host
  names or CreateBucket bodies, and the CreateBucket body is built as XML; queue policies refuse bucket names or
  account ids that would widen `aws:SourceArn`/`aws:SourceAccount`.
- sync/events hardening (#96 review):
  - the index manifest's own notification is never applied or republished (it fed an endless PUT loop);
  - events are ordered to the millisecond (R2 has no sequencer); a create/remove tie is decided by one HEAD;
  - a removal is applied only after a HEAD confirms the object is gone (404); a failed HEAD is retried, never read
    as a deletion;
  - lost continuity (dead-letter messages, a poll gap longer than queue retention, events not stored before their last
    delivery) holds events and forces one full listing instead of trusting the index; DLQ depth is reported;
  - the applier takes the vault's pass lease before reading its batch, yields to a waiting regular pass, and stops
    between keys on shutdown; the service's own requests (teardown retries, HEADs, manifest publish) are cancellable;
  - provider rule changes of one bucket are serialized and every live subscription's rules are verified after a PUT;
  - write intents are removed when the request fails and live from completion; claiming one and settling the event
    are one transaction; unrouted rows get swept and are re-routed only within the subscription's prefix and age;
  - a scoped pass dropped before it runs releases its lease; `vault sync reconcile`/`inventory` take the lease;
  - `vh vault sync events --file` needs admin.upstream.configure + sync.config.edit + key Consume (it can delete);
  - vaults that encrypt upstream default to `foreign_objects=ignore` (adopted buckets keep `import`), and
    `vh-encrypted=false` over a file the vault holds sealed is refused unless the subscription imports foreign objects.
