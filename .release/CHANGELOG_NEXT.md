<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->

## File recovery

- Vault recovery preference (`off | local_snapshots | provider_versioning`, migration 111), shared recovery model and
  one authorizing boundary (`ops::recovery`), CLI `vh snapshot …`, `vh recovery list|inspect|plan|restore|delete|costs`,
  `vh vault recovery status|set|suspend|disclosure`, ws `recovery.*` / `vault.recovery.*`, web console Recovery
  history, restore preview, vault Recovery panel, cost disclosure dialog and recovery cost panel.
- Local snapshots: explicit, named, encrypted recovery points of a file or directory tree (deduplicated zero-copy
  blobs under `<backing>/.vh-recovery/<vault>`), survive deletion of the live files (`file_versions.file_id` cascade
  replaced by SET NULL), count against a snapshot quota and the vault quota, restore to the original or an alternate
  destination with a CAS against concurrent writes.
- Local versioning (opt-in): every content change keeps the prior sealed generation (keep-last / max-age / quota);
  in upstream vaults unsent generations form an ordered backlog replayed into a versioned bucket when the provider is
  reachable again; cache vaults release local bodies once the provider holds them.
- Provider versioning (AWS S3): capability detection (R2 refused), explicit activation behind a signed cost
  disclosure, adoption of an existing vault's bucket, propagation window, noncurrent retention (30/90/365 days or
  indefinite; shortening needs its own acceptance), confirmed suspension that deletes nothing, a lifecycle rule
  expiring the index manifest's noncurrent versions, protected and unmanaged buckets never mutated.
- Version-aware restore: provider copy (same key, ≤ 5 GiB) or bounded GET + re-seal + PUT under the sync pass lease;
  cache vaults adopt the restored generation index-only so nothing is uploaded twice; point-in-time directory plans
  are labelled timestamp-based reconstructions.
- Local, telemetry-free usage accounting per vault (`vault_upstream_usage_daily`) and a decimal cost model for
  versioning (observed vs illustrative bases, ranges, retention scenarios, unpriced when no profile; never $0.00),
  cost alerts as operator notifications that never block writes.
- Historical keys: retired vault key versions are unsealed on demand for recovery reads only and kept while
  recoverable data needs them (trigger `recovery_guard_retired_vault_key`); key export includes them.
- Backing files are never written in place (new files are created exclusively or replaced by rename; contract test).
- Re-sealing a retained generation wipes the decrypted (still unauthenticated) plaintext on every path, and unsealed
  retired keys leave memory once idle on a 30 s timer instead of waiting for the next recovery read.
- Provider restore verifies what it restores: a plaintext version in a vault that encrypts upstream is refused (even
  when unverified versions are accepted) unless the vault's event subscription imports foreign objects, and a version
  Vaulthalla wrote must still match its recorded IV, key version and size.
- Local versioning limits that delete retained versions sooner (a new or lower keep-last / max-age / quota, or turning
  versioning back on with limits) need the same explicit acceptance as a shorter provider retention, with a count of
  what the next retention run deletes; every recovery settings change is written to the audit log.
- The versioning cost disclosure reveals the bucket's configuration (object lock, MFA delete, other applications'
  lifecycle rules) only to callers with admin.upstream.view and view on the vault's API key, like a status refresh;
  others get the cost figures without a provider request.

## Fixes

- fuse: rename over an existing file replaces it as rename(2) does (editors' temp-file saves failed with EIO; a
  failed cross-folder rename stranded the file's bytes); replacing needs Delete on the destination, and with local
  versioning on the replaced content is kept as a version (reason overwrite).
- S3 data plane: the legacy signer puts the canonical query in SigV4 order (paged listings past 1,000 keys failed
  with SignatureDoesNotMatch on page 2); a CompleteMultipartUpload 200 carrying an <Error> body is a failure.
- fix(vault): a restart during an unfinished key rotation could not load the vault's key (`get_rotation_old_vault_key`
  selected `*` from `vault_keys_trashed`, which has no `updated_at`).
- Deleting a folder (web console, ws `fs.entry.delete`) also drops its subfolders and symlinks from the filesystem
  metadata cache; recreating a path under the deleted folder failed.
- S3 sync: a full bucket LIST throws when any page fails (transport error, 403/503, cut or non-XML body) instead of
  returning the keys gathered so far, and every page of a listing reaches the remote index (buckets past 1,000
  objects indexed only their first page) (#246).
- Upstream admin (AWS): HeadBucket goes straight to the bucket's known region (cached, `upstream_bucket.region`, else
  the key's region): one request instead of a global-endpoint probe plus a regional one; the global endpoint is
  probed only when no region is known or a redirect names none (#247).
- S3 sync: a pass publishes the remote index manifest once (a vault's first pass PUT it twice: after the full LIST
  and again after its uploads); a pass that stops early still publishes the listed index; the expected 404 for a
  missing manifest (and any absent object's HEAD) is logged at debug, not as an error (#248).
- Local versioning: pending upstream versions of a deleted file whose key is never written again no longer stay
  pending forever: maintenance replays them into a bucket that keeps history (under the sync pass lease,
  price-preflighted, then deleted again so the file stays deleted) or marks them skipped (`orphaned`) when the bucket
  keeps none or never had the file, so retention can free their blobs; live and trashed keys are left to sync (#249).
