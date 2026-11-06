---
title: S3 Gateway Semantics
description: Understand S3 Gateway LIST, HEAD, GET, PUT, DELETE, ETags, multipart storage, backfill, and current protocol limitations.
order: 60
status: published
tags:
  - s3-gateway
  - semantics
  - protocol
  - storage
---

# S3 Gateway Semantics

This page summarizes how S3 operations map to Vaulthalla vault state. The gateway aims for useful S3-compatible client behavior while keeping Vaulthalla metadata, encryption, sync, and budget rules authoritative.

:::toc[On this page]{depth="3" theme="compact"}
:::

## LIST

LIST is metadata-only. It uses gateway object metadata, Vaulthalla filesystem metadata, and sync-maintained remote object indexes.

LIST does not decrypt object bodies, read plaintext to calculate ETags, refresh manifests, or call upstream S3/R2 LIST/HEAD/GET APIs.

## HEAD

HEAD returns client-visible gateway metadata when available. Remote-backed buckets can answer metadata-backed HEAD requests from known Vaulthalla state or the remote object index without downloading object bodies.

## GET

GET can be served from:

- Local encrypted Vaulthalla files.
- Materialized remote-cache files.
- A remote-only upstream object download when the vault policy allows it.

Only the remote-only download path consumes actual upstream request and price budgets inside the gateway request. Local/cache reads do not consume provider, vault, or global upstream budgets by default.

## PUT, COPY, And Multipart Completion

PUT, COPY destination writes, and multipart completion write Vaulthalla local state and gateway metadata first. For remote-backed gateway buckets, sync owns eventual upstream upload, index, manifest, request-budget, storage-class, and encryption side effects.

Downstream clients receive the S3 response after Vaulthalla accepts the local state. They should not interpret that response as proof that upstream provider upload has completed.

## DELETE

Gateway DELETE is unversioned from the S3 client perspective.

Local buckets remove local Vaulthalla object state, object metadata, backing/cache files, and filesystem cache mappings. Remote-backed buckets mark or remove Vaulthalla local object state first, clear gateway metadata, and hide the object from future S3 LIST/HEAD/GET immediately.

The gateway does not directly delete upstream S3/R2 objects as the primary DELETE behavior. Sync observes the local delete or tombstone and owns eventual upstream purge.

## ETags And Metadata

S3 ETags are client-visible gateway metadata. They are not the same thing as Vaulthalla local `content_hash`.

| Source | ETag behavior |
| --- | --- |
| Single PUT | MD5 of the S3 request body, quoted. |
| Multipart upload | S3-style MD5 of part MD5 digests plus `-part_count`, quoted. |
| Existing Vaulthalla files without gateway ETags | Metadata-derived fallback ETags during LIST and HEAD. |

`x-amz-meta-*` headers are preserved as gateway object metadata. `Content-Type` is preserved when provided and falls back to `application/octet-stream`.

## Multipart Storage

Multipart upload parts live under Vaulthalla-owned hidden backing paths with opaque per-upload directories. They are not stored under the bucket or object-key path while an upload is in progress.

Each part is encrypted at rest under the vault's key, bound to its vault, upload and part number, so an upload can be resumed after the daemon restarts. Part ETags and sizes are those of the bytes the client sent. Completion streams the parts into the object without writing a plaintext copy. If a stored part fails its integrity check, completion answers `InvalidPart` and leaves the upload open, so the client can upload that part again. Streamed request bodies are staged encrypted under a key that exists only in the daemon's memory, and are deleted once the request is answered.

Parts are removed when the upload completes, aborts, or expires according to `s3_gateway.multipart.abort_after_days`.

## Backfill

Backfill imports existing Vaulthalla files or remote-index rows into gateway object metadata:

```bash
vh s3-gateway bucket backfill archive
```

The default path is metadata-only. Use ETag calculation only when the operator intentionally wants local body reads:

```bash
vh s3-gateway bucket backfill archive --calculate-etags
```

`--calculate-etags` reads and decrypts local file bodies to calculate plaintext MD5 ETags and prints a warning. It is not invoked by LIST.

## Limitations

Current S3 Gateway behavior does not implement:

- IAM policy or bucket policy emulation.
- ACLs.
- S3 object versioning.
- Lifecycle rules.
- Object lock, legal hold, or MFA delete.
- Vaulthalla undo-delete integration for gateway deletes.

Large PUT and multipart bodies are accepted by the gateway path, but operators should size `max_body_size_mb`, client retry behavior, and request budgets for the workload.
