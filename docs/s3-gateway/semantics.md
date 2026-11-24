---
title: S3 Gateway Semantics
description: Understand S3 Gateway LIST, bucket subresources, HEAD, GET, PUT, DELETE, ETags, multipart storage, backfill, and current protocol limitations.
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

Both listing calls are served, for local and remote-backed buckets alike:

| Call | Request | Resumes from |
| --- | --- | --- |
| ListObjectsV2 | `GET /bucket?list-type=2` | `continuation-token` (the `NextContinuationToken` of the page before), or `start-after` for a first page |
| ListObjects | `GET /bucket` without `list-type=2` | `marker` (`NextMarker`, or the last key of the page before) |

### Order And Paging

Keys are listed in ascending UTF-8 byte order, as S3 lists them: `big-single.bin` comes before `big.bin`, and uppercase before lowercase. The order does not depend on the locale of the PostgreSQL cluster. `start-after`, `marker` and continuation tokens resume with the same comparison, so paging never skips or repeats a key, and a client may merge or diff listings by comparing keys as bytes.

A page holds up to `max-keys` items, 1000 at most. With a `delimiter`, each common prefix counts as one item and is listed once, even when its keys span a page boundary. `KeyCount` (ListObjectsV2) counts keys and common prefixes together.

`start-after` and `marker` name a key, which need not exist. Keys after it are listed, and with a delimiter they still roll up into their common prefix, including the prefix the named key lies in. A position that is itself a common prefix of the listing (for example a `NextMarker` of `photos/` with the delimiter `/`) skips every key under it.

### Continuation Tokens

`NextContinuationToken` is opaque. Send it back exactly as received: it is never percent-encoded, whatever `encoding-type` the request asked for, and it needs no encoding of its own in a query string beyond what every SDK already does. A token the gateway did not issue is refused with `InvalidArgument`. When a request carries both a token and `start-after`, the token wins.

`encoding-type=url` percent-encodes the fields that hold key text and nothing else: `Key`, `Prefix`, `Delimiter`, `CommonPrefixes`, and `StartAfter` (ListObjectsV2) or `Marker` and `NextMarker` (ListObjects). SDKs decode exactly those fields.

`prefix`, `delimiter`, `start-after` and `marker` must be valid UTF-8; anything else is refused with `InvalidArgument`.

## Bucket Subresources

A bucket request that names a subresource (`GET /bucket?versioning`, `PUT /bucket?lifecycle`, `DELETE /bucket?policy`, ...) is a configuration call. It is never answered as a listing, and it never creates or deletes a bucket. The gateway has no bucket configuration of its own (see [Limitations](#limitations)), so a GET answers what S3 answers for a bucket that never had the feature configured:

| Subresource | GET answer |
| --- | --- |
| `location` | 200, an empty `LocationConstraint` (`us-east-1`) |
| `versioning` | 200, an empty `VersioningConfiguration`: versioning was never enabled |
| `notification`, `logging`, `accelerate` | 200, an empty `NotificationConfiguration`, `BucketLoggingStatus` or `AccelerateConfiguration` |
| `requestPayment` | 200, `Payer` `BucketOwner` |
| `lifecycle` | 404 `NoSuchLifecycleConfiguration` |
| `policy` | 404 `NoSuchBucketPolicy` |
| `cors` | 404 `NoSuchCORSConfiguration` |
| `tagging` | 404 `NoSuchTagSet` |
| `encryption` | 404 `ServerSideEncryptionConfigurationNotFoundError` (vault encryption at rest is not an S3 bucket encryption setting) |
| `object-lock` | 404 `ObjectLockConfigurationNotFoundError` |
| `website` | 404 `NoSuchWebsiteConfiguration` |
| `replication` | 404 `ReplicationConfigurationNotFoundError` |
| `publicAccessBlock` | 404 `NoSuchPublicAccessBlockConfiguration` |
| `ownershipControls` | 404 `OwnershipControlsNotFoundError` |
| `versions` (ListObjectVersions) | 501 `NotImplemented` |
| `acl`, `policyStatus` | 501 `NotImplemented`: access is decided by Vaulthalla RBAC and credential scopes, which an S3 ACL or policy status can't describe |
| `uploads` | ListMultipartUploads |
| any other subresource | 501 `NotImplemented` |

PUT, DELETE and POST on any of these (other than POST `?delete`, DeleteObjects) answer 501 `NotImplemented` and change nothing: `put_bucket_versioning`, `put_bucket_lifecycle_configuration`, `delete_bucket_policy` and the like fail loudly instead of appearing to succeed.

Remote-backed buckets answer the same way. The answer describes the gateway bucket, not the settings of the upstream S3/R2 bucket behind it.

A subresource call is authorized as a listing of the bucket is. A caller who may not list the bucket gets the listing's error (`NoSuchBucket`, `AccessDenied`), whatever subresource it names.

Every subresource S3 defines is recognized by name, and any other query parameter sent without a value is treated as a subresource the gateway does not know. The listing parameters (`list-type`, `prefix`, `delimiter`, `marker`, `start-after`, `continuation-token`, `max-keys`, `encoding-type`, `fetch-owner`), the paging parameters of ListMultipartUploads, presigned-URL parameters and other parameters with a value keep a request a listing.

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
- S3 object versioning, including ListObjectVersions.
- Lifecycle rules.
- Object lock, legal hold, or MFA delete.
- Bucket configuration of any kind (CORS, tagging, encryption settings, website, replication, notifications, logging). [Bucket Subresources](#bucket-subresources) lists what each configuration call answers.
- Vaulthalla undo-delete integration for gateway deletes.

Large PUT and multipart bodies are accepted by the gateway path, but operators should size `max_body_size_mb`, client retry behavior, and request budgets for the workload.
