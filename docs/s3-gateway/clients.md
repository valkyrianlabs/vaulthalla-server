---
title: S3 Gateway Clients
description: Configure AWS CLI, rclone, and MinIO mc as downstream S3 clients for Vaulthalla S3 Gateway.
order: 20
status: published
tags:
  - s3-gateway
  - clients
  - aws-cli
  - rclone
  - minio
---

# S3 Gateway Clients

Downstream S3 clients connect to Vaulthalla with gateway credentials, not upstream provider credentials. Use the direct listener for local/private access or the managed S3-domain endpoint for public reverse-proxy access.

:::toc[On this page]{depth="3" theme="compact"}
:::

## Endpoint Selection

| Endpoint | URL | Notes |
| --- | --- | --- |
| Direct local endpoint | `http://127.0.0.1:39000` | Good for local automation and smoke tests. |
| Public S3-domain endpoint | `https://s3.vaulthalla.example.com` | Managed Nginx path-style reverse proxy. |

Configure path-style addressing for clients whenever possible. In path-style mode, `s3://archive/photos/image.jpg` becomes `/archive/photos/image.jpg` on the gateway endpoint.

## AWS CLI

Configure the gateway key:

```bash
aws configure set aws_access_key_id VH...
aws configure set aws_secret_access_key ...
aws configure set default.region us-east-1
aws configure set s3.addressing_style path
```

Use the public S3-domain endpoint:

```bash
aws --endpoint-url https://s3.vaulthalla.example.com s3api list-buckets
aws --endpoint-url https://s3.vaulthalla.example.com s3 cp ./file.txt s3://archive/file.txt
aws --endpoint-url https://s3.vaulthalla.example.com s3 rm s3://archive/file.txt
```

Use the direct local endpoint:

```bash
aws --endpoint-url http://127.0.0.1:39000 s3api list-buckets
aws --endpoint-url http://127.0.0.1:39000 s3 cp ./file.txt s3://archive/file.txt
aws --endpoint-url http://127.0.0.1:39000 s3 rm s3://archive/file.txt
```

Directory upload and download:

```bash
aws --endpoint-url https://s3.vaulthalla.example.com s3 sync ./photos s3://archive/photos
aws --endpoint-url https://s3.vaulthalla.example.com s3 sync s3://archive/photos ./restored-photos
aws --endpoint-url https://s3.vaulthalla.example.com s3 rm s3://archive/photos/old-prefix --recursive
```

## rclone

Example rclone remote:

```ini
[vh-public]
type = s3
provider = Other
access_key_id = VH...
secret_access_key = ...
endpoint = https://s3.vaulthalla.example.com
force_path_style = true
region = us-east-1
acl = private
```

Directory upload, sync, download, and delete examples:

```bash
rclone copy ./photos vh-public:archive/photos --progress
rclone sync ./backup vh-public:archive/backup --progress
rclone copy vh-public:archive/photos ./restored-photos --progress
rclone delete vh-public:archive/backup/old-prefix --rmdirs
```

`rclone copy` preserves existing destination objects that are not in the source. `rclone sync` makes the destination match the source, including deletes. For remote-backed gateway buckets, those deletes are local-first in Vaulthalla and upstream cleanup remains sync-owned.

## MinIO mc

Configure a public endpoint alias:

```bash
mc alias set vh https://s3.vaulthalla.example.com VH... ...
```

Basic object operations:

```bash
mc cp ./file.txt vh/archive/file.txt
mc ls vh/archive
mc rm vh/archive/file.txt
```

Directory operations:

```bash
mc cp --recursive ./photos vh/archive/photos
mc cp --recursive vh/archive/photos ./restored-photos
mc rm --recursive --force vh/archive/photos/old-prefix
```

Use `http://127.0.0.1:39000` in the alias when the client runs on the Vaulthalla host and should bypass public Nginx.

## Upload Signing Over HTTP and HTTPS

Clients choose how to sign an upload body. They usually decide based on whether the connection is encrypted. The gateway accepts each of these modes:

| Client and connection | `x-amz-content-sha256` | What the gateway checks |
| --- | --- | --- |
| AWS CLI, boto3, rclone, mc over HTTPS | the body's SHA-256, `UNSIGNED-PAYLOAD` or `STREAMING-UNSIGNED-PAYLOAD-TRAILER` | The request signature, plus the body hash when one is sent. |
| mc and the AWS Java SDK over plain HTTP | `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` (signed chunks) | The request signature, then every chunk's signature in order, ending with the final zero-length chunk. |
| AWS SDKs with signed trailing checksums | `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` | As above, plus the trailing checksum header's signature. |

Signed-chunk uploads arrive `aws-chunked` encoded. The gateway decodes the body as it arrives and verifies each chunk's signature against the previous one. Nothing is written to the bucket until the whole body has verified. If a chunk was altered, dropped, reordered or truncated, the upload fails and nothing is stored. When the request was overwriting an object, the existing object is left unchanged.

| Failure | S3 error | HTTP |
| --- | --- | --- |
| A chunk or trailer signature does not match | `SignatureDoesNotMatch` | 403 |
| The body ends before the final chunk, or its length differs from `x-amz-decoded-content-length` | `IncompleteBody` | 400 |
| Malformed chunk framing, a chunk larger than 16 MiB, or trailers that differ from `x-amz-trailer` | `InvalidRequest` | 400 |
| SigV4a streaming (`STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD`) | `NotImplemented` | 501 |

So `mc` works against the direct listener too:

```bash
mc alias set vh-local http://127.0.0.1:39000 VH... ...
mc cp ./file.txt vh-local/archive/file.txt
mc cp --checksum CRC32C ./file.txt vh-local/archive/file.txt
```

Plain HTTP still sends the request in clear text, so keep it on loopback or a private network. Prefer the HTTPS endpoint everywhere else.

## Multipart Uploads

Multipart uploads are supported for large object and directory workflows. Vaulthalla stores upload parts in Vaulthalla-owned hidden per-upload backing directories until the upload is completed, aborted, or expired by the configured retention window.

Multipart ETags use the S3-style form based on part MD5 digests and part count. They are client-visible gateway metadata and are not the same value as Vaulthalla's local encrypted content hash.
