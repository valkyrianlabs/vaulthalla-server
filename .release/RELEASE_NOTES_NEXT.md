<!--
vl-release staged release notes: the user-facing story of the NEXT release.
Maintained continuously while working; `vlr prepare` promotes it into the release notes
history (and the GitHub release) and resets this file to this template.

Format: the first line is "# <release title>" WITHOUT a version number (vlr adds it).
Everything after the title is the Markdown release body. Describe the resulting behavior
for users and operators; keep it representative of what actually ships.
-->
# Large uploads to S3 and R2 no longer fail silently

- Uploading a file of 5 MiB or more to an S3 or R2 vault could fail partway (a timeout, a SlowDown, a dropped
  connection) and still be treated as uploaded. Vaulthalla cancelled the incomplete upload at the provider but then
  carried on as if the file had arrived, so the bucket could be missing a file that the vault showed as synced. A
  failed part now fails the upload, and the file stays pending for the next sync pass.

## S3 gateway

- The S3 gateway checks request signatures with vl-sigv4, Valkyrian Labs' shared AWS Signature Version 4 library.
  AWS CLI, boto3, rclone and MinIO mc requests, presigned URLs included, are accepted exactly as before.
- Refused requests now carry the error code AWS S3 would send, so clients report the real cause instead of a
  signature mismatch: `RequestTimeTooSkewed` when the client's clock is off by more than 15 minutes (SDKs that correct
  their clock react to it), `InvalidAccessKeyId` for an unknown, disabled or expired gateway key,
  `AuthorizationHeaderMalformed` or `AuthorizationQueryParametersError` (HTTP 400) for a malformed signature,
  `XAmzContentSHA256Mismatch` when the body doesn't match its declared hash, `AccessDenied` for an unsigned request or
  an expired presigned URL, and `NotImplemented` for uploads with signed chunks (`mc` and the AWS Java SDK over plain
  HTTP), which the gateway has never accepted. A wrong secret is still `SignatureDoesNotMatch`.
- Requests that break SigV4 rules AWS S3 enforces are now refused too: an unsigned `Host` header, a credential date
  that differs from the request date, a presigned URL with `X-Amz-Expires=0` (it used to never expire), and a
  presigned URL that also carries an `Authorization` header. No client that works with AWS sends these.
- Requests whose credentials don't check out no longer cause a credential lookup: a request with a bad date, a stale
  timestamp or a mismatched body is refused before the gateway reads or decrypts any key.

## Under the hood

- Requests to S3, R2, SQS and STS for bucket administration, event notifications, full bucket listings and
  file-version recovery are now signed by vl-sigv4, Valkyrian Labs' shared AWS Signature Version 4 library, instead
  of a copy inside Vaulthalla. The signed requests are byte-for-byte the same, so nothing changes for providers or
  keys.
- Operator email sent through Amazon SES is signed by vl-sigv4 too. The requests are the same as before, so SES
  credentials and settings need no change.
- The everyday traffic of S3 and R2 vaults (uploads, downloads, listings, deletes, multipart uploads) is signed by
  vl-sigv4 as well, so all of Vaulthalla's AWS request signing now goes through that one library. The requests are
  the same as before. One rare failure is gone: a request signed at the very moment UTC midnight passed could carry
  two different dates and be refused by the provider; both dates now come from the same instant.
