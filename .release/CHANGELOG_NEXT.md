<!--
vl-release staged changelog: package-facing changes for the NEXT release.
Maintained continuously while working; `vlr prepare` renders it into debian/changelog
and resets this file to this template.

Format: one "- " bullet per change (concise, technical). Indent continuation lines.
Optional "## Section" headings group bullets; if used, every bullet must be under one.
One level of nested "  - " detail bullets is allowed. Consolidate; don't paste commit logs.
-->
- S3: `Controller::uploadLargeObject` (file and buffer overloads) throws after aborting a multipart upload whose part
  failed. It used to return normally, so `CloudEngine` uploads, backlog replays and recovery restores of objects
  >= 5 MiB treated the aborted upload as stored. Regression test
  `S3VersionedFake.AFailedMultipartPartAbortsAndThrowsForBuffersAndFiles` runs the real driver against the
  versioned fake.
- S3/SQS/STS: the upstream control plane (bucket administration, event notifications, `provider::admin::detail::send`)
  and the object requests built by `Controller::signObjectRequest` (the full bucket LIST of `listObjects`,
  ListObjectVersions, HEAD/GET/COPY with `versionId`) sign with `vl::sigv4::sign` from vl-sigv4 0.1.0 (Valkyrian
  Labs, MIT) instead of the in-tree `storage::s3::sigv4::sign`. Same bytes on the wire: `SigV4Goldens.VlSigv4MatchesUpstreamGoldens` and
  `VlSigv4SendsWhatTheUpstreamSignerSent` hold it to every upstream golden record. The in-tree signer stays as the
  reference until a release is verified; the legacy data-path and gateway implementations are unchanged.
- SES: `SesProvider::send` (SES v2 SendEmail) signs with `vl::sigv4::sign` (service `ses`) instead of
  `email::providers::detail::signAwsV4`. Same request on the wire: `SigV4Goldens.VlSigv4MatchesSesGoldens`,
  `VlSigv4SendsWhatTheSesSignerSent` and `SesProviderSendSignsLikeTheGoldens` (URL, header lines, Authorization).
  The old signer, kept as the goldens' reference until a release is verified, deviated from SigV4 for inputs
  SendEmail never has (unsorted query, bare flag parameters, untrimmed header values, single-encoded non-S3 paths);
  `VlSigv4FixesTheSesSignersDeviations` holds vl-sigv4 to the spec there.
- Build: new dependency vl-sigv4 0.1.0, a static library built from the release tarball pinned in
  `subprojects/vl-sigv4.wrap` (sha256 checked by meson) and committed in `subprojects/packagecache/`, so the package
  build stays offline (`--wrap-mode=nodownload`). Needs only libcrypto >= 3.0, already a build dependency; installs
  nothing into the package.
- S3 gateway: SigV4 verification moves to vl-sigv4 0.1.0 (`vl::sigv4::verify` with a `SecretLookup`):
  `protocols::s3::verifySignedRequest` parses, runs every secret-free check (date, skew or presign window, signed
  headers, payload hash), then looks the credential up, then compares the signature in constant time. `Router::route`
  builds the input with `protocols::s3::verificationInput` (Beast adapter). The in-tree `protocols/s3/SigV4` has no
  production callers and stays as the goldens' reference until a release is verified.
  - Same acceptance for real clients: 126 requests captured from aws-cli 2.38, boto3 1.34, rclone 1.69 and mc 2025-08
    over HTTP and HTTPS (`core/test-assets/sigv4/client-requests.jsonl`, `tools/dev/sigv4-capture/`) verify as
    before, and `SigV4Goldens.VlSigv4VerifierMatchesGatewayGoldens` rebuilds every S3 gateway record.
  - Error codes follow AWS (`vl::sigv4::awsErrorCode`; statuses in `sigv4Error`): RequestTimeTooSkewed (403),
    InvalidAccessKeyId (403, was AccessDenied), AuthorizationHeaderMalformed / AuthorizationQueryParametersError (400),
    XAmzContentSHA256Mismatch (400), AccessDenied (403) for a missing Authorization, missing or invalid date or an
    expired presigned URL, NotImplemented (501) for signed-chunk payloads, InvalidArgument (400) for header plus
    presigned query. Everything else was SignatureDoesNotMatch (403); a wrong signature and a missing signed header
    still are, and session tokens are still InvalidToken (400).
  - Newly refused (AWS refuses them too): host not signed, credential scope date != x-amz-date date, X-Amz-Expires=0,
    Authorization header plus presigned query, malformed x-amz-date, credential scope or SignedHeaders, Authorization
    parts without '='. Newly accepted (spec-valid, refused before): repeated signed headers combined with ',', an
    X-Amz-Signature query parameter on a header-signed request, upper-case hex in x-amz-content-sha256.
  - The credential lookup (a DB query and the secret's decryption) now runs after the date and payload checks, not
    before them.
- Tests: SigV4 characterization goldens (`core/tests/unit/test_sigv4_goldens.cpp`, `core/test-assets/sigv4/`) pin the
  canonical requests and signatures of the upstream, legacy data-path, SES and gateway signers ahead of their
  consolidation. Two test seams, no behaviour change: `curl::buildAuthorizationTrace` (the legacy signer with the
  scope date given) and `email::providers::detail::signAwsV4` (SesProvider's signer, now in `SesSigning.hpp`).
