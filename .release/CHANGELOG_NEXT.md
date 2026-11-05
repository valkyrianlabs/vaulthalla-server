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
  ListObjectVersions, HEAD/GET/COPY with `versionId`) sign with `vl::sigv4::sign` from vl-sigv4 (Valkyrian
  Labs, MIT) instead of the in-tree `storage::s3::sigv4::sign`. Same bytes on the wire: `SigV4Goldens.VlSigv4MatchesUpstreamGoldens` and
  `VlSigv4SendsWhatTheUpstreamSignerSent` hold it to every upstream golden record. The in-tree signer stays as the
  reference until a release is verified.
- SES: `SesProvider::send` (SES v2 SendEmail) signs with `vl::sigv4::sign` (service `ses`) instead of
  `email::providers::detail::signAwsV4`. Same request on the wire: `SigV4Goldens.VlSigv4MatchesSesGoldens`,
  `VlSigv4SendsWhatTheSesSignerSent` and `SesProviderSendSignsLikeTheGoldens` (URL, header lines, Authorization).
  The old signer, kept as the goldens' reference until a release is verified, deviated from SigV4 for inputs
  SendEmail never has (unsorted query, bare flag parameters, untrimmed header values, single-encoded non-S3 paths);
  `VlSigv4FixesTheSesSignersDeviations` holds vl-sigv4 to the spec there.
- S3 data path: object PUT (buffer, file, conditional), GET (buffer, file, streamed), HEAD, copy-in-place metadata
  updates, DELETE, `listObjectKeysPage`, multipart initiate/part/complete/abort, the credential probe and
  `isBucketEmpty` sign with `curl::signDataPathRequest` (behind `curl::buildAuthorizationHeader`), built on vl-sigv4's
  primitives, instead of the in-tree legacy signer. Callers still build the URL, the header lines and the
  payload hash (`UNSIGNED-PAYLOAD` or the body's SHA-256, per operation, unchanged), so the request is the same:
  `SigV4Goldens.VlSigv4MatchesLegacyGoldens` and `VlSigv4SendsWhatTheLegacySignerSent` hold it to 23 of the 24 legacy
  records, and `S3DataPathWire.*` sends every request shape through real curl to a capture server and checks that
  vl-sigv4's verifier accepts it and that the old signer computes the same Authorization for it.
  - One time source: `buildHeaderMap` no longer sets `x-amz-date`; the signer sets it from the instant it signs at
    and takes the credential-scope date from the same instant. The old signer read the scope date from a second
    clock read (`getDate()`), so a request stamped just before UTC midnight and signed just after carried two dates and
    was refused (`VlSigv4DataPathDatesComeFromOneInstant`).
  - Header values are signed trimmed with inner whitespace collapsed, as SigV4 says; the old signer signed them
    verbatim, which fails at S3 for values with extra whitespace. No data-path header carries any (every value is
    generated or an ETag read back trimmed), so no request changes; `VlSigv4FixesTheLegacySignersDeviations`.
  - `curl::buildAuthorizationTrace` (the old signer) has no production callers and stays as the goldens' reference
    until a release is verified.
- SES: an `email.ses.endpoint` with a path prefix (an SES proxy at `https://host/aws`) is signed for the path it is
  sent to. `SesProvider::send` used to send to `<endpoint>/v2/email/outbound-emails` while signing
  `/v2/email/outbound-emails`, so every send through such an endpoint failed with SignatureDoesNotMatch. The endpoint
  is split into origin, Host and prefix, the prefix is signed with the SES path, and the URL is built from what was
  signed. Endpoints without a path are unchanged. Regression test `SesProviderTest.EndpointPathPrefixIsSentAndSigned`
  verifies the sent request with vl-sigv4's verifier.
- Build: new dependency vl-sigv4 (0.2.1), a static library built from the release tarball pinned in
  `subprojects/vl-sigv4.wrap` (sha256 checked by meson) and committed in `subprojects/packagecache/`, so the package
  build stays offline (`--wrap-mode=nodownload`). Needs only libcrypto >= 3.0, already a build dependency; installs
  nothing into the package.
- S3 gateway: SigV4 verification moves to vl-sigv4 (`vl::sigv4::verify` with a `SecretLookup`):
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
- S3 gateway: signed streaming uploads (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD` and `-TRAILER`: mc and the AWS Java SDK
  over plain HTTP) are accepted. They were `NotImplemented` (501) before.
  - `Session` spools a streamed PUT as before. It now hands aws-chunked bodies to `Router::route` still encoded
    (`BodyPayload::aws_chunked_decode_to`) when Content-Encoding says `aws-chunked` or `x-amz-content-sha256` is any
    `STREAMING-*` mode. mc sends signed chunks without Content-Encoding.
  - `Router::route` decodes the body with `decodeAwsChunkedBody` (`protocols/s3/RequestBody.cpp`, vl-sigv4's
    `AwsChunkedDecoder`). Unsigned framing is decoded before authentication, as before. Signed chunks are decoded
    after it, through the `vl::sigv4::ChunkVerifier` that `Authenticator::authenticate(input, &chain)` /
    `verifySignedRequest(..., &chain)` returns once the seed signature verified.
  - `routeAuthenticated` runs only after the final chunk (and the trailer signature) verified. A tampered,
    reordered, dropped or missing chunk stores nothing and leaves an existing object unchanged.
  - The Session's own aws-chunked decoder (`decodeAwsChunkedBody` in `Session.cpp`) is gone. Moving to the library
    parser changes some answers:
    - Framing errors were a `std::runtime_error` that closed the connection without a response. They are now S3
      errors: `IncompleteBody` (400) for a truncated body, a missing final chunk or an
      `x-amz-decoded-content-length` mismatch; `InvalidRequest` (400) for malformed framing, a chunk over 16 MiB or
      trailers that differ from `x-amz-trailer`; `SignatureDoesNotMatch` (403) for a chunk or trailer signature;
      `InvalidArgument` for a non-numeric `x-amz-decoded-content-length`.
    - Stricter, as AWS and MinIO are: chunk sizes are 1 to 16 hex digits (no sign, whitespace or `0x`), chunk
      headers end in CRLF, header and trailer lines are at most 4 KiB, trailer lines need a `name:` token, and no
      bytes may follow the end of the body. The trailer layouts of the AWS SDKs and of MinIO's Go client are both
      accepted.
  - Signed chunks outside a streamed PUT, and SigV4a streaming, still answer `NotImplemented`. New `sigv4StatusFor`
    rows: `ChunkSignatureMismatch` 403; `MalformedChunkedEncoding`, `ChunkTooLarge`, `IncompleteBody`,
    `DecodedLengthMismatch` 400.
  - Tests:
    - `S3GatewayStreaming.*` covers mc- and SDK-shaped uploads, trailers and every failure class.
    - `S3GatewayClientCaptures` replays mc's real uploads over plain HTTP (one chunk, three chunks, and
      `mc cp --checksum` unsigned trailers), each verified and decoded at its signing time. Captures come from the
      new `tools/dev/sigv4-capture/capture_mc_streaming.sh`, and a flipped byte in a signed body fails.
    - `S3GatewayDbTest.SignedStreamingUploadsStoreOnlyFullyVerifiedBodies` runs end to end over a socket. Tampered,
      reordered, dropped and unfinished bodies store nothing, and a tampered overwrite keeps the old object.
    - `S3GatewayDbTest.RealMcUploadsOverPlainHttpWhenMcIsInstalled` runs a real mc against the running gateway and
      skips where mc is not installed.
- Tests: SigV4 characterization goldens (`core/tests/unit/test_sigv4_goldens.cpp`, `core/test-assets/sigv4/`) pin the
  canonical requests and signatures of the upstream, legacy data-path, SES and gateway signers ahead of their
  consolidation. Two test seams, no behaviour change: `curl::buildAuthorizationTrace` (the legacy signer with the
  scope date given) and `email::providers::detail::signAwsV4` (SesProvider's signer, now in `SesSigning.hpp`).
- Release CI: the macOS `.pkg` and its `.sha256` publish to Apthalla's raw repository `valkyrian-raw` (VPS loopback
  port 8090; `pkg.vaulthalla.sh` serves it) instead of Nexus. `tools/macos/pkg/publish-nexus.sh` is now
  `publish-pkg.sh` (`PKG_REPO_URL`, uploads carry `X-Checksum-SHA256`; immutable, read back as before) and the
  release job is `macos-publish-pkg`. README.Debian's needrestart example names a placeholder `example.service`
  instead of `nexus.service`.
- Offline startup (#316): `ProtocolService` no longer downloads password lists before starting the ws/http
  listeners (a failed download threw out of `runLoop` and the listeners never started without internet). The
  lists ship as `/usr/share/vaulthalla/password-lists/{dictionary,common-passwords}.txt` (SecLists NCSC top 100k,
  MIT; SCOWL size 50 dictionary, SCOWL licence; provenance in `deploy/password-lists/README.md`) and load once per
  process from local files, never throwing. The unlicensed `dolph/dictionary` list is gone.
  - `Strength::checkPwnedPassword` returns `NotFound`/`Found`/`Unavailable`, with a 3 s connect and 5 s total
    timeout, a 4 MiB response cap and no redirects; `Unavailable` no longer blocks a password change.
  - Lists swap in under a mutex (readers take snapshots). Tests: `OfflineStartup.*` (listeners up with no list
    files and zero outbound requests; refused, blackholed, unresolvable and HTTP-error breach lookups).
- Protocols: `ProtocolService` and the device listener keep their io_context for the life of the process while any
  `ws::Session` object is alive (new `ws::Session::liveCount()`, a `SessionLifetimes` token released after the
  socket). ws sessions stay cached in the session manager across a listener restart; freeing the context made their
  later destruction a use-after-free (intermittent SIGSEGV, found by `OfflineStartup.ListenersStart…` under
  `MALLOC_PERTURB_`: 11/40 runs before, 0/80 after).
- Crypto (#318): `KeyProvider` generates new master secrets with libsodium's `randombytes_buf`
  (`KeyProvider::generateMasterSecret`); they came from `std::random_device`, one call per byte. Already-sealed
  secrets are untouched (no reseal, no rotation). `fs::ops::generate_random_suffix` (the names of plaintext working
  copies, staging and seal temporaries) uses `randombytes_uniform` instead of a `std::mt19937`. Contract
  `tools/contracts/test_crypto_rng_contract.py` keeps `<random>` engines out of `core/`; tests `MasterSecretRng.*`.
- Sharing (#317): email-challenge codes are delivered. `share::Manager::startEmailChallenge` sends the code through
  `ChallengeCodeSender` (`share/CodeDelivery.{hpp,cpp}`; default: the configured `email::Provider`, idempotency key
  `share-challenge-<id>`), only when the address is a listed recipient; other addresses get the same reply and no
  email (audit `share_email_recipient_not_listed`). Send failures are logged and audited
  (`share_email_delivery_failed`), never reported. Without email delivery, `createLink`, an `updateLink` into
  `email_validated`, and `startEmailChallenge` throw `ops::Refused{"share_email_unavailable"}`. The email names no
  file, link or sharer. Tests: `ShareManagerTest.EmailChallengeSendsTheCodeToTheListedRecipientOnly`,
  `EmailValidatedLinksNeedEmailDelivery`, `AFailedSendIsAuditedNotReported`, `ShareCodeEmail.*`, and the ws
  challenge test now asserts delivery.

