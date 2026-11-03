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
  reference until a release is verified.
- SES: `SesProvider::send` (SES v2 SendEmail) signs with `vl::sigv4::sign` (service `ses`) instead of
  `email::providers::detail::signAwsV4`. Same request on the wire: `SigV4Goldens.VlSigv4MatchesSesGoldens`,
  `VlSigv4SendsWhatTheSesSignerSent` and `SesProviderSendSignsLikeTheGoldens` (URL, header lines, Authorization).
  The old signer, kept as the goldens' reference until a release is verified, deviated from SigV4 for inputs
  SendEmail never has (unsorted query, bare flag parameters, untrimmed header values, single-encoded non-S3 paths);
  `VlSigv4FixesTheSesSignersDeviations` holds vl-sigv4 to the spec there.
- S3 data path: object PUT (buffer, file, conditional), GET (buffer, file, streamed), HEAD, copy-in-place metadata
  updates, DELETE, `listObjectKeysPage`, multipart initiate/part/complete/abort, the credential probe and
  `isBucketEmpty` sign with `curl::signDataPathRequest` (behind `curl::buildAuthorizationHeader`), built on vl-sigv4
  0.1.0's primitives, instead of the in-tree legacy signer. Callers still build the URL, the header lines and the
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
- Build: new dependency vl-sigv4 0.1.0, a static library built from the release tarball pinned in
  `subprojects/vl-sigv4.wrap` (sha256 checked by meson) and committed in `subprojects/packagecache/`, so the package
  build stays offline (`--wrap-mode=nodownload`). Needs only libcrypto >= 3.0, already a build dependency; installs
  nothing into the package.
- Tests: SigV4 characterization goldens (`core/tests/unit/test_sigv4_goldens.cpp`, `core/test-assets/sigv4/`) pin the
  canonical requests and signatures of the upstream, legacy data-path, SES and gateway signers ahead of their
  consolidation. Two test seams, no behaviour change: `curl::buildAuthorizationTrace` (the legacy signer with the
  scope date given) and `email::providers::detail::signAwsV4` (SesProvider's signer, now in `SesSigning.hpp`).
