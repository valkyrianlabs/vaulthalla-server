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
  reference until a release is verified; the legacy data-path, SES and gateway implementations are unchanged.
- Build: new dependency vl-sigv4 0.1.0, a static library built from the release tarball pinned in
  `subprojects/vl-sigv4.wrap` (sha256 checked by meson) and committed in `subprojects/packagecache/`, so the package
  build stays offline (`--wrap-mode=nodownload`). Needs only libcrypto >= 3.0, already a build dependency; installs
  nothing into the package.
- Tests: SigV4 characterization goldens (`core/tests/unit/test_sigv4_goldens.cpp`, `core/test-assets/sigv4/`) pin the
  canonical requests and signatures of the upstream, legacy data-path, SES and gateway signers ahead of their
  consolidation. Two test seams, no behaviour change: `curl::buildAuthorizationTrace` (the legacy signer with the
  scope date given) and `email::providers::detail::signAwsV4` (SesProvider's signer, now in `SesSigning.hpp`).
