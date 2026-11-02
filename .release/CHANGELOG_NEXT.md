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
