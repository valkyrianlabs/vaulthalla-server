- VHF1 at rest for new writes (#367, WS2-b; design/encryption/02 §3.7, §3.8, §4): every new content generation is
  VHF1 (`EncryptionManager` encrypt/encryptToFile/reseal/rotation, FUSE seals, `createFile`, hydrate-and-seal of
  plaintext objects, provider restores, key salvage, the resumable sealing cursor). The generation id
  (`files.encryption_iv`, `recovery_blob.encryption_iv`, upload rows, `x-amz-meta-vh-iv`, the remote index) is the
  header salt; its length tells the formats apart (`vault::content::formatOf`: 12-byte IV = legacy GCM, 32-byte salt
  = VHF1). Legacy GCM stays readable everywhere and is not rewritten.
- Reads: `storage::Vhf1FileReader` (per-chunk authentication, catalog size as the authenticated object size, sticky
  failures) behind `Engine::openPlaintextReader`; `RemoteRangedReader` authenticates VHF1 windows (header GET at
  open); hydrate verifies VHF1 with a full chunk walk. No VHF1 path calls `gcmCtrDecryptAt`
  (`crypto::util::gcmCtrDecryptAtCallsForTesting`, `Vhf1AtRestTest.IntegrityContract*`).
- Resumable uploads: `vault::content::PrefixSealer` seals whole chunks as the prefix grows, resumes by authenticating
  the recorded prefix, and continues under a fresh salt (`<ord>.sealed.resalt`, `Resumable::setSealing`) when bytes
  past the record or divergent stored bytes would otherwise reseal an index under one salt. Uploads created before
  this release keep the legacy cursor.
- Size math is format-aware everywhere it was `plaintext + 16` (repairAtRest's size correction, hydrate/ranged
  expectations, provider version sizes and own-write detection, rotation's re-seal check, conflict preview caps,
  restore and snapshot estimates). `crypto::util::b64_decode` decodes any length (it was capped at 12 bytes).
- Migration 125: generated `files.content_format` and `recovery_blob.content_format` (`plain`/`gcm0`/`vhf1`) with
  partial indexes on legacy rows, for the conversion (#372) and the retirement gate (#376).
- `crypto::vhf1::Expectation::objectUid` is optional (the generation then binds the object), `IntegrityRegistry::peek`.
- Tests: `Vhf1AtRestTest.*` (writes, streaming, local range reader, IntegrityContract, sidecars), `Vhf1ResumableTest.*`,
  `Vhf1UploadTest.*` (fake S3: 0-byte/small/multipart one object each, part failure aborts, lost Complete response,
  identical retries, versioned), `CloudRemoteReadTest.Vhf1*`.
