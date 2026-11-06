- S3 gateway request bodies are staged as `crypto::ScratchFile` ciphertext (process key) in
  `<backing>/.s3-request-body/` instead of plaintext in `<backing>/s3-request-body/`; both are cleared at startup (#345).
- S3 multipart parts are sealed under the vault key (AES-256-GCM, fresh IV per write, AAD bound to vault, upload id,
  part number and size; `protocols/s3/PartCipher`). Migration 118 adds `s3_gateway_multipart_part.encryption_iv` and
  `key_version`. CompleteMultipartUpload authenticates every part, then streams them into the vault object (no
  `.complete-object` concatenation file); a failed part answers `InvalidPart` and keeps the upload.
- Startup seals pre-#345 plaintext parts after an MD5 and size check, deletes the plaintext, and removes files and
  directories no open upload references.
- `ObjectStore::putObjectFromFile` and `MultipartStore::uploadPartFromFile` are replaced by `putObjectFromSource` and
  `uploadPartFromSource` (`fs::PlaintextSource`).
