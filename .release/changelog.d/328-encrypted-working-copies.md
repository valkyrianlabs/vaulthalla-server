- FUSE working copies (now `<backing>/.fuse-working`), private HTTP upload staging (`.upload-staging`) and `vh fs put`
  staging (`.cli-staging`) are block-encrypted at rest (XChaCha20-Poly1305 per 64 KiB block, fresh nonce per write,
  AAD bound to the file and block) under a random per-process key held only in locked memory (#328).
- A working copy whose seal fails stays registered as unsaved and is retried every 60 s, on the next
  flush/fsync/release and at FUSE stop; a file deleted meanwhile is restored as a new file. Unsaved copies still
  failing at shutdown, or left by a crash, are deleted with an error naming how many were lost.
- The startup sweep deletes everything under `.fuse-working`; plaintext an older version left in `.fuse-plaintext/unsaved/` is kept
  with a warning and the rest of `.fuse-plaintext` is removed.
- `fs::NewFileContext::source_path` is replaced by `source` (`fs::PlaintextSource`); `EncryptionManager` gains
  `encryptToFile` and `decryptFileTo` (sink), and `decryptFileToFile` is gone, so nothing decrypts to a plaintext file.
