- The WebAuthn relying-party verifier is now vl-webauthn 0.1.0 (Valkyrian Labs, MIT; shared with Vaulthalla Cloud),
  statically linked from the release pinned in `subprojects/vl-webauthn.wrap` and listed in `debian/copyright`.
  Passkey behaviour is unchanged; the verifier also builds against OpenSSL 4. Its tests, vectors and fuzzing moved
  with it.
