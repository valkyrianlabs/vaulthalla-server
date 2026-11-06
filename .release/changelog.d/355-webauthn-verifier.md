- WebAuthn relying-party verifier (#355, design docs/dev/mfa-design.md section 4.1, decision D5) in
  `core/{include,src}/auth/webauthn/`, built as its own static library (`vh_webauthn`) over libcbor, OpenSSL 3 and
  libsodium only: registration (`none`, `packed` self and `packed` x5c, other formats recorded as none) and
  assertions for ES256, EdDSA (Ed25519) and RS256 (2048..4096 bits); all 14 checks of the design table, including
  the session/purpose/user/scope-bound single-use challenge store, exact configured origins, crossOrigin/topOrigin,
  UP and UV, credential owner and userHandle, BE immutability and the backup-aware signCount table. Strict CBOR
  (definite lengths, no trailing bytes, no duplicate keys, bounded nesting and sizes), strict clientDataJSON and
  response JSON. Not wired into sign-in yet (#357).
- New config `auth.webauthn.{rp_id,rp_name,origins}` (config.yaml, settings.get/update, ws contract model
  `WebAuthnConfig`, console Settings › Security), validated on load and on settings.update.
- Packaging: Build-Depends `libcbor-dev (>= 0.10)`; the runtime `libcbor0.10` comes through `${shlibs:Depends}`.
  macOS: Homebrew `libcbor` (bundled into the pkg by `bundle_dylibs.py`). The CI image adds `libcbor-dev`,
  `clang-18` and `libclang-rt-18-dev`.
- Tests: W3C WebAuthn L3 section 16 vectors (`core/test-assets/webauthn/`), `WebAuthnCeremony`/`WebAuthnChecks`
  negatives per check, parser suites, `WebAuthnFuzzCorpus`; libFuzzer targets (`-Dfuzz=true`,
  `tools/dev/fuzz-webauthn.sh`) run 60 s each in PR CI; `tools/contracts/test_webauthn_contract.py`.
