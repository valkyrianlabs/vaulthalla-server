- vl-keykit 0.5.0 (its feat/desktop-attestation at bfeff025, a `git archive` tarball committed for the offline build)
  replaces 0.2.0, and the key check and key attestations are now vl-keykit's (`attestation.hpp`), the code Vaulthalla
  Desktop signs with: the same bytes as before (the documented vectors, now in `design/encryption/vectors/key_provenance.json`
  and checked against an independent reference). A vault a Mac created and attested (spec 03 §6.5) is restored from
  Vaulthalla Cloud canonically, its key versions proven by the Mac's attestation exactly as a server's are; a version
  without a valid attestation under a pinned key is still unproven (`salvage_required`).
