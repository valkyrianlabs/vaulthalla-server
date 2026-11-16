- The vault format (VHF1 files, the object keys of opaque_v1 buckets, the encrypted manifest with its publish, read,
  reconcile and session logic) is now vl-vaultfmt 0.1.0 (Valkyrian Labs, AGPL-3.0-or-later; shared with the
  Desktop-only engine and the portal's reader), statically linked from the commit pinned in
  `subprojects/vl-vaultfmt.wrap` (its tarball committed for the offline build) and listed in `debian/copyright`. No
  behaviour change: every golden vector is unchanged, and the library's copy of the vectors is checked identical to
  the server's. Its format tests, vectors and the VHF1 fuzz target moved with it.
