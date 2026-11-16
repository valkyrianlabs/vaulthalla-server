- vl-vaultfmt 0.3.0 (its main at 54742cb, a `git archive` tarball committed for the offline build) replaces 0.1.0.
  It adds a database-free engine and a WebAssembly reader the server doesn't use, and the manifest root's writer
  floor, which the server now honours: a manifest root written by a newer Vaulthalla (a `writer_floor` above this
  server's writer revision, 1) is neither applied nor published over. The vault's sync stalls with the stop reason
  `manifest_writer_floor` (shown as `last_apply.stopped` in `storage.vault.get` and `vh vault sync info`), the
  operators are alerted once per root (`manifest_apply_stopped`) telling them to upgrade this server, and nothing is
  changed; the next successful apply or publish clears it. Roots without a floor (every root written so far) behave
  as before; this server writes none. The writer floor vectors are copied to `design/encryption/vectors/` and checked
  identical to the library's.
