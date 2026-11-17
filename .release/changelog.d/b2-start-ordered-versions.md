- Backblaze B2 orders a key's versions by when their upload started, not when it finished (measured live on
  2026-11-16; spec 06 §4, A4 false). One writer per `version_log` bucket is safe under that order: a manifest root PUT
  whose reply was lost and that the provider completed after the retry won used to land below the recorded root and
  refuse the vault (`order_violation`); it is now recognised as this server's own superseded attempt and deleted
  (vl-vaultfmt 0.4.0, `windowIntruders`). For 15 minutes after a failed root PUT a pass lists the root's versions
  instead of one HEAD, so such a root is removed before a restore could take it.
- Several writers on a `version_log` bucket are refused: `vh vault join` (by kit and `--from-cloud`) refuses
  `join_version_log` when the root or the binding's probe says `version_log`, and the library refuses any root naming
  more than one writer there (`WritersRefused`, before any PUT). Replicated vaults need a bucket with conditional PUT
  (AWS S3, Cloudflare R2).
- The manifest root PUT has a deadline of 60 s for the whole request (`storage::s3::kManifestRootPutDeadline`), and
  every buffer PUT a 30 s connect bound and a stall bound (below 1 byte/s for 60 s); before, a stalled provider could
  hold a sync pass forever. Past either, curl closes the connection and the publish treats the outcome as unknown.
- vl-vaultfmt 0.4.0 (the wrap and its committed tarball): the above, the engine's `join` refused on `version_log`
  (status 632 `writers_refused`), and test doubles that model Backblaze's order.
