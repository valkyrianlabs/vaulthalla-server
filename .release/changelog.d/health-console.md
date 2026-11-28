- Web console: the Health Overview lists findings from `health.findings.list` with their state, Acknowledge /
  Silence / Turn back on for `can_manage` accounts (lazy silence dialog: 1 h, 24 h, 7 d or until turned back on,
  note up to 500 bytes) and each `open` remedy as a link; a Silenced list covers silences whose class is not active.
  Change answers replace the cached findings and severity.
- Web console: the top bar health dot uses `unattended_error_count` / `unattended_warning_count`; the health pages
  keep the true severity and counts.
- Web console: health views and the top bar subscribe to `health.changed` (capability `health.push`), refetch on each
  event and stop polling `stats.dashboard.severity` and the findings while subscribed; they poll again without the
  capability, after a reconnect until resubscribed, or after `"subscribed": false`.
- ws contract generator: `WS_CONTRACT_TIMEOUTS` lists only commands whose timeout differs from the common one, which
  is emitted as `WS_CONTRACT_DEFAULT_TIMEOUT_MS`; the table is in every route's first load, so commands at the
  common timeout no longer grow it (`/login` 170.0 to 168.2 KB).
