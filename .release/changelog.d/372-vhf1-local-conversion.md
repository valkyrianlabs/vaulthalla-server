- Local format conversion to VHF1 (#372, WS2-c; design/encryption/02 §6.1, §6.2): `vault::conversion`
  (`vault/FormatConversion.hpp`) re-seals legacy (gcm0) live backing files and `.vh-recovery` blobs as VHF1 under the
  same key version, verified per item (legacy tag over the whole input, plaintext BLAKE2b while streaming, full VHF1
  chunk walk bound to vault/salt/key version/object, matching digest and recorded size) before anything is replaced.
  Live files use the rotation sidecar protocol under the content lock (sidecar → one transaction: files CAS + the
  shared blob's row → rename → unlink the old blob); a blob of a live file's generation is linked to the converted
  sidecar and converts once. Other blobs: new store name → CAS of the `recovery_blob` row → unlink. Crash recovery is
  the existing startup sidecar recovery and store sweep. `content_hash` columns are kept, as rotation keeps them.
- `vault::FormatConversionService` (runtime service, after VaultRetentionService): passes every
  `vaults.format_conversion.pass_interval` over vaults with legacy rows, paced by `max_mib_per_second` and
  `max_cpu_percent` (pauses between items), blocked while the vault rotates its key or a salvage runs. Live files of
  encrypt-upstream cloud vaults are left to the layout migration (spec 01 §6); rows of plaintext-upstream vaults
  without local bytes get their stale legacy id cleared, as rotation does.
- `vh vault format status <vault|all> [--json]` (`ops::vault_format`, encryption-key View permission): remaining live
  files and blobs (items, bytes), state, last pass. `db::query::vault::FormatConversion` uses migration 126's
  `content_format` columns.
- Tests: `FormatMigrationTest.*` (DB-free: digests, crash at every step + restart, hard links once, no plaintext on disk,
  refusals, rotation/salvage, pacing), `FormatMigrationDbTest.*` (db-only: snapshots, local versions and retired-key
  generations restore after conversion; status; blocked during rotation).
