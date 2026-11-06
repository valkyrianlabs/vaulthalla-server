- **Groundwork for provider-blind storage.** Every vault and every file now gets a permanent random identifier, and
  each S3/R2 vault records its storage layout. `vh vault info` shows both, and the vault details the API returns
  include the layout: encrypting vaults report `path (v0)` (encrypted objects under their file paths, as before) and
  the others `transparent`. The layout follows the vault's upstream encryption setting; there is nothing to choose.
  Nothing changes in your buckets: object names, contents and sync behave exactly as before. The upgrade assigns the
  identifiers to existing vaults and files once, in the same database transaction as the schema change.
