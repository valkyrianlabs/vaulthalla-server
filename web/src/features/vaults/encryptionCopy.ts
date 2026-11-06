// What the console says about upstream encryption (#364). The wording is fixed by
// design/encryption/05-claims-and-custody.md §6 and checked by tools/contracts/encryption_claims.py: every upstream-
// encrypted vault is `path_v0` today, so its object names are the vault's paths and the provider can read them.
export const UPSTREAM_ENCRYPTION_ON =
  'File contents are encrypted before upload. File and folder names are visible to your storage provider.'
export const UPSTREAM_ENCRYPTION_OFF = 'Objects are stored in the bucket as plain files, readable by anyone with access to it.'
