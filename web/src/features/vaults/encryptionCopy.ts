// What the console says about upstream encryption (#364, #371). The wording is fixed by
// design/encryption/05-claims-and-custody.md §6 and checked by tools/contracts/encryption_claims.py. A new vault that
// encrypts upstream is `opaque_v1` (#371): its objects are named by random ids. An existing vault that turns
// encryption on (and every encrypting vault from before #371) is `path_v0` until the layout migration (WS1-c): its
// object names are the vault's paths and the provider can read them.
export const UPSTREAM_ENCRYPTION_NEW =
  "Your storage provider only ever sees encrypted, opaquely named objects. It can't see your file names, folders or " +
  'contents. It can see how many objects you store, their sizes and when they change.'
export const UPSTREAM_ENCRYPTION_ON =
  'File contents are encrypted before upload. File and folder names are visible to your storage provider.'
export const UPSTREAM_ENCRYPTION_OFF = 'Objects are stored in the bucket as plain files, readable by anyone with access to it.'
