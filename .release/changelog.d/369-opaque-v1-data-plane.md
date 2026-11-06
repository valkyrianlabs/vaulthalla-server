- `opaque_v1` data plane (#369, WS1-b; design/encryption/01 §4, §5, §7): content objects are `o/<file uid>` (one
  object per file; provider versions are content versions) beside the `.vaulthalla/` manifest objects; key
  construction and parsing live in `storage/ObjectKeys.hpp`. Every request of an `opaque_v1` vault is held to spec 01
  §4.3 in one place, `s3::Controller::enforceRequestPolicy` (set by `CloudEngine` for the vault's layout), before it
  is sent or metered: keys only `o/<uid>` and `.vaulthalla/{layout.json,root,seg/<sid>,key/<kid>}`, listings only with
  the prefixes "", `o/`, `.vaulthalla/…` or one allowlisted key, no `x-amz-meta-*`, `Content-Type:
  application/octet-stream` only (multipart initiates send it too), no content headers or tags, no metadata rewrites,
  CopyObject onto its own key only (provider-version restore). Checksums stay the SigV4 payload hash of the bytes on
  the wire (ciphertext). Refusals throw `s3::OpaqueRequestRefused`.
- Sync is keyed by file uid under `opaque_v1`: both sides of a pass are keyed `/o/<uid>`, a remote row is bound to the
  file with that uid (so a rename or move is no difference and sends no object request; the encrypted manifest takes
  it at the next publish), the planner treats a row naming the file's generation as in sync, and remote objects no
  file names are left alone (trashed files' objects wait for the purge; orphans are counted and logged, never
  downloaded or deleted). A full listing has no prefix and sorts content, metadata and foreign keys; foreign objects
  are ignored and reported (`foreign_objects = ignore`, the default) or imported once as `/Imported/<key>` (`import`,
  `CloudEngine::importForeignObject`, the only request that names a foreign key, inside
  `s3::ScopedForeignObjectRead`). Events: foreign keys are never HEADed or indexed; an `o/<uid>` object no file of the
  vault has is an orphan.
- The remote index, provider versions (`upstream_object_version`, `file_versions.upstream_key`), write intents, the
  usage ledger and the backlog replay use `o/<uid>` keys. Uploads record the PUT's ETag and version id on the index
  row (and the upload baseline), which the manifest collector turns into the entry's object reference (sealed size,
  ETag, version id) and generation (`format: 1`, hex salt). Trash purges remove the index row by object key.
- Reads of `opaque_v1` objects are bound to the vault and the file's uid, mandatory (sync downloads, hydrate, ranged
  reads, conflict previews, provider restores, key salvage, local VHF1 reads): a row without a recorded generation
  learns it from the authenticated header. Hydrate is one GET (no metadata HEAD); `CloudEngine::requireOpaqueHeader`
  refuses to upload bytes whose header doesn't name the file. Copies re-seal under the copy's own uid and a new
  generation. Provider restores of `opaque_v1` versions take the generation from Vaulthalla's own write (or the
  header) and re-seal a transfer into the destination's uid; directory points and point-in-time plans place objects
  by the paths the database gives their uids.
- Manifest v2: a pass that changed nothing costs one HEAD of the root (`ObjectStore::headEtag`,
  `Service::verifyRemote`) and publishes nothing (`Service::publishIfChanged`); explicit publishes are unchanged.
- Multipart part size `max(5 MiB, ceil(size / 10,000))` rounded up to a whole MiB for every layout
  (`object_keys::partSizeFor`): objects up to 48.8 GiB keep 5 MiB parts, larger ones stay within 10,000 parts.
- `opaque_v1` creation stays refused outside test mode (#371 lifts it); `path_v0` and `transparent` vaults behave as
  before.
- Tests: `OpaqueObjectKeys.*`, `OpaqueRequestPolicy.*`, `OpaqueMultipart.ASixtyGiBObjectUploadsInAtMost10000Parts`
  (a sparse 60 GiB object), `OpaqueLayoutTest.*` (`OpaqueRequestAudit`, `OpaqueObjectCount`,
  `OpaqueRenameCostsNothing`, `OpaqueRequestCountsMatchSpec01Section5`, `OpaqueCopyReseals`,
  `OpaqueReadsRequireTheFilesObjectUid`, `OpaqueForeignObjectsAndOrphans`,
  `OpaqueManifestNamesTheObjectsItsFilesAreStoredIn`, `OpaqueCreationIsRefusedOutsideTestMode`) and
  `LiveR2.OpaqueObjectsCarryNoMetadataAndCostWhatSpec01Says`. The versioned fake bucket records every request
  (`VersionedBucket::requests()`) and runs the request policy like the network paths.
