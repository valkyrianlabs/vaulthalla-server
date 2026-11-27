- Key rotation on a mirrored vault (mirror/rotate; design/peers/mirror.md "Key rotation"): prepare_key_rotation on a
  core delivers the new version first (peer.mirror.key: KEV1 to the peer wrap key, the core's key check and
  attestation; proven on the mirror against the pinned keys and held in vault_keys_trashed with its vault_key_origin)
  and refuses with mirror_not_live, mirror_link_down or mirror_key_refused otherwise; the applier makes a held version
  current when the log's key row names it with the same key check (mirror_key_mismatch otherwise) and reloads the
  engine's keys; a mirrored vault reads files under any retired version it holds. Salvage stays refused (vault_mirrored).
- A key rotation's per-file commit records the re-sealed bytes' BLAKE2b (files.content_hash) with the new generation
  (statement compare_and_set_file_encryption_iv_version_and_hash): before, the hash stayed the old generation's, which a
  mirror rightly refused when it fetched the re-sealed file. On a cloud vault the same transaction moves the sync
  baseline's hash (sync_file_baseline) and, when the rotation uploaded the new generation, the baseline's remote hash
  and the old generation's remote_object_index entry (by its IV), so a rotated file reads as unchanged on both sides
  instead of a two-sided change (OpaqueLayoutTest.OpaqueRequestAudit's provider restore after a rotation).
- Migration 170 replaces the change journal's files trigger (115) so that hash alone is no change: the rotation's
  statement sets vh.key_rotation for its transaction; a seal, overwrite or any other hash change is journaled as before.
