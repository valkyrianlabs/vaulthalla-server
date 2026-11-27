- Key rotation on a mirrored vault (mirror/rotate; design/peers/mirror.md "Key rotation"): prepare_key_rotation on a
  core delivers the new version first (peer.mirror.key: KEV1 to the peer wrap key, the core's key check and
  attestation; proven on the mirror against the pinned keys and held in vault_keys_trashed with its vault_key_origin)
  and refuses with mirror_not_live, mirror_link_down or mirror_key_refused otherwise; the applier makes a held version
  current when the log's key row names it with the same key check (mirror_key_mismatch otherwise) and reloads the
  engine's keys; a mirrored vault reads files under any retired version it holds. Salvage stays refused (vault_mirrored).
