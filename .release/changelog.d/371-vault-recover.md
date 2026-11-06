- `vh vault recover` and ws `vault.recover` (#371, WS3-c; design/encryption/03 §6.4): rebuild an `opaque_v1` vault on any
  instance from its bucket plus a recovery kit and/or a key export. D1 trust anchor: a key version is canonical only
  when its original node's attestation verifies against an attestation key pinned in the customer's material (never
  the restoring node's own); otherwise `salvage_required`, and `--salvage` (typed confirmation `vault_recover_salvage`)
  re-encrypts under a fresh key above every version the bucket names without storing the supplied keys. `--dry-run`
  writes nothing. Restored vaults start in the cache strategy: only manifest objects, envelopes and 120-byte headers
  are read until a file is. Paired devices need the keys step-up; browser sessions get `recover_requires_device`;
  excluded from MCP. Audit event `vault.recover`.
- Migration 131 `vault_key_origin`: where a recovered key version was minted and the original attestation; reported by
  `vault.keys.status` (`needed_versions[].origin`) and carried in the manifest root (`keys[].origin`). Root grants carry
  their public key (`recovery_policy.grants[].public_key`), so a restore re-enrolls them.
- New encrypting S3 vaults are created `opaque_v1` (the internal staging is lifted: the restore drill passes). Existing
  `path_v0` vaults are unchanged until the layout migration (WS1-c).
- Key exports carry `node_id` and `vault_uid`. Key rotation and salvage record the object they PUT in the remote index,
  so the `opaque_v1` manifest names the object the bucket holds after a rotation.
- Harness: `vhh drill recover` (spec 03 §7: three private instances with their own databases and swtpm, a fake S3 with
  versioning and a request log, negative drills) and `tools/harness/drill_recover_r2.sh` (live R2, fixed test bucket
  `vh-test-recover-drill`, deleted afterwards).
