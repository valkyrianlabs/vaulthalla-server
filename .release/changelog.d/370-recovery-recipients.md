- Recovery recipients and KEV1 key envelopes (#370, WS3-b; design/encryption/03 §5): customer-held X25519 recipients
  per S3 vault; every held and future key version is wrapped (KEV1 suite 1, purpose 1, recipient class 0) to every
  usable grant and PUT to the vault's bucket as `.vaulthalla/key/<kid>` (`If-None-Match: *`). Rotations, the salvage
  key and a vault's first key write their envelopes before the version is committed (a failed PUT fails the rotation);
  enrollment wraps every held version; each sync pass writes what is missing. The manifest v2 root lists the grants
  (`recovery_policy`, revoked ones with `revoked_at`) and `keys[].envelopes`. The KEV1 reader rejects reserved
  purposes and recipient classes, which a restore skips.
- `vh vault keys recipient list|add|revoke` and ws `vault.keys.recipients.list|add|revoke` (add and revoke: CLI or a
  paired device only, `recipient_requires_device` elsewhere, agents denied and excluded from MCP; keys step-up bound
  to the vault, #359; encryption-key Export permission). Audit events `vault.recovery.recipient.add|revoke`.
- `vh vault keys import --recovery-kit <file|->` (read client-side): unwraps the vault's envelopes with the kit's seed
  and restores only versions the vault's records reference whose recorded (or manifest-root) attestation by this node
  verifies; planted keys that don't match the recorded key check are ignored; recover mode only. Audit event
  `vault.keys.import.recovery_kit`.
- New offline tool `vh-recovery` (`/usr/bin/vh-recovery`): `kit create|public-key|add-vault|show`. Kit format
  `vh.recovery-kit` v1.
- D2 (spec 03 §5.5): `vault.keys.status` gains `recovery` (`not_required|recipient|export|recovery_material_missing`,
  uncovered versions, `rotation_needed`), `vault_uid`, `node_id`, `attestation_public_keys` and `checkpoint`; health
  gains `vaults_recovery_material_missing` (degraded). Exports' attestations carry `public_key`; an import checks it
  against this node's key of that id.
- Migration 127: `vault_recovery_grant` (class constrained to `customer`, suite 1) and `vault_key_envelope`. Additive
  and idempotent.
- Tests: `Kev1Vectors`, `Kev1ReservedFields`, `RecoverySeedVectors`, `RecoveryKit`, `RecoveryRecipient.*`,
  `RecoveryRequirement.*`, `RecoveryNoSilentCustody.*`, `KeysImportFromKit.*`, `VaultKeyExportProvenance.*`,
  `recovery_tool`.
