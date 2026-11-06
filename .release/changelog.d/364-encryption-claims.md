- Encryption claims per design/encryption/05 §6 (#364): `path_v0` wording ("File contents are encrypted before
  upload. File and folder names are visible to your storage provider.") in docs/vaults/encryption.md, README,
  docs index and stack.toml, and the console's upstream-encryption hints (`features/vaults/encryptionCopy.ts`:
  new vault, vault settings, S3 gateway remote bucket); the vault list no longer says "encrypted storage".
- New contract `tools/contracts/encryption_claims.py` (+ `test_encryption_claims_contract.py`): fails on disallowed
  claims in docs/, README.md and web/src ("zero-knowledge" or "end-to-end encrypted" outside sealed vaults,
  provider/operator-blind, "military-grade", "HIPAA compliant", bucket-only recovery, Vaulthalla Cloud
  Assisted/Custodial Recovery as available, custody tied to an account or payment) unless the claim carries an
  approved qualifier. Runs in CI through `tools/dev/verify.sh packaging`.
