- Groundwork for Vaulthalla Cloud, which isn't open yet: `vh cloud link|status|unlink` (super admins, CLI only,
  excluded from `vh mcp`) link a server to a vaulthalla.cloud account. Adds migration 134 (`cloud_link`), a sealed
  `cloud_identity` key, VHC1-Ed25519 request signing (`core/{include,src}/cloud/`) and a read-only `cloud.endpoint` in
  config.yaml (default `https://api.vaulthalla.cloud`; https, or http to localhost). Nothing contacts the cloud unless
  asked. Operator docs are held in `design/cloud/server-link.md` until the service opens.
- `vh cloud recovery enroll|status|unenroll` (Tier B, customer-key-controlled, approved 2026-11-10; spec 05 §3.2): a
  linked server sends a vault's existing KEV1 envelopes, byte for byte from its bucket, with key checks, attestations,
  attestation public keys and the checkpoint, to its vaulthalla.cloud account; explicit per vault, revocable, never a
  key. Migration 135 (`cloud_recovery_vault`); `vault/RecoveryEnvelopes.hpp`'s bucket-only rule names this exception.
- `vh vault recover --from-cloud --vault-uid <uid>`: a restore whose keys a device relays through the linked
  vaulthalla.cloud account to a temporary X25519 key held only in the daemon's memory (`ops::cloud_restore`); the
  delivered keys are proven and imported as a key export, unchanged rules (D1, the bucket's records).
