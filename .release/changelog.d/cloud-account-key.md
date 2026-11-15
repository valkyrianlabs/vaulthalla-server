- Groundwork for Vaulthalla Cloud's account recovery key, which isn't open yet (design/cloud/key-manager.md, "As
  built"): `vh cloud link` sends link proof v2 with this server's node id and records the deployment and the account's
  public id (migration 141 adds `cloud_link.deployment_id`, `.account_public_id`). A linked server fetches the account
  key's statement chain and signed recovery policy, verifies them with vl-keykit 0.2.0 (now pinned), and pins the key
  only after a super admin confirms its fingerprint (`vh cloud key status|confirm|refresh|forget`; ws
  `cloud.key.status`, `.confirm`, `.refresh` and `cloud.link.status` behind the `cloud.account_key` capability).
  Pinned rows (`cloud_account_key`) carry an HMAC under the new sealed slot `cloud_account_pin`; signed rotations are
  followed, an unsigned replacement waits for a confirmation (health `cloud_account_key_change_pending`), a failing
  row stops every wrap (`cloud_account_key_tampered`). A daily `CloudKeyService` check runs only while linked.
- The pinned key as a recovery recipient: `vh vault keys recipient add <vault> --account-key`
  (`vault_recovery_grant.account_key_generation`) and `vh cloud recovery enroll <vault> --account-key`, by a person
  with today's permission, channels and step-up. The account's signed recovery policy keeps such vaults' other
  account-managed grants (`.account_policy_sequence`) equal to it; revoking one by hand is refused
  `recovery_policy_account_managed`. Local vaults can now be enrolled with the envelopes their database holds.
  `vh cloud key confirm` and `forget` are excluded from `vh mcp`.
