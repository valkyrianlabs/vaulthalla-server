-- MFA recovery effects on paired devices (#360; MFA design note docs/dev/mfa-design.md sections 6.4 and 7.4, D4).
--
-- A recovery-code sign-in, an admin MFA reset (auth.mfa.admin.reset) and `vh user mfa reset` revoke the account's
-- key-backup grants: the authority a paired Vaulthalla Desktop has to export vault keys without a step-up (its
-- automatic 1Password backup). Until the grant table lands (#362), every live paired device holds that authority
-- implicitly (D1: its user's existing export authority); this column records that it was revoked, and when.
--   key_backup_revoked_at      set once per revocation; the device keeps syncing (D4: a lost browser factor never
--                              breaks a legitimate Desktop) but a key export from it needs a person's approval again
--   key_backup_revoked_reason  recovery_code | admin_reset | cli_reset
-- #362's migration must carry it over: no 'migrated' grant for a device whose key backup was revoked.
--
-- Additive and idempotent: new nullable columns only, safe on upgraded installs.

ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS key_backup_revoked_at     TIMESTAMPTZ DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS key_backup_revoked_reason TEXT        DEFAULT NULL
        CHECK (key_backup_revoked_reason IS NULL OR key_backup_revoked_reason IN ('recovery_code', 'admin_reset', 'cli_reset'));
