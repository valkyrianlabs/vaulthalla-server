-- Key-backup grants (#362, MFA design note docs/dev/mfa-design.md sections 6.4 and 9; decisions D1 and D4).
--
-- Vaulthalla Desktop backs up every needed version of each vault key to 1Password in the background. A key-backup
-- grant is the narrow, device-bound authority that lets it do so without a person's approval each time: one paired
-- device, one user, the vaults it names and nothing else. Anything outside it (another vault, a suspended or revoked
-- grant, another session) needs the `keys` step-up for that one export.
--
--   key_backup_grants        one row per grant. At most one live (unrevoked) grant per device. origin 'approved'
--                            (made by device.backup.grant.create, or confirmed) or 'migrated' (below); approved_via
--                            names how the person approved it (a passkey or password+TOTP in the console, the device's
--                            approval key, a console approval of the device's request). suspended_at: the export cap
--                            (60 vault exports an hour) tripped; confirming the grant again lifts it. revoked_at and
--                            revoked_reason are final: a new grant is a new row.
--   key_backup_grant_vaults  the vaults a grant names. No foreign key to vault on purpose (like vault_deletion): a
--                            deleted vault's key stays exportable while it is retained, and vault ids are never reused.
--   key_backup_grant_migration
--                            D1's snapshot: the devices that were live when this migration ran. The daemon turns each
--                            into an origin 'migrated' grant at its next start (device::backup::migratePending), over
--                            exactly the vaults the device's user may export then, when that user holds the
--                            encryption-key Export permission, with one keys.backup.grant.migrate audit event per
--                            grant; then it removes the row. Permissions are the daemon's to evaluate, not SQL's. The
--                            snapshot is taken only when the table is created, so re-running this file never adds a
--                            device paired later.
--
-- Additive and idempotent: new tables only, safe on upgraded installs. No existing row changes.

CREATE TABLE IF NOT EXISTS key_backup_grants
(
    id             SERIAL PRIMARY KEY,
    device_id      INTEGER     NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    user_id        INTEGER     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    origin         TEXT        NOT NULL CHECK (origin IN ('approved', 'migrated')),
    approved_via   TEXT CHECK (approved_via IN ('webauthn', 'password_totp', 'device_approval', 'console_approval')),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    confirmed_at   TIMESTAMPTZ,
    last_used_at   TIMESTAMPTZ,
    suspended_at   TIMESTAMPTZ,
    revoked_at     TIMESTAMPTZ,
    revoked_reason TEXT CHECK (revoked_reason IS NULL OR revoked_reason IN
                               ('manual', 'device_revoked', 'user_inactive', 'export_permission', 'recovery_code',
                                'admin_reset', 'cli_reset', 'device_idle')),
    CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_key_backup_grant_live ON key_backup_grants (device_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_key_backup_grants_user ON key_backup_grants (user_id);

CREATE TABLE IF NOT EXISTS key_backup_grant_vaults
(
    grant_id INTEGER NOT NULL REFERENCES key_backup_grants (id) ON DELETE CASCADE,
    vault_id INTEGER NOT NULL CHECK (vault_id > 0),
    PRIMARY KEY (grant_id, vault_id)
);

DO
$$
    BEGIN
        IF to_regclass('public.key_backup_grant_migration') IS NULL THEN
            CREATE TABLE key_backup_grant_migration
            (
                device_id   INTEGER PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
                snapshot_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            INSERT INTO key_backup_grant_migration (device_id)
            SELECT id FROM devices WHERE revoked_at IS NULL;
        END IF;
    END
$$;
