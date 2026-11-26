-- A linked server's vault role (server mirror phase 2, wave 2; design/peers/identity.md "Decided and given", Cooper
-- 2026-11-25): the mirror's permissions are a role held by the mirror server, a ceiling on everything that arrives
-- from it. Roles are never matched or shared by id between servers: the core tells the mirror the role it has, by
-- name and with its actual permissions, and the mirror stores what it was told. Nothing sends or enforces it yet
-- (rbac::resolver::PeerVault is the question the next waves ask; rbac::mirrored the mirror's rule).
--
-- On the core (the server where a mirrored vault's changes commit):
--
--   vault_role_assignments.subject_type gains 'peer': the subject is a row of `peer`, and the assignment is that
--                         linked server's role on that one vault. It overrides the link's default, including "no
--                         access" (an assignment of the built-in role implicit_deny, which grants nothing whatever its
--                         bits say). A peer assignment takes no path override, and only names an existing peer row.
--   peer_vault_policy     the link's default: the vault role a linked server holds on every vault mirrored over that
--                         link (none: NULL role, or no row), who set it and when. A role in use here can't be deleted.
--
-- On the mirror (a server holding another server's vault): mirror_vault gains what the core granted this server for
-- that vault, as it was told: the role's name, its permissions (the bit layout of vault_role), the granting server's
-- node id and when. All of them or none, and never on a vault this server is the core of. Only db::query::mirror
-- writes them (tools/contracts/test_replication_log_contract.py).
--
-- Additive and idempotent: existing assignments are untouched (they are users' and groups'), new columns are NULL, a
-- second run changes nothing.

-- ---------------------------------------------------------------------------------------------- the peer subject

-- 060's inline CHECK (subject_type IN ('user', 'group')) is replaced, whatever it was named, once.
DO $$
DECLARE
    c RECORD;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'vault_role_assignments'::regclass AND contype = 'c'
                     AND conname = 'vault_role_assignments_subject_type_check'
                     AND pg_get_constraintdef(oid) LIKE '%''peer''%') THEN
        FOR c IN SELECT conname FROM pg_constraint
                 WHERE conrelid = 'vault_role_assignments'::regclass AND contype = 'c'
                   AND pg_get_constraintdef(oid) LIKE '%subject_type%'
        LOOP
            EXECUTE format('ALTER TABLE vault_role_assignments DROP CONSTRAINT %I', c.conname);
        END LOOP;
        ALTER TABLE vault_role_assignments ADD CONSTRAINT vault_role_assignments_subject_type_check
            CHECK (subject_type IN ('user', 'group', 'peer'));
    END IF;
END $$;

-- A peer assignment names a linked server's row (a revoked one too: unlinking keeps the row, and its assignments
-- grant nothing while it is revoked). No foreign key: subject_id is a user's, a group's or a peer's.
CREATE OR REPLACE FUNCTION vh_peer_vault_assignment_check() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.subject_type = 'peer' AND NOT EXISTS (SELECT 1 FROM peer WHERE id = NEW.subject_id) THEN
        RAISE EXCEPTION 'vault_role_assignments: peer % is not a linked server here', NEW.subject_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS vh_peer_vault_assignment_check ON vault_role_assignments;
CREATE TRIGGER vh_peer_vault_assignment_check BEFORE INSERT OR UPDATE OF subject_type, subject_id
    ON vault_role_assignments FOR EACH ROW EXECUTE FUNCTION vh_peer_vault_assignment_check();

-- Path overrides are for people: a linked server's role is whole (design/peers/identity.md; out of scope).
CREATE OR REPLACE FUNCTION vh_peer_vault_override_check() RETURNS TRIGGER AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM vault_role_assignments WHERE id = NEW.assignment_id AND subject_type = 'peer') THEN
        RAISE EXCEPTION 'vault_permission_overrides: assignment % is a linked server''s, which takes no path override',
            NEW.assignment_id USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS vh_peer_vault_override_check ON vault_permission_overrides;
CREATE TRIGGER vh_peer_vault_override_check BEFORE INSERT OR UPDATE OF assignment_id
    ON vault_permission_overrides FOR EACH ROW EXECUTE FUNCTION vh_peer_vault_override_check();

-- ---------------------------------------------------------------------------------------------- the link's default

CREATE TABLE IF NOT EXISTS peer_vault_policy
(
    peer_id INTEGER PRIMARY KEY REFERENCES peer (id) ON DELETE CASCADE,
    role_id INTEGER REFERENCES vault_role (id) ON DELETE RESTRICT,   -- NULL: no default role
    set_by  INTEGER REFERENCES users (id) ON DELETE SET NULL,
    set_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_peer_vault_policy_role ON peer_vault_policy (role_id);

-- Set by a person signed in here: never by a remote account (migration 158's rule for every row naming an account
-- that acts).
DROP TRIGGER IF EXISTS vh_refuse_remote_account ON peer_vault_policy;
CREATE TRIGGER vh_refuse_remote_account BEFORE INSERT OR UPDATE OF set_by ON peer_vault_policy
    FOR EACH ROW EXECUTE FUNCTION vh_refuse_remote_account('set_by');

-- ---------------------------------------------------------------------------------------------- the mirror's grant

ALTER TABLE mirror_vault
    ADD COLUMN IF NOT EXISTS granted_role_name               TEXT,
    ADD COLUMN IF NOT EXISTS granted_files_permissions       BIT(32),
    ADD COLUMN IF NOT EXISTS granted_directories_permissions BIT(32),
    ADD COLUMN IF NOT EXISTS granted_sync_permissions        BIT(32),
    ADD COLUMN IF NOT EXISTS granted_roles_permissions       BIT(16),
    ADD COLUMN IF NOT EXISTS granted_by_node                 TEXT,
    ADD COLUMN IF NOT EXISTS granted_at                      TIMESTAMPTZ;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid = 'mirror_vault'::regclass AND conname = 'mirror_vault_grant_check') THEN
        ALTER TABLE mirror_vault ADD CONSTRAINT mirror_vault_grant_check CHECK (
            (granted_role_name IS NULL AND granted_files_permissions IS NULL AND granted_directories_permissions IS NULL
             AND granted_sync_permissions IS NULL AND granted_roles_permissions IS NULL AND granted_by_node IS NULL
             AND granted_at IS NULL)
            OR (role <> 'core'
                AND char_length(granted_role_name) BETWEEN 1 AND 50
                AND granted_files_permissions IS NOT NULL AND granted_directories_permissions IS NOT NULL
                AND granted_sync_permissions IS NOT NULL AND granted_roles_permissions IS NOT NULL
                AND char_length(granted_by_node) BETWEEN 1 AND 64
                AND granted_at IS NOT NULL));
    END IF;
END $$;
