-- Permanent ids for every folder and symlink, and the groundwork for remote accounts (server mirror phase 1b;
-- design/peers/identity.md "How an account is named across servers", "Remote accounts"; design/peers/mirror.md
-- "Permanent ids for every entry").
--
--   directories.uid,              (125, 145) assigned at insert for every vault type from now on, no longer by the
--   symlinks.uid,                 manifest collector the first time it lists the entry; 16 raw bytes from libsodium,
--   recovery_snapshot.uid         as before. The id two servers use to name the same folder, symlink and snapshot.
--   files_trashed.object_uid      (125) filled in where no bucket object is named by it (below); still nullable.
--   users/groups.home_node,       a remote account names a person or group of a linked server for attribution only
--   users/groups.home_id          (an owner, "last modified by", an audit line): by its home server's node id and its
--   users/groups.remote           integer id there, both set on a remote row and both NULL on a local one, unique per
--                                 home server. Local integer ids are unchanged and nothing is assigned to existing
--                                 accounts. A remote account has no password hash, no linux uid or gid, no credentials
--                                 of any kind, no admin role and no global vault policy, and no authentication path
--                                 accepts it (identities::UserState::authorizing, and the triggers below). A local
--                                 account never becomes remote. Nothing creates remote accounts yet.
--   users.name, users.email,      unique among local accounts only: a remote account may share a name with a local
--   groups.name                   one. `ON CONFLICT (name)` on these tables now reads `ON CONFLICT (name) WHERE NOT
--                                 remote`.
--
-- The deployer's data step for this file (seed/SqlDeployer, kMigrationDataSteps: assignPermanentIds) gives every
-- folder, symlink and snapshot without a uid one in the same transaction, never changing one that is set (their
-- triggers ignore the assignment: it is no file change). 159_permanent_ids_required.sql then checks that nothing was
-- missed and makes the columns NOT NULL.
--
-- Trashed files: a trash row made before 125 (or by the S3 gateway's delete of an object it never held as a file) has
-- no object uid. On a vault that is not opaque_v1 the bucket names objects by path, so the row gets a fresh uid. On an
-- opaque_v1 vault the bucket names the trashed object o/<uid> by a uid this database no longer holds: inventing one
-- would name an object that does not exist, so such a row keeps NULL, the manifest leaves it out as it always has,
-- and restore and purge still find it by its path.
--
-- Idempotent and safe on upgraded installs: new columns, indexes, constraints and triggers only; nothing is dropped
-- but the three whole-table uniqueness constraints (users.name, users.email, groups.name), replaced by the
-- local-account indexes first.

-- ---------------------------------------------------------------------------------------------------- columns

ALTER TABLE users ADD COLUMN IF NOT EXISTS home_node TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS home_id INTEGER;
ALTER TABLE users ADD COLUMN IF NOT EXISTS remote BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS home_node TEXT;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS home_id INTEGER;
ALTER TABLE groups ADD COLUMN IF NOT EXISTS remote BOOLEAN NOT NULL DEFAULT FALSE;

-- One row per account of a home server.
CREATE UNIQUE INDEX IF NOT EXISTS users_remote_home_key ON users (home_node, home_id) WHERE remote;
CREATE UNIQUE INDEX IF NOT EXISTS groups_remote_home_key ON groups (home_node, home_id) WHERE remote;

-- ---------------------------------------------------------------------------------------------------- names

-- Local accounts keep unique names (and emails); a remote account may share one. The new indexes go in first, so the
-- names are never unconstrained, then the old whole-table constraints go, found by their column, not their name.
CREATE UNIQUE INDEX IF NOT EXISTS users_local_name_key ON users (name) WHERE NOT remote;
CREATE UNIQUE INDEX IF NOT EXISTS users_local_email_key ON users (email) WHERE NOT remote;
CREATE UNIQUE INDEX IF NOT EXISTS groups_local_name_key ON groups (name) WHERE NOT remote;

DO $$
DECLARE
    c RECORD;
BEGIN
    FOR c IN
        SELECT con.conname, rel.relname
        FROM pg_constraint con
        JOIN pg_class rel ON rel.oid = con.conrelid
        JOIN pg_attribute att ON att.attrelid = con.conrelid AND att.attnum = con.conkey[1]
        WHERE con.contype = 'u'
          AND rel.relnamespace = current_schema()::regnamespace
          AND cardinality(con.conkey) = 1
          AND ((rel.relname = 'users' AND att.attname IN ('name', 'email')) OR
               (rel.relname = 'groups' AND att.attname = 'name'))
    LOOP
        EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', c.relname, c.conname);
    END LOOP;
END $$;

-- ---------------------------------------------------------------------------------------------------- remote accounts

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'users'::regclass AND conname = 'users_remote_check') THEN
        ALTER TABLE users ADD CONSTRAINT users_remote_check
            CHECK ((home_node IS NULL OR length(home_node) > 0) AND
                   (remote = (home_node IS NOT NULL)) AND (remote = (home_id IS NOT NULL)) AND
                   (NOT remote OR (password_hash = '' AND linux_uid IS NULL AND NOT protected AND NOT system_only)));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = 'groups'::regclass AND conname = 'groups_remote_check') THEN
        ALTER TABLE groups ADD CONSTRAINT groups_remote_check
            CHECK ((home_node IS NULL OR length(home_node) > 0) AND
                   (remote = (home_node IS NOT NULL)) AND (remote = (home_id IS NOT NULL)) AND
                   (NOT remote OR linux_gid IS NULL));
    END IF;
END $$;

-- A local account never becomes remote: it would keep the credentials, roles and policies a remote account cannot
-- hold. (A remote account becoming local is the deployment join's to do, later.)
CREATE OR REPLACE FUNCTION vh_remote_account_guard() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.remote AND NOT OLD.remote THEN
        RAISE EXCEPTION '%: a local account cannot become remote', TG_TABLE_NAME USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS vh_remote_account_guard ON users;
CREATE TRIGGER vh_remote_account_guard BEFORE UPDATE OF remote ON users FOR EACH ROW
    EXECUTE FUNCTION vh_remote_account_guard();
DROP TRIGGER IF EXISTS vh_remote_account_guard ON groups;
CREATE TRIGGER vh_remote_account_guard BEFORE UPDATE OF remote ON groups FOR EACH ROW
    EXECUTE FUNCTION vh_remote_account_guard();

-- Rows that would let an account authenticate or hold server-wide authority never name a remote account: sessions,
-- passkeys, TOTP and recovery codes, paired devices, S3 gateway keys, connector grants, key-backup grants, an admin
-- role, a global vault policy. TG_ARGV names the user columns of the table.
CREATE OR REPLACE FUNCTION vh_refuse_remote_account() RETURNS TRIGGER AS $$
DECLARE
    col     TEXT;
    account INTEGER;
BEGIN
    FOREACH col IN ARRAY TG_ARGV
    LOOP
        account := (to_jsonb(NEW) ->> col)::integer;
        IF account IS NOT NULL AND EXISTS (SELECT 1 FROM users WHERE id = account AND remote) THEN
            RAISE EXCEPTION '%: user % is a remote account, which holds no credentials, admin role or global vault policy',
                TG_TABLE_NAME, account USING ERRCODE = 'check_violation';
        END IF;
    END LOOP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['refresh_tokens', 'webauthn_credentials', 'totp_factors', 'recovery_code_batches',
                             'recovery_codes', 'devices', 'connector_grants', 'key_backup_grants',
                             'admin_role_assignments', 'user_global_vault_policy']
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS vh_refuse_remote_account ON %I', t);
        EXECUTE format('CREATE TRIGGER vh_refuse_remote_account BEFORE INSERT OR UPDATE OF user_id ON %I '
                       'FOR EACH ROW EXECUTE FUNCTION vh_refuse_remote_account(''user_id'')', t);
    END LOOP;
END $$;

DROP TRIGGER IF EXISTS vh_refuse_remote_account ON s3_gateway_credentials;
CREATE TRIGGER vh_refuse_remote_account BEFORE INSERT OR UPDATE OF user_id, principal_user_id ON s3_gateway_credentials
    FOR EACH ROW EXECUTE FUNCTION vh_refuse_remote_account('user_id', 'principal_user_id');
