-- Identity revision and change log (identities::Manager).
--
-- The daemon keeps one canonical in-memory object per user and group and publishes new state into it whenever the
-- identity or authorization rows behind it change. Every change to those rows, from the daemon or from anywhere else
-- (psql by hand, a future second process), bumps one counter and logs which identities it touched:
--
--   identity_revision      one row; rev increases once per writing transaction. Writers take its row lock for the
--                          rest of their transaction, so rev order is commit order.
--   identity_change_log    (rev, entity, entity_id) per touched identity: 'user', 'group', 'admin_role' (a template;
--                          every user holding it), 'vault_role' (a template; every subject holding it).
--
-- The daemon reads rev in the same snapshot as the rows it loads, never publishes a state older than the one it
-- holds, and polls rev (plus LISTEN vh_identity) to reload what out-of-band writes touched. last_login,
-- password_hash, password_changed_at and updated_at do not count as identity changes: they never affect
-- authorization, and login would otherwise churn the log.
--
-- Idempotent: CREATE ... IF NOT EXISTS, CREATE OR REPLACE FUNCTION, triggers dropped and recreated.

CREATE TABLE IF NOT EXISTS identity_revision
(
    id  SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    rev BIGINT   NOT NULL DEFAULT 0
);

INSERT INTO identity_revision (id, rev) VALUES (1, 0) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS identity_change_log
(
    rev        BIGINT      NOT NULL,
    entity     VARCHAR(16) NOT NULL CHECK (entity IN ('user', 'group', 'admin_role', 'vault_role')),
    entity_id  INTEGER     NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_identity_change_log_rev ON identity_change_log (rev);

-- Bumps identity_revision once per transaction (the bumped value is remembered in a transaction-local setting) and
-- returns the transaction's revision.
CREATE OR REPLACE FUNCTION vh_identity_bump() RETURNS BIGINT AS $$
DECLARE
    txid_text TEXT := txid_current()::text;
    bumped    BIGINT;
BEGIN
    IF current_setting('vh.identity_txid', true) = txid_text THEN
        RETURN current_setting('vh.identity_rev')::bigint;
    END IF;
    UPDATE identity_revision SET rev = rev + 1 WHERE id = 1 RETURNING rev INTO bumped;
    IF bumped IS NULL THEN
        INSERT INTO identity_revision (id, rev) VALUES (1, 1)
        ON CONFLICT (id) DO UPDATE SET rev = identity_revision.rev + 1
        RETURNING rev INTO bumped;
    END IF;
    PERFORM set_config('vh.identity_txid', txid_text, true);
    PERFORM set_config('vh.identity_rev', bumped::text, true);
    PERFORM pg_notify('vh_identity', bumped::text);
    RETURN bumped;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION vh_identity_log(kind TEXT, ident INTEGER) RETURNS VOID AS $$
BEGIN
    IF ident IS NULL THEN
        RETURN;
    END IF;
    INSERT INTO identity_change_log (rev, entity, entity_id) VALUES (vh_identity_bump(), kind, ident);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION vh_identity_track() RETURNS TRIGGER AS $$
DECLARE
    rec RECORD;
BEGIN
    IF TG_TABLE_NAME = 'users' THEN
        IF TG_OP = 'UPDATE' AND
           (to_jsonb(OLD) - ARRAY['last_login', 'password_hash', 'password_changed_at', 'updated_at']) =
           (to_jsonb(NEW) - ARRAY['last_login', 'password_hash', 'password_changed_at', 'updated_at']) THEN
            RETURN NULL;
        END IF;
        IF TG_OP <> 'INSERT' THEN PERFORM vh_identity_log('user', OLD.id); END IF;
        IF TG_OP <> 'DELETE' THEN PERFORM vh_identity_log('user', NEW.id); END IF;
    ELSIF TG_TABLE_NAME = 'groups' THEN
        IF TG_OP = 'UPDATE' AND (to_jsonb(OLD) - 'updated_at') = (to_jsonb(NEW) - 'updated_at') THEN
            RETURN NULL;
        END IF;
        IF TG_OP <> 'INSERT' THEN PERFORM vh_identity_log('group', OLD.id); END IF;
        IF TG_OP <> 'DELETE' THEN PERFORM vh_identity_log('group', NEW.id); END IF;
    ELSIF TG_TABLE_NAME IN ('group_members', 'admin_role_assignments', 'user_global_vault_policy') THEN
        IF TG_OP <> 'INSERT' THEN PERFORM vh_identity_log('user', OLD.user_id); END IF;
        IF TG_OP <> 'DELETE' THEN PERFORM vh_identity_log('user', NEW.user_id); END IF;
    ELSIF TG_TABLE_NAME = 'vault_role_assignments' THEN
        IF TG_OP <> 'INSERT' AND OLD.subject_type IN ('user', 'group') THEN
            PERFORM vh_identity_log(OLD.subject_type, OLD.subject_id);
        END IF;
        IF TG_OP <> 'DELETE' AND NEW.subject_type IN ('user', 'group') THEN
            PERFORM vh_identity_log(NEW.subject_type, NEW.subject_id);
        END IF;
    ELSIF TG_TABLE_NAME = 'vault_permission_overrides' THEN
        -- A cascade from a deleted assignment finds no assignment row; that delete is logged by the assignment.
        FOR rec IN
            SELECT vra.subject_type, vra.subject_id
            FROM vault_role_assignments vra
            WHERE vra.id IN (CASE WHEN TG_OP <> 'INSERT' THEN OLD.assignment_id END,
                             CASE WHEN TG_OP <> 'DELETE' THEN NEW.assignment_id END)
              AND vra.subject_type IN ('user', 'group')
        LOOP
            PERFORM vh_identity_log(rec.subject_type, rec.subject_id);
        END LOOP;
    ELSIF TG_TABLE_NAME = 'admin_role' THEN
        IF TG_OP <> 'INSERT' THEN PERFORM vh_identity_log('admin_role', OLD.id); END IF;
        IF TG_OP = 'INSERT' THEN PERFORM vh_identity_log('admin_role', NEW.id); END IF;
    ELSIF TG_TABLE_NAME = 'vault_role' THEN
        IF TG_OP <> 'INSERT' THEN PERFORM vh_identity_log('vault_role', OLD.id); END IF;
        IF TG_OP = 'INSERT' THEN PERFORM vh_identity_log('vault_role', NEW.id); END IF;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['users', 'groups', 'group_members', 'admin_role_assignments', 'user_global_vault_policy',
                             'vault_role_assignments', 'vault_permission_overrides', 'admin_role', 'vault_role']
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS vh_identity_track ON %I', t);
        EXECUTE format('CREATE TRIGGER vh_identity_track AFTER INSERT OR UPDATE OR DELETE ON %I '
                       'FOR EACH ROW EXECUTE FUNCTION vh_identity_track()', t);
    END LOOP;
END $$;
