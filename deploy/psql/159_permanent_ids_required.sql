-- Every folder, symlink and snapshot has its permanent id (server mirror phase 1b). 158_permanent_ids.sql's deployer
-- data step (seed/SqlDeployer, kMigrationDataSteps: assignPermanentIds) gave one to every existing row in this same
-- transaction. This file checks that nothing was missed before tightening anything, then makes the columns NOT NULL.
-- Two files, because the backfill has to run between them, as for vault.uid and files.object_uid (122/123).
--
-- From here on every insert names its uid: libsodium, in the code that inserts the row (db::query::fs::Directory,
-- ::Symlink, db::query::recovery::Snapshot, the manifest applier, vault restore). files_trashed.object_uid stays
-- nullable (158).
--
-- Idempotent: the check finds nothing on a second run, and SET NOT NULL on a NOT NULL column is a no-op.

DO $$
DECLARE
    t       TEXT;
    missing BIGINT;
BEGIN
    FOREACH t IN ARRAY ARRAY['directories', 'symlinks', 'recovery_snapshot']
    LOOP
        EXECUTE format('SELECT count(*) FROM %I WHERE uid IS NULL', t) INTO missing;
        IF missing > 0 THEN
            RAISE EXCEPTION '%: % row(s) have no uid after the backfill (158_permanent_ids.sql data step)', t, missing;
        END IF;
    END LOOP;
END $$;

ALTER TABLE directories ALTER COLUMN uid SET NOT NULL;
ALTER TABLE symlinks ALTER COLUMN uid SET NOT NULL;
ALTER TABLE recovery_snapshot ALTER COLUMN uid SET NOT NULL;
