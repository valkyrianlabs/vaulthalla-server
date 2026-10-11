#pragma once

#include "db/Transactions.hpp"
#include "identities/Manager.hpp"
#include "seed/include/SqlDeployer.hpp"
#include <paths.h>

namespace vh::db::seed {

inline void init_tables_if_not_exists() {
    Transactions::exec("init_db_tables::deploy_sql", [&](pqxx::work& txn) {
        SqlDeployer::ensureMigrationsTable(txn);
        SqlDeployer::applyDir(txn, paths::getPsqlSchemasPath());
    });
}


// ################################################################################################################
// ############################################## TESTING ONLY ####################################################
// ################################################################################################################

// Fast + safe for dev/test: empties every table in `public` and
// resets all owned sequences back to 1. Keeps schema, types, funcs, RLS, etc.
inline void wipe_all_data_restart_identity() {
    Transactions::exec("reset_db::wipe_all_data", [&](pqxx::work& txn) {
        txn.exec(R"(
DO $$
DECLARE
    _tables TEXT;
BEGIN
    -- Build a comma-separated list of fully-qualified base tables in `public`
    SELECT string_agg(format('%I.%I', schemaname, tablename), ', ')
      INTO _tables
      FROM pg_tables
     WHERE schemaname = 'public'
       AND tablename NOT LIKE 'pg_%'
       AND tablename NOT LIKE 'sql_%';

    IF _tables IS NOT NULL AND length(_tables) > 0 THEN
        -- TRUNCATE bypasses RLS; requires TRUNCATE privilege or ownership
        EXECUTE 'TRUNCATE TABLE ' || _tables || ' RESTART IDENTITY CASCADE';
    END IF;
END
$$;
        )");

        // (Optional belt-and-suspenders) Restart any sequences in `public`
        // that aren't "owned by" truncated columns.
        txn.exec(R"(
DO $$
DECLARE rec record;
BEGIN
  FOR rec IN
      SELECT sequence_schema, sequence_name
      FROM information_schema.sequences
      WHERE sequence_schema = 'public'
  LOOP
      EXECUTE format('ALTER SEQUENCE %I.%I RESTART WITH 1', rec.sequence_schema, rec.sequence_name);
  END LOOP;
END
$$;
        )");
    });

    identities::manager().reset();
}

// Hard reset: drop & recreate the entire `public` schema (tables, types,
// funcs, triggers, policies, indexes, everything), then rebuild schema.
inline void nuke_and_recreate_schema_public() {
    // Drop + recreate schema in its own transaction
    Transactions::exec("reset_db::nuke_and_recreate_schema_public", [&](pqxx::work& txn) {
        txn.exec(R"(
DO $$
BEGIN
    EXECUTE 'DROP SCHEMA IF EXISTS public CASCADE';
    EXECUTE 'CREATE SCHEMA public';
    -- Restore typical grants; adjust as needed for your DB roles
    EXECUTE 'GRANT USAGE, CREATE ON SCHEMA public TO PUBLIC';
END
$$;
        )");
    });

    // Recreate everything
    init_tables_if_not_exists();

    // Ids are reused by the new schema: forget every identity the previous one held.
    identities::manager().reset();
}

}
