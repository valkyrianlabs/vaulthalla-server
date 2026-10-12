// vh_migrate: applies deploy/psql to one test database with the daemon's own SqlDeployer, exactly as startup would.
// Builds the migrated template that per-run test databases are cloned from (bin/tests/lib/itest.sh,
// tools/harness/vhh/instance.py), so a clone's schema_migrations match what the daemon expects and nothing re-runs.
//
//   VH_TEST_DB_{USER,PASS,HOST,PORT,NAME} from the environment (all required), the database must be a test database
//   (runtime/TestInstance: vh_harness_* or a name containing "test").
//   vh_migrate <dir with *.sql>
#include "runtime/TestInstance.hpp"
#include "seed/include/SqlDeployer.hpp"

#include <pqxx/pqxx>

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string>
#include <utility>
#include <vector>

int main(const int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: vh_migrate <migrations dir>\n");
        return 2;
    }
    std::vector<std::pair<std::string, std::string>> params;
    for (const auto& [key, param] : {std::pair{"VH_TEST_DB_USER", "user"}, std::pair{"VH_TEST_DB_PASS", "password"},
                                     std::pair{"VH_TEST_DB_HOST", "host"}, std::pair{"VH_TEST_DB_PORT", "port"},
                                     std::pair{"VH_TEST_DB_NAME", "dbname"}}) {
        const char* v = std::getenv(key);
        if (!v || !*v) {
            std::fprintf(stderr, "vh_migrate: %s is not set\n", key);
            return 78;
        }
        params.emplace_back(param, v);
    }
    if (!vh::runtime::test_instance::isTestDatabaseName(std::getenv("VH_TEST_DB_NAME"))) {
        std::fprintf(stderr, "vh_migrate: refusing a database that is not a test database\n");
        return 78;
    }
    try {
        pqxx::connection conn(params);
        {
            // The daemon's session setup (db/Connection.cpp configureSession): remember the original zone, run in UTC.
            pqxx::nontransaction tx(conn);
            tx.exec("SELECT set_config('vaulthalla.database_timezone', current_setting('TimeZone'), false), "
                    "set_config('TimeZone', 'UTC', false)");
        }
        pqxx::work txn(conn);
        vh::db::seed::SqlDeployer::ensureMigrationsTable(txn);
        const auto report = vh::db::seed::SqlDeployer::applyDir(txn, argv[1]);
        txn.commit();
        std::printf("vh_migrate: %zu migration(s) applied\n", report.applied.size());
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "vh_migrate: %s\n", e.what());
        return 1;
    }
}
