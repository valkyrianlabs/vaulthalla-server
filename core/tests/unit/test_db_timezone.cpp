// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// #157: on a database whose TimeZone isn't UTC, naive `timestamp` columns stored local wall time that the daemon
// read back as UTC, so every time was off by the UTC offset. Daemon sessions are now forced to UTC (recording the
// zone they started in), and migration 100 converts naive columns to timestamptz, reading old values in that zone.
//
// DB-backed (VH_TEST_DB_*). Every scenario runs on its own connection with an explicit non-UTC session zone, and
// the migration scenarios run in a scratch schema inside a transaction that is rolled back.

#include "db/DBConnection.hpp"
#include "db/encoding/timestamp.hpp"
#include "seed/include/SqlDeployer.hpp"

#include <gtest/gtest.h>
#include <paths.h>
#include <pqxx/pqxx>

#include <chrono>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <unistd.h>

namespace vh::test_db_timezone {

std::optional<std::string> tzTestEnv(const char* key) {
    if (const auto* v = std::getenv(key); v && *v) return std::string(v);
    return std::nullopt;
}

// A plain libpq session that starts in America/Denver, like a daemon on an MST/MDT host.
std::optional<std::string> denverConnectionString() {
    const auto user = tzTestEnv("VH_TEST_DB_USER");
    const auto pass = tzTestEnv("VH_TEST_DB_PASS");
    const auto host = tzTestEnv("VH_TEST_DB_HOST");
    const auto port = tzTestEnv("VH_TEST_DB_PORT");
    const auto name = tzTestEnv("VH_TEST_DB_NAME");
    if (!user || !pass || !host || !port || !name) return std::nullopt;
    return "user=" + *user + " password=" + *pass + " host=" + *host + " port=" + *port + " dbname=" + *name +
           " options='-c TimeZone=America/Denver'";
}

std::string migrationSql() {
    return db::seed::readFileToString(std::filesystem::path(VH_PSQL_TEST_SCHEMAS_PATH) / "100_timestamptz.sql");
}

std::time_t epochOf(pqxx::work& txn, const std::string& expr) {
    return txn.exec("SELECT EXTRACT(EPOCH FROM " + expr + ")::bigint").one_field_ref().as<std::time_t>();
}

class DbTimezoneTest : public ::testing::Test {
protected:
    std::optional<std::string> conninfo = denverConnectionString();

    void SetUp() override {
        if (!conninfo) GTEST_SKIP() << "VH_TEST_DB_* not set";
    }
};

TEST_F(DbTimezoneTest, DaemonSessionsRunInUtcAndRememberTheDatabaseZone) {
    pqxx::connection conn(*conninfo);
    {
        pqxx::nontransaction tx(conn);
        ASSERT_EQ(tx.exec("SHOW TimeZone").one_field_ref().as<std::string>(), "America/Denver");
    }

    db::Connection::configureSession(conn);

    pqxx::work txn(conn);
    EXPECT_EQ(txn.exec("SHOW TimeZone").one_field_ref().as<std::string>(), "UTC");
    EXPECT_EQ(txn.exec("SELECT current_setting('vaulthalla.database_timezone')").one_field_ref().as<std::string>(),
              "America/Denver");

    // A naive column written with CURRENT_TIMESTAMP now holds UTC, which the daemon parses as UTC.
    txn.exec("CREATE TEMP TABLE tz_probe (naive TIMESTAMP DEFAULT CURRENT_TIMESTAMP, aware TIMESTAMPTZ DEFAULT now())");
    txn.exec("INSERT INTO tz_probe DEFAULT VALUES");
    const auto row = txn.exec("SELECT naive::text, aware::text FROM tz_probe").one_row();
    const auto now = std::time(nullptr);
    EXPECT_LE(std::llabs(db::encoding::parsePostgresTimestamp(row[0].as<std::string>()) - now), 5)
        << row[0].as<std::string>();
    EXPECT_LE(std::llabs(db::encoding::parsePostgresTimestamp(row[1].as<std::string>()) - now), 5)
        << row[1].as<std::string>();
    txn.abort();
}

TEST_F(DbTimezoneTest, TimestamptzWrittenInDenverReadsBackCorrectlyInTheDaemonSession) {
    pqxx::connection writer(*conninfo);  // stays in Denver: e.g. an operator's psql session
    pqxx::connection daemon(*conninfo);
    db::Connection::configureSession(daemon);

    {
        pqxx::work w(writer);
        w.exec("CREATE TABLE IF NOT EXISTS tz_probe_shared (id TEXT PRIMARY KEY, at TIMESTAMPTZ DEFAULT now())");
        w.exec("INSERT INTO tz_probe_shared (id) VALUES ('denver') ON CONFLICT (id) DO UPDATE SET at = now()");
        w.commit();
    }
    {
        pqxx::work r(daemon);
        const auto text = r.exec("SELECT at::text FROM tz_probe_shared WHERE id = 'denver'").one_field_ref().as<std::string>();
        EXPECT_TRUE(text.ends_with("+00")) << text;
        EXPECT_LE(std::llabs(db::encoding::parsePostgresTimestamp(text) - std::time(nullptr)), 5) << text;
        r.exec("DROP TABLE tz_probe_shared");
        r.commit();
    }
}

TEST_F(DbTimezoneTest, MigrationReadsNaiveValuesInTheRecordedZoneAndIsIdempotent) {
    pqxx::connection conn(*conninfo);
    db::Connection::configureSession(conn);  // session UTC, database zone recorded as America/Denver

    pqxx::work txn(conn);
    txn.exec("CREATE SCHEMA vh_tz_migration_test");
    txn.exec("SET LOCAL search_path = vh_tz_migration_test");
    txn.exec(R"(
        CREATE TABLE sample (
            id         SERIAL PRIMARY KEY,
            stamp      TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            viewed     TIMESTAMP,
            aware      TIMESTAMPTZ
        ))");
    txn.exec("CREATE INDEX sample_stamp_idx ON sample (stamp DESC)");
    txn.exec("CREATE VIEW sample_view AS SELECT viewed FROM sample");
    // Local Denver wall times as an MST/MDT host stored them: winter is UTC-7, summer UTC-6.
    txn.exec("INSERT INTO sample (stamp, viewed, aware) VALUES "
             "('2026-01-15 12:00:00', '2026-01-15 12:00:00', '2026-01-15 19:00:00+00'), "
             "('2026-07-15 12:00:00', NULL, NULL)");

    txn.exec(migrationSql());

    const auto typeOf = [&](const std::string& column) {
        return txn.exec("SELECT data_type FROM information_schema.columns WHERE table_schema = current_schema() "
                        "AND table_name = 'sample' AND column_name = $1", pqxx::params{column})
            .one_field_ref().as<std::string>();
    };
    EXPECT_EQ(typeOf("stamp"), "timestamp with time zone");
    EXPECT_EQ(typeOf("created_at"), "timestamp with time zone");
    EXPECT_EQ(typeOf("aware"), "timestamp with time zone");
    EXPECT_EQ(typeOf("viewed"), "timestamp without time zone") << "a column a view depends on is skipped";

    // 2026-01-15T19:00:00Z and 2026-07-15T18:00:00Z.
    EXPECT_EQ(epochOf(txn, "(SELECT stamp FROM sample WHERE id = 1)"), 1768503600);
    EXPECT_EQ(epochOf(txn, "(SELECT stamp FROM sample WHERE id = 2)"), 1784138400);
    EXPECT_EQ(epochOf(txn, "(SELECT aware FROM sample WHERE id = 1)"), 1768503600) << "timestamptz untouched";

    // The default and the index survive the type change.
    const auto defaultExpr = txn.exec(
        "SELECT pg_get_expr(d.adbin, d.adrelid) FROM pg_attrdef d JOIN pg_attribute a "
        "ON a.attrelid = d.adrelid AND a.attnum = d.adnum WHERE a.attrelid = 'sample'::regclass "
        "AND a.attname = 'created_at'").one_field_ref().as<std::string>();
    EXPECT_EQ(defaultExpr, "CURRENT_TIMESTAMP");
    EXPECT_FALSE(txn.exec("SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() "
                          "AND indexname = 'sample_stamp_idx'").empty());
    txn.exec("INSERT INTO sample (stamp) VALUES (now())");
    EXPECT_LE(std::llabs(epochOf(txn, "(SELECT created_at FROM sample WHERE id = 3)") - std::time(nullptr)), 5);

    // A second run changes nothing.
    txn.exec(migrationSql());
    EXPECT_EQ(epochOf(txn, "(SELECT stamp FROM sample WHERE id = 1)"), 1768503600);
    EXPECT_EQ(typeOf("viewed"), "timestamp without time zone");
    txn.abort();
}

// Found by the packaged 1.8.0 -> candidate upgrade: the daemon's UTC session recorded 099's schema_migrations row
// as UTC wall time, then 100 read it as Denver time (+7h). A fresh install shifted every row 000-099 wrote the same way.
TEST_F(DbTimezoneTest, RowsWrittenEarlierInTheSameDeployAreNotShifted) {
    pqxx::connection conn(*conninfo);
    db::Connection::configureSession(conn);

    const auto dir = std::filesystem::temp_directory_path() / ("vh_tz_deploy_" + std::to_string(::getpid()));
    std::filesystem::create_directories(dir);
    {
        std::ofstream(dir / "001_seed.sql") << "CREATE TABLE seeded (at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);\n"
                                               "INSERT INTO seeded DEFAULT VALUES;\n";
        std::ofstream(dir / "100_timestamptz.sql") << migrationSql();
    }

    pqxx::work txn(conn);
    txn.exec("CREATE SCHEMA vh_tz_migration_deploy");
    txn.exec("SET LOCAL search_path = vh_tz_migration_deploy");
    db::seed::SqlDeployer::ensureMigrationsTable(txn);
    const auto report = db::seed::SqlDeployer::applyDir(txn, dir);
    std::filesystem::remove_all(dir);
    ASSERT_EQ(report.applied.size(), 2u);

    const auto now = std::time(nullptr);
    EXPECT_LE(std::llabs(epochOf(txn, "(SELECT at FROM seeded)") - now), 5);
    EXPECT_LE(std::llabs(epochOf(txn, "(SELECT applied_at FROM schema_migrations WHERE filename = '001_seed.sql')") - now), 5);
    EXPECT_LE(std::llabs(epochOf(txn, "(SELECT applied_at FROM schema_migrations WHERE filename = '100_timestamptz.sql')") - now), 5);
    txn.abort();

    pqxx::nontransaction after(conn);
    EXPECT_EQ(after.exec("SHOW TimeZone").one_field_ref().as<std::string>(), "UTC") << "the deploy's zone is transaction-local";
}

TEST_F(DbTimezoneTest, MigrationFallsBackToTheSessionZoneWhenRunOutsideTheDaemon) {
    pqxx::connection conn(*conninfo);  // a manual psql-style run: Denver session, no recorded zone

    pqxx::work txn(conn);
    txn.exec("CREATE SCHEMA vh_tz_migration_manual");
    txn.exec("SET LOCAL search_path = vh_tz_migration_manual");
    txn.exec("CREATE TABLE sample (stamp TIMESTAMP NOT NULL)");
    txn.exec("INSERT INTO sample VALUES ('2026-01-15 12:00:00')");
    txn.exec(migrationSql());
    EXPECT_EQ(epochOf(txn, "(SELECT stamp FROM sample)"), 1768503600);
    txn.abort();
}

}
