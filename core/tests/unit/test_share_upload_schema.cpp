// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// Deleting a folder that once received a share-link upload failed with a raw foreign key violation:
// share_upload.target_parent_entry_id was NOT NULL REFERENCES fs_entry with no delete action. Migration 101 makes it
// nullable and ON DELETE SET NULL, so upload history outlives the folder. DB-backed (VH_TEST_DB_*).

#include <gtest/gtest.h>
#include <pqxx/pqxx>

#include <cstdlib>
#include <optional>
#include <string>

namespace vh::test_share_upload_schema {

std::optional<std::string> env(const char* key) {
    if (const auto* v = std::getenv(key); v && *v) return std::string(v);
    return std::nullopt;
}

std::optional<std::string> connectionString() {
    const auto user = env("VH_TEST_DB_USER");
    const auto pass = env("VH_TEST_DB_PASS");
    const auto host = env("VH_TEST_DB_HOST");
    const auto port = env("VH_TEST_DB_PORT");
    const auto name = env("VH_TEST_DB_NAME");
    if (!user || !pass || !host || !port || !name) return std::nullopt;
    return "user=" + *user + " password=" + *pass + " host=" + *host + " port=" + *port + " dbname=" + *name;
}

TEST(ShareUploadSchema, DeletingTheTargetFolderKeepsUploadHistory) {
    const auto cs = connectionString();
    if (!cs) GTEST_SKIP() << "VH_TEST_DB_* not set";
    pqxx::connection conn(*cs);
    pqxx::read_transaction txn(conn);

    const auto nullable = txn.query_value<std::string>(
        "SELECT is_nullable FROM information_schema.columns "
        "WHERE table_schema = current_schema() AND table_name = 'share_upload' AND column_name = 'target_parent_entry_id'");
    EXPECT_EQ(nullable, "YES");

    const auto actions = txn.exec(
        "SELECT c.confdeltype FROM pg_constraint c "
        "JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1] "
        "WHERE c.contype = 'f' AND c.conrelid = 'share_upload'::regclass AND c.confrelid = 'fs_entry'::regclass "
        "AND cardinality(c.conkey) = 1 AND a.attname = 'target_parent_entry_id'");
    ASSERT_EQ(actions.size(), 1u) << "exactly one foreign key on share_upload.target_parent_entry_id";
    EXPECT_EQ(actions[0][0].as<std::string>(), "n") << "ON DELETE SET NULL";
}

}  // namespace vh::test_share_upload_schema
