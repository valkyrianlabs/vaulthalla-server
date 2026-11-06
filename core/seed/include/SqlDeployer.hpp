#pragma once

#include <pqxx/pqxx>
#include <algorithm>
#include <array>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace vh::db::seed {

namespace fs = std::filesystem;

std::string readFileToString(const fs::path& p);

std::string sha256Hex(const std::string& s);

// Migration files that were edited in place AFTER being shipped in a released tag.
//
// SqlDeployer records sha256(raw file bytes) per migration in schema_migrations and refuses to start when the
// recorded hash differs from the file on disk. Every entry below is a hash that a released package really shipped
// (so a real database may have recorded it) for a file whose content later changed. When the recorded hash matches
// one of these, the deployer accepts it, does NOT re-execute the file, and rewrites the recorded hash to the current
// one. The schema delta introduced by each in-place edit is owned by a separate, idempotent forward migration
// (named per entry), so re-running the edited file is never needed.
//
// Rewriting the recorded hash (instead of leaving the historical one) keeps the check strict: once a database is
// reconciled it matches the current file exactly, any later drift of that file fails again, and this table only
// matters for databases that have not yet upgraded past the edit.
//
// Rules:
//  - Never edit a shipped migration. Add the next-numbered forward migration instead.
//  - This table is append-only and reviewed. It must match the "historical" lines of
//    core/seed/shipped_migrations.lock; tools/contracts/test_migration_checksums_contract.py
//    enforces that and checks every released tag's deploy/psql against the lock when tags are available.
struct HistoricalMigrationChecksum {
    std::string_view filename;
    std::string_view sha256;
    std::string_view note;
};

inline constexpr std::array kHistoricalMigrationChecksums{
    HistoricalMigrationChecksum{
        "020_vaults.sql",
        "64170212eb3f9fbe0f7c949791b953f0376a1f2bcf66b3dec7afc5db6325d570",
        "shipped v0.28.0-alpha..v1.5.0; v1.5.1 added s3.storage_tier_id in place "
        "(forward: 090_s3_storage_tier_id.sql)"
    },
    HistoricalMigrationChecksum{
        "060_acl.sql",
        "c154cd7e10f7931f29c12b9221c90f66d6b953cfb5e3dc15ea50f0940e5d4220",
        "shipped v0.28.0-alpha..v1.5.1; v1.6.0 added admin_role.s3_gateway_permissions in place "
        "(forward: 097_admin_role_s3_gateway_permissions.sql)"
    },
    HistoricalMigrationChecksum{
        "082_stats_metric_samples.sql",
        "720caaa27c0d51635fe3f459a8426f019d3f0dbdc0b7ae176d283309933a7f53",
        "shipped v1.2.4..v1.2.5 with alertable FUSE error columns; v1.2.6 reverted the file "
        "(forward: 084_stats_fuse_alertable_errors.sql)"
    },
};

inline bool isAcceptedHistoricalChecksum(const std::string_view filename, const std::string_view sha256) {
    return std::ranges::any_of(kHistoricalMigrationChecksums, [&](const HistoricalMigrationChecksum& e) {
        return e.filename == filename && e.sha256 == sha256;
    });
}

// C++ data steps: work a migration file can't do in SQL, run right after that file is applied, inside the same
// transaction (a failure rolls the whole deploy back). They run only when their file is applied in this run, so each
// must be idempotent and leave the schema to the SQL files.
//
//  - 122_storage_layout.sql: every existing vault and file gets its uid from libsodium (assignObjectUids), before
//    123_object_uids_required.sql makes the columns NOT NULL. PostgreSQL must not generate them: its UUIDs carry
//    version bits, and spec 01 §4.1 names the CSPRNG.
struct MigrationDataStep {
    std::string_view filename;
    void (*run)(pqxx::work&);
};

// Assigns a fresh vh::crypto::id::newObjectUid() to every vault without a uid and every file without an object uid, in
// batches. Rows that already have one are left alone.
void assignObjectUids(pqxx::work& txn);

inline constexpr std::array kMigrationDataSteps{
    MigrationDataStep{"122_storage_layout.sql", &assignObjectUids},
};

struct ReconciledMigration {
    std::string filename;
    std::string previous_sha256;
    std::string current_sha256;
};

struct SqlDeployReport {
    std::vector<std::string> applied;
    std::vector<ReconciledMigration> reconciled;
};

struct SqlDeployer {
    // Creates the migrations table if missing.
    static void ensureMigrationsTable(pqxx::work& txn);

    // Returns true if this exact file hash is already applied.
    static bool isApplied(pqxx::work& txn, const std::string& filename, const std::string& hash);

    // Mark file applied (upsert).
    static void markApplied(pqxx::work& txn, const std::string& filename, const std::string& hash);

    // Rewrite a reconciled migration's recorded hash. applied_at is preserved: the file was not re-applied.
    static void updateRecordedHash(pqxx::work& txn, const std::string& filename,
                                   const std::string& previous, const std::string& current);

    static bool filenameExists(pqxx::work& txn, const std::string& filename, std::string* existing_hash = nullptr);

    // Load *.sql from a directory, sort by filename, execute. Everything runs inside the caller's transaction, so
    // a failure anywhere rolls back every migration and schema_migrations row from this run.
    //
    // Behavior:
    //  - Not recorded yet => execute, then record its hash.
    //  - Recorded hash == file hash => skip.
    //  - Recorded hash is an accepted historical hash (kHistoricalMigrationChecksums) => skip WITHOUT executing,
    //    rewrite the recorded hash to the current one, and log it. A forward migration owns the schema delta.
    //  - Any other mismatch => throw: a shipped migration was edited. Create a new migration instead.
    //  - A file with a data step (kMigrationDataSteps) runs it right after the file itself.
    static SqlDeployReport applyDir(pqxx::work& txn, const fs::path& dir);
};

} // namespace vh::database::seed
