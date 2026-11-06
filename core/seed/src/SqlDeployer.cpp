#include "seed/include/SqlDeployer.hpp"

#include "crypto/id/ObjectUid.hpp"
#include "log/Registry.hpp"

#include <fmt/format.h>
#include <openssl/sha.h>

#include <algorithm>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace vh::db::seed {

std::string readFileToString(const fs::path& p) {
    std::ifstream in(p, std::ios::in | std::ios::binary);
    if (!in) throw std::runtime_error("Failed to open SQL file: " + p.string());
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

std::string sha256Hex(const std::string& s) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(s.data()), s.size(), hash);

    static const auto* hex = "0123456789abcdef";
    std::string out;
    out.resize(SHA256_DIGEST_LENGTH * 2);
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        out[i * 2 + 0] = hex[(hash[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[(hash[i] >> 0) & 0xF];
    }
    return out;
}

void SqlDeployer::ensureMigrationsTable(pqxx::work& txn) {
    txn.exec(R"(
        CREATE TABLE IF NOT EXISTS schema_migrations (
            filename   TEXT PRIMARY KEY,
            sha256     TEXT NOT NULL,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    )");
}

bool SqlDeployer::isApplied(pqxx::work& txn, const std::string& filename, const std::string& hash) {
    const auto r = txn.exec(
        "SELECT 1 FROM schema_migrations WHERE filename = $1 AND sha256 = $2",
        pqxx::params{filename, hash}
    );
    return !r.empty();
}

void SqlDeployer::markApplied(pqxx::work& txn, const std::string& filename, const std::string& hash) {
    txn.exec(R"(
        INSERT INTO schema_migrations (filename, sha256)
        VALUES ($1, $2)
        ON CONFLICT (filename)
        DO UPDATE SET sha256 = EXCLUDED.sha256, applied_at = CURRENT_TIMESTAMP
    )", pqxx::params{filename, hash});
}

void SqlDeployer::updateRecordedHash(pqxx::work& txn, const std::string& filename,
                                   const std::string& previous, const std::string& current) {
    txn.exec(
        "UPDATE schema_migrations SET sha256 = $3 WHERE filename = $1 AND sha256 = $2",
        pqxx::params{filename, previous, current}
    );
}

bool SqlDeployer::filenameExists(pqxx::work& txn, const std::string& filename, std::string* existing_hash) {
    const auto r = txn.exec(
        "SELECT sha256 FROM schema_migrations WHERE filename = $1",
        pqxx::params{filename}
    );
    if (r.empty()) return false;
    if (existing_hash) *existing_hash = r[0][0].as<std::string>();
    return true;
}

namespace {

// One table's missing uids, 10,000 rows per statement. Ids and uids travel as array literals (integers and UUID text
// need no quoting).
void assignUids(pqxx::work& txn, const std::string& table, const std::string& key, const std::string& column) {
    constexpr int kBatch = 10000;
    std::size_t assigned = 0;
    while (true) {
        const auto rows = txn.exec(fmt::format("SELECT {0} FROM {1} WHERE {2} IS NULL ORDER BY {0} LIMIT {3}",
                                               key, table, column, kBatch));
        if (rows.empty()) break;
        std::string ids = "{", uids = "{";
        for (const auto& row : rows) {
            if (ids.size() > 1) {
                ids += ',';
                uids += ',';
            }
            ids += row[0].c_str();
            uids += vh::crypto::id::toUuid(vh::crypto::id::newObjectUid());
        }
        ids += '}';
        uids += '}';
        txn.exec(fmt::format("UPDATE {1} t SET {2} = u.uid FROM unnest($1::int[], $2::uuid[]) AS u(id, uid) "
                             "WHERE t.{0} = u.id AND t.{2} IS NULL", key, table, column),
                 pqxx::params{ids, uids});
        assigned += rows.size();
    }
    if (assigned)
        log::Registry::vaulthalla()->info("[SqlDeployer] Assigned {} {}.{} value(s)", assigned, table, column);
}

}

void assignObjectUids(pqxx::work& txn) {
    assignUids(txn, "vault", "id", "uid");
    assignUids(txn, "files", "fs_entry_id", "object_uid");
}

SqlDeployReport SqlDeployer::applyDir(pqxx::work& txn, const fs::path& dir) {
    if (!fs::exists(dir)) throw std::runtime_error("SQL deploy dir does not exist: " + dir.string());
    if (!fs::is_directory(dir)) throw std::runtime_error("SQL deploy path is not a directory: " + dir.string());

    std::vector<fs::path> files;
    for (const auto& e : fs::directory_iterator(dir)) {
        if (!e.is_regular_file()) continue;
        const auto& p = e.path();
        if (p.extension() == ".sql") files.push_back(p);
    }

    std::ranges::sort(files.begin(), files.end(), [](const fs::path& a, const fs::path& b) {
        return a.filename().string() < b.filename().string();
    });

    // Until migration 100 converts them, naive `timestamp` columns hold wall time in the database's own zone, and
    // 100 reads them in that zone. Rows this run writes before 100 (schema_migrations, seed data) must land in
    // the same zone, not the daemon's UTC session (db::Connection::configureSession): run the whole deploy in it.
    // Local to this transaction; timestamptz columns are absolute either way.
    txn.exec("SELECT set_config('TimeZone', COALESCE(NULLIF(current_setting('vaulthalla.database_timezone', true), "
             "''), current_setting('TimeZone')), true)");

    SqlDeployReport report;

    for (const auto& p : files) {
        const std::string sql = readFileToString(p);
        const std::string hash = sha256Hex(sql);
        const std::string filename = p.filename().string();

        std::string existing;
        if (filenameExists(txn, filename, &existing)) {
            if (existing == hash) continue; // exact match already applied

            if (isAcceptedHistoricalChecksum(filename, existing)) {
                updateRecordedHash(txn, filename, existing, hash);
                log::Registry::vaulthalla()->info(
                    "[SqlDeployer] Migration {} was recorded with a known historical checksum ({}); "
                    "accepting it without re-applying and recording the current checksum ({})",
                    filename, existing, hash
                );
                report.reconciled.push_back({filename, existing, hash});
                continue;
            }

            throw std::runtime_error(fmt::format("Migration file was modified after being applied: {} "
                                                 "(db={} file={}). Create a new migration instead.",
                filename, existing, hash)
            );
        }

        txn.exec(sql);
        for (const auto& step : kMigrationDataSteps)
            if (step.filename == filename) step.run(txn);
        markApplied(txn, filename, hash);
        report.applied.push_back(filename);
    }

    return report;
}

}
