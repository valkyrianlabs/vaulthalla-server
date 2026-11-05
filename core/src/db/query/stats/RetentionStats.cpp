#include "db/query/stats/RetentionStats.hpp"

#include "config/Registry.hpp"
#include "db/Transactions.hpp"
#include "stats/model/RetentionStats.hpp"

#include <chrono>
#include <pqxx/pqxx>

namespace vh::db::query::stats {

namespace {

using RetentionModel = ::vh::stats::model::RetentionStats;

std::uint64_t retentionStatsUnixTimestamp() {
    return static_cast<std::uint64_t>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
}

std::optional<std::uint64_t> optionalRetentionStatsUInt64(pqxx::row_ref row, const char* column) {
    const auto field = row[column];
    if (field.is_null()) return std::nullopt;
    const auto value = field.as<double>();
    if (value < 0) return std::nullopt;
    return static_cast<std::uint64_t>(value);
}

std::uint64_t retentionStatsUInt64(pqxx::row_ref row, const char* column) {
    return optionalRetentionStatsUInt64(row, column).value_or(0);
}

void applyRetentionStatsRow(RetentionModel& stats, pqxx::row_ref row) {
    stats.trashedFilesCount = retentionStatsUInt64(row, "trashed_files_count");
    stats.trashedBytesTotal = retentionStatsUInt64(row, "trashed_bytes_total");
    stats.oldestTrashedAgeSeconds = optionalRetentionStatsUInt64(row, "oldest_trashed_age_seconds");
    stats.trashedFilesPastRetentionCount = retentionStatsUInt64(row, "trashed_files_past_retention_count");
    stats.trashedBytesPastRetention = retentionStatsUInt64(row, "trashed_bytes_past_retention");

    stats.syncEventsTotal = retentionStatsUInt64(row, "sync_events_total");
    stats.syncEventsPastRetentionCount = retentionStatsUInt64(row, "sync_events_past_retention_count");

    stats.auditLogEntriesTotal = retentionStatsUInt64(row, "audit_log_entries_total");
    stats.oldestAuditLogAgeSeconds = optionalRetentionStatsUInt64(row, "oldest_audit_log_age_seconds");
    stats.auditLogEntriesPastRetentionCount = retentionStatsUInt64(row, "audit_log_entries_past_retention_count");

    stats.shareAccessEventsTotal = retentionStatsUInt64(row, "share_access_events_total");
    stats.oldestShareAccessEventAgeSeconds = optionalRetentionStatsUInt64(row, "oldest_share_access_event_age_seconds");

    stats.cacheEntriesTotal = retentionStatsUInt64(row, "cache_entries_total");
    stats.cacheBytesTotal = retentionStatsUInt64(row, "cache_bytes_total");
    stats.cacheEvictionCandidates = retentionStatsUInt64(row, "cache_eviction_candidates");
    stats.cacheEntriesExpired = retentionStatsUInt64(row, "cache_entries_expired");
}

void applyRetentionStatsConfig(RetentionModel& stats) {
    const auto& config = config::Registry::get();
    stats.trashRetentionDays = static_cast<std::uint64_t>(config.auditing.files_trashed.retention_days.count());
    stats.syncEventRetentionDays = config.sync.event_audit_retention_days;
    stats.syncEventMaxEntries = config.sync.event_audit_max_entries;
    stats.auditLogRetentionDays = static_cast<std::uint64_t>(config.auditing.trail.retention_days.count());
    stats.cacheExpiryDays = config.caching.thumbnails.expiry_days;
    stats.cacheMaxSizeBytes = static_cast<std::uint64_t>(config.caching.max_size_mb) * 1024ull * 1024ull;
}

pqxx::params retentionStatsQueryParams(const RetentionModel& stats) {
    return pqxx::params{
        stats.trashRetentionDays,
        stats.syncEventRetentionDays,
        stats.auditLogRetentionDays,
        stats.cacheExpiryDays,
        stats.cacheMaxSizeBytes,
    };
}

pqxx::params retentionStatsQueryParamsForVault(const RetentionModel& stats, const std::uint32_t vaultId) {
    return pqxx::params{
        vaultId,
        stats.trashRetentionDays,
        stats.syncEventRetentionDays,
        stats.auditLogRetentionDays,
        stats.cacheExpiryDays,
        stats.cacheMaxSizeBytes,
    };
}

}

std::shared_ptr<::vh::stats::model::RetentionStats> RetentionStats::snapshot() {
    return Transactions::exec("RetentionStats::snapshot", [&](pqxx::work& txn) {
        auto stats = std::make_shared<RetentionModel>();
        stats->scope = "system";
        stats->checkedAt = retentionStatsUnixTimestamp();
        applyRetentionStatsConfig(*stats);

        const auto res = txn.exec(pqxx::prepped{"retention_stats.system"}, retentionStatsQueryParams(*stats));
        if (!res.empty()) applyRetentionStatsRow(*stats, res.one_row_ref());

        stats->finalize();
        return stats;
    });
}

std::shared_ptr<::vh::stats::model::RetentionStats> RetentionStats::snapshotForVault(const std::uint32_t vaultId) {
    return Transactions::exec("RetentionStats::snapshotForVault", [&](pqxx::work& txn) {
        auto stats = std::make_shared<RetentionModel>();
        stats->vaultId = vaultId;
        stats->scope = "vault";
        stats->checkedAt = retentionStatsUnixTimestamp();
        applyRetentionStatsConfig(*stats);

        const auto res = txn.exec(pqxx::prepped{"retention_stats.vault"}, retentionStatsQueryParamsForVault(*stats, vaultId));
        if (!res.empty()) applyRetentionStatsRow(*stats, res.one_row_ref());

        stats->finalize();
        return stats;
    });
}

}
