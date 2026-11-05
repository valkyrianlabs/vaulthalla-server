#include "db/DBConnection.hpp"

void vh::db::Connection::initPreparedRetentionStats() const {
    conn_->prepare("retention_stats.system",
        R"SQL(
            SELECT
                (SELECT COUNT(*) FROM files_trashed WHERE deleted_at IS NULL) AS trashed_files_count,
                (SELECT COALESCE(SUM(size_bytes), 0) FROM files_trashed WHERE deleted_at IS NULL) AS trashed_bytes_total,
                (SELECT EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - MIN(trashed_at))) FROM files_trashed WHERE deleted_at IS NULL) AS oldest_trashed_age_seconds,
                (SELECT COUNT(*) FROM files_trashed WHERE deleted_at IS NULL AND trashed_at < CURRENT_TIMESTAMP - ($1::int * INTERVAL '1 day')) AS trashed_files_past_retention_count,
                (SELECT COALESCE(SUM(size_bytes), 0) FROM files_trashed WHERE deleted_at IS NULL AND trashed_at < CURRENT_TIMESTAMP - ($1::int * INTERVAL '1 day')) AS trashed_bytes_past_retention,

                (SELECT COUNT(*) FROM sync_event) AS sync_events_total,
                (SELECT COUNT(*) FROM sync_event WHERE timestamp_begin < CURRENT_TIMESTAMP - ($2::int * INTERVAL '1 day')) AS sync_events_past_retention_count,

                (SELECT COUNT(*) FROM audit_event) AS audit_log_entries_total,
                (SELECT EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) - MIN(occurred_us) / 1000000.0 FROM audit_event) AS oldest_audit_log_age_seconds,
                (SELECT COUNT(*) FROM audit_event WHERE occurred_us < (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP - ($3::int * INTERVAL '1 day')) * 1000000)::bigint) AS audit_log_entries_past_retention_count,

                (SELECT COUNT(*) FROM share_access_event) AS share_access_events_total,
                (SELECT EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - MIN(created_at))) FROM share_access_event) AS oldest_share_access_event_age_seconds,

                (SELECT COUNT(*) FROM cache_index) AS cache_entries_total,
                (SELECT COALESCE(SUM(size), 0) FROM cache_index) AS cache_bytes_total,
                (
                    SELECT CASE
                        WHEN COALESCE(SUM(size), 0) > $5::bigint THEN COUNT(*)
                        ELSE COUNT(*) FILTER (WHERE last_accessed < CURRENT_TIMESTAMP - ($4::int * INTERVAL '1 day'))
                    END
                    FROM cache_index
                ) AS cache_eviction_candidates,
                (SELECT COUNT(*) FROM cache_index WHERE last_accessed < CURRENT_TIMESTAMP - ($4::int * INTERVAL '1 day')) AS cache_entries_expired;
        )SQL"
    );

    conn_->prepare("retention_stats.vault",
        R"SQL(
            SELECT
                (SELECT COUNT(*) FROM files_trashed WHERE vault_id = $1 AND deleted_at IS NULL) AS trashed_files_count,
                (SELECT COALESCE(SUM(size_bytes), 0) FROM files_trashed WHERE vault_id = $1 AND deleted_at IS NULL) AS trashed_bytes_total,
                (SELECT EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - MIN(trashed_at))) FROM files_trashed WHERE vault_id = $1 AND deleted_at IS NULL) AS oldest_trashed_age_seconds,
                (SELECT COUNT(*) FROM files_trashed WHERE vault_id = $1 AND deleted_at IS NULL AND trashed_at < CURRENT_TIMESTAMP - ($2::int * INTERVAL '1 day')) AS trashed_files_past_retention_count,
                (SELECT COALESCE(SUM(size_bytes), 0) FROM files_trashed WHERE vault_id = $1 AND deleted_at IS NULL AND trashed_at < CURRENT_TIMESTAMP - ($2::int * INTERVAL '1 day')) AS trashed_bytes_past_retention,

                (SELECT COUNT(*) FROM sync_event WHERE vault_id = $1) AS sync_events_total,
                (SELECT COUNT(*) FROM sync_event WHERE vault_id = $1 AND timestamp_begin < CURRENT_TIMESTAMP - ($3::int * INTERVAL '1 day')) AS sync_events_past_retention_count,

                (SELECT COUNT(*) FROM audit_event WHERE vault_id = $1) AS audit_log_entries_total,
                (SELECT EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) - MIN(occurred_us) / 1000000.0 FROM audit_event WHERE vault_id = $1) AS oldest_audit_log_age_seconds,
                (SELECT COUNT(*) FROM audit_event WHERE vault_id = $1 AND occurred_us < (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP - ($4::int * INTERVAL '1 day')) * 1000000)::bigint) AS audit_log_entries_past_retention_count,

                (SELECT COUNT(*) FROM share_access_event WHERE vault_id = $1) AS share_access_events_total,
                (SELECT EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - MIN(created_at))) FROM share_access_event WHERE vault_id = $1) AS oldest_share_access_event_age_seconds,

                (SELECT COUNT(*) FROM cache_index WHERE vault_id = $1) AS cache_entries_total,
                (SELECT COALESCE(SUM(size), 0) FROM cache_index WHERE vault_id = $1) AS cache_bytes_total,
                (
                    SELECT CASE
                        WHEN COALESCE(SUM(size), 0) > $6::bigint THEN COUNT(*)
                        ELSE COUNT(*) FILTER (WHERE last_accessed < CURRENT_TIMESTAMP - ($5::int * INTERVAL '1 day'))
                    END
                    FROM cache_index
                    WHERE vault_id = $1
                ) AS cache_eviction_candidates,
                (SELECT COUNT(*) FROM cache_index WHERE vault_id = $1 AND last_accessed < CURRENT_TIMESTAMP - ($5::int * INTERVAL '1 day')) AS cache_entries_expired;
        )SQL"
    );
}
