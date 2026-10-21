// ws models: stats (stats.* and dashboard.preferences.*). Serializers: core/src/stats/model/*.cpp, the vault capacity
// stat (core/src/vault/model/{Stat,Capacity}.cpp) and the sync run it carries (core/src/sync/model/*.cpp).
// Timestamps in these models are Unix epoch seconds (integers) unless a field says otherwise.

#include "models.hpp"

namespace vh::contract::ws::detail {

namespace {

// Serialized std::optional<T>: always sent, null when unset.
WsField statsNullable(WsField f) { return f.nullable(); }

WsField statsUint(std::string name, std::string description = {}) {
    auto f = uinteger(std::move(name));
    return description.empty() ? f : f.desc(std::move(description));
}

WsField statsCheckedAt() { return uinteger("checked_at").desc("When the figures were taken (epoch seconds)."); }

const std::vector<std::string> kStatsTriStatus{"healthy", "warning", "critical"};

std::vector<WsModel> statsVaultModels() {
    std::vector<WsModel> out;

    out.push_back(model("VaultCapacity",
        "A vault's capacity figures (core/src/vault/model/Capacity.cpp to_json).",
        {statsUint("capacity", "Quota in bytes (0 = unlimited)."),
         statsUint("logical_size", "Bytes of the vault's files."),
         statsUint("physical_size", "Bytes the vault uses on its backing store."),
         statsUint("free_space"), statsUint("cache_size"), statsUint("file_count"), statsUint("directory_count"),
         statsUint("average_file_size"), statsUint("largest_file_size"),
         mapOf("top_file_extensions", uinteger("bytes"))
             .desc("Extension → total bytes, the 10 largest; unused slots appear as the key \"\" with 0.")}));

    out.push_back(model("VaultStat",
        "stats.vault: capacity plus the vault engine's latest sync run (core/src/vault/model/Stat.cpp to_json).",
        {object("capacity", "VaultCapacity"),
         object("latest_sync_event", "SyncEvent").nullable().desc("null before the vault's first sync run.")}));

    out.push_back(model("SyncThroughput",
        "One metric bucket of a sync run (core/src/sync/model/Throughput.cpp to_json).",
        {statsUint("id"), str("run_uuid"), statsUint("num_ops"), statsUint("failed_ops"), statsUint("size_bytes"),
         statsUint("duration_ms"),
         str("metric_type").oneOf({"upload", "download", "index", "rename", "copy", "delete", "unknown"})}));

    out.push_back(model("SyncRunConflictArtifact",
        "One side of a sync run conflict (core/src/sync/model/Artifact.cpp to_json).",
        {statsUint("id"), statsUint("conflict_id"), str("side").oneOf({"local", "upstream", "unknown"}),
         object("file", "FsEntry").desc("The file as that side has it.")}));

    out.push_back(model("SyncRunConflict",
        "A conflict recorded by a sync run (core/src/sync/model/Conflict.cpp to_json).",
        {statsUint("id"), statsUint("event_id"), statsUint("file_id"),
         str("type").oneOf({"mismatch", "encryption", "both"}),
         str("resolution").oneOf({"unresolved", "kept_local", "kept_remote", "kept_both", "overwritten",
                                  "fixed_remote_encryption"}),
         integer("resolved_at").desc("Epoch seconds; 0 while unresolved."), integer("created_at"),
         object("artifacts", "",
                {object("local", "SyncRunConflictArtifact"), object("upstream", "SyncRunConflictArtifact")})
             .desc("core/src/sync/model/ConflictArtifact.cpp to_json."),
         objectArray("reasons", "", {str("code"), str("message")})}));

    std::vector<WsField> event{
        statsUint("id"), statsUint("vault_id"), str("run_uuid"),
        integer("timestamp_begin").desc("Epoch seconds; 0 = not set."),
        integer("timestamp_end").desc("Epoch seconds; 0 while running."),
        integer("heartbeat_at").desc("Epoch seconds; 0 = none yet."),
        str("status").oneOf({"pending", "running", "success", "stalled", "error", "cancelled"}),
        str("trigger").oneOf({"schedule", "manual", "startup", "webhook", "retry"}),
        statsUint("retry_attempt"),
        str("stall_reason").desc("\"\" when none."), str("error_code").desc("\"\" when none."),
        str("error_message").desc("\"\" when none."),
    };
    for (const auto* n : {"num_ops_total", "num_failed_ops", "num_conflicts", "bytes_up", "bytes_down",
                          "s3_list_requests", "s3_head_requests", "s3_get_requests", "s3_put_requests",
                          "s3_copy_requests", "s3_delete_requests", "s3_downloaded_bytes",
                          "s3_estimated_list_requests", "s3_estimated_head_requests", "s3_estimated_get_requests",
                          "s3_estimated_put_requests", "s3_estimated_copy_requests", "s3_estimated_delete_requests",
                          "s3_estimated_body_download_bytes", "s3_estimated_upload_bytes", "s3_remote_index_objects",
                          "s3_archive_downloads_skipped"})
        event.push_back(statsUint(n));
    for (const auto* n : {"s3_estimated_cost", "s3_estimated_cost_currency", "s3_price_profile_id",
                          "s3_price_catalog_version", "s3_price_confidence_level", "s3_price_estimate_mode",
                          "s3_price_free_tier_policy", "s3_budget_estimated_cost", "s3_budget_estimated_cost_currency",
                          "s3_budget_estimate_mode", "s3_budget_free_tier_policy"})
        event.push_back(statsNullable(str(n)));
    event.push_back(statsNullable(boolean("s3_price_free_tiers_applied")));
    event.push_back(statsNullable(boolean("s3_budget_free_tiers_applied")));
    event.push_back(strArray("s3_price_unknowns")
                        .desc("What the run's price estimate could not price, as recorded; [] when none."));
    event.push_back(objectArray("s3_price_breakdown", "")
                        .desc("The run's price-estimate line items ({meter_key, cost, ...}) as the pricing engine "
                              "returned them, stored verbatim; [] when none."));
    event.push_back(objectArray("conflicts", "SyncRunConflict"));
    event.push_back(objectArray("throughputs", "SyncThroughput"));
    event.push_back(boolean("divergence_detected"));
    event.push_back(str("local_state_hash").desc("\"\" when not computed."));
    event.push_back(str("remote_state_hash").desc("\"\" when not computed."));
    event.push_back(str("config_hash"));
    out.push_back(model("SyncEvent", "One sync run (core/src/sync/model/Event.cpp to_json).", std::move(event)));

    std::vector<WsField> sync{
        statsUint("vault_id"),
        str("overall_status").oneOf({"healthy", "syncing", "warning", "stalled", "error", "diverged", "unknown"}),
        str("current_state").oneOf({"idle", "pending", "running", "stalled", "error", "cancelled", "success",
                                    "diverged", "unknown"}),
        boolean("sync_enabled"), statsUint("sync_interval_seconds"),
        statsNullable(str("configured_strategy")), statsNullable(str("conflict_policy")),
    };
    for (const auto* n : {"s3_budget_list_requests", "s3_budget_head_requests", "s3_budget_get_requests",
                          "s3_budget_put_requests", "s3_budget_copy_requests", "s3_budget_delete_requests",
                          "s3_budget_downloaded_bytes"})
        sync.push_back(statsNullable(statsUint(n)));
    sync.push_back(boolean("s3_budget_unlimited_legacy"));
    sync.push_back(statsNullable(str("s3_budget_warning")));
    sync.push_back(statsNullable(statsUint("max_remote_index_age_seconds")));
    sync.push_back(object("latest_event", "SyncEvent").nullable());
    sync.push_back(statsNullable(statsUint("latest_event_id")));
    sync.push_back(statsNullable(str("latest_run_uuid")));
    for (const auto* n : {"last_sync_at", "last_success_at", "last_success_age_seconds"})
        sync.push_back(statsNullable(statsUint(n)));
    for (const auto* n : {"active_run_count", "pending_run_count", "running_run_count", "stalled_run_count"})
        sync.push_back(statsUint(n));
    sync.push_back(statsNullable(statsUint("oldest_active_age_seconds")));
    sync.push_back(statsNullable(statsUint("latest_heartbeat_age_seconds")));
    for (const auto* n : {"error_count_24h", "error_count_7d", "failed_ops_24h", "failed_ops_7d", "retry_count_24h",
                          "retry_count_7d", "conflict_count_open", "conflict_count_24h", "conflict_count_7d",
                          "bytes_up_24h", "bytes_down_24h", "bytes_total_24h", "bytes_up_7d", "bytes_down_7d",
                          "bytes_total_7d"})
        sync.push_back(statsUint(n));
    sync.push_back(number("avg_throughput_bytes_per_sec_24h"));
    sync.push_back(number("peak_throughput_bytes_per_sec_24h"));
    sync.push_back(boolean("divergence_detected"));
    sync.push_back(statsNullable(str("local_state_hash")));
    sync.push_back(statsNullable(str("remote_state_hash")));
    sync.push_back(boolean("hash_mismatch"));
    sync.push_back(statsUint("remote_index_object_count"));
    sync.push_back(statsNullable(str("remote_index_source")));
    sync.push_back(statsNullable(statsUint("remote_index_indexed_at")));
    sync.push_back(boolean("remote_index_stale"));
    sync.push_back(statsNullable(str("last_error_code")));
    sync.push_back(statsNullable(str("last_error_message")));
    sync.push_back(statsNullable(str("last_stall_reason")));
    sync.push_back(statsCheckedAt());
    out.push_back(model("VaultSyncHealth", "A vault's sync health (core/src/stats/model/VaultSyncHealth.cpp to_json).",
                        std::move(sync)));

    out.push_back(model("VaultActivity",
        "A vault's recent activity (core/src/stats/model/VaultActivity.cpp to_json).",
        {statsUint("vault_id"), statsNullable(statsUint("last_activity_at")),
         statsNullable(str("last_activity_action")),
         statsUint("uploads_24h"), statsUint("uploads_7d"), statsUint("deletes_24h"), statsUint("deletes_7d"),
         statsUint("renames_24h"), statsUint("renames_7d"), statsUint("moves_24h"), statsUint("moves_7d"),
         statsUint("copies_24h"), statsUint("copies_7d"), statsUint("restores_24h"), statsUint("restores_7d"),
         statsUint("bytes_added_24h"), statsUint("bytes_removed_24h"),
         objectArray("top_active_users", "",
                     {statsNullable(statsUint("user_id")), statsNullable(str("user_name")), statsUint("count")}),
         objectArray("top_touched_paths", "", {str("path"), str("action"), statsUint("count"), statsUint("bytes")}),
         objectArray("recent_activity", "",
                     {str("source"), str("action"), str("path"), statsNullable(statsUint("user_id")),
                      statsNullable(str("user_name")), statsNullable(str("status")), statsNullable(str("error")),
                      statsUint("bytes"), statsUint("occurred_at")}),
         statsCheckedAt()}));

    out.push_back(model("VaultShareStats",
        "A vault's share-link statistics (core/src/stats/model/VaultShareStats.cpp to_json).",
        {statsUint("vault_id"), statsUint("active_links"), statsUint("expired_links"), statsUint("revoked_links"),
         statsUint("links_created_24h"), statsUint("links_revoked_24h"), statsUint("public_links"),
         statsUint("email_validated_links"), statsUint("downloads_24h"), statsUint("uploads_24h"),
         statsUint("denied_attempts_24h"), statsUint("rate_limited_attempts_24h"), statsUint("failed_attempts_24h"),
         objectArray("top_links_by_access", "",
                     {str("share_id"), str("label"), str("root_path"), str("link_type"), str("access_mode"),
                      statsUint("access_count"), statsUint("download_count"), statsUint("upload_count"),
                      statsNullable(statsUint("last_accessed_at"))}),
         objectArray("recent_share_events", "",
                     {statsUint("id"), statsNullable(str("share_id")), str("event_type"), str("status"),
                      statsNullable(str("target_path")), statsUint("bytes_transferred"),
                      statsNullable(str("error_code")), statsNullable(str("error_message")), statsUint("created_at")}),
         statsCheckedAt()}));

    out.push_back(model("VaultRecoveryStats",
        "A vault's backup/recovery posture (core/src/stats/model/VaultRecovery.cpp to_json; C++ "
        "stats::model::VaultRecovery).",
        {statsUint("vault_id"), boolean("backup_policy_present"), boolean("backup_enabled"), str("backup_status"),
         statsUint("backup_interval_seconds"), statsNullable(statsUint("retention_seconds")),
         statsNullable(statsUint("last_backup_at")), statsNullable(statsUint("last_success_at")),
         statsNullable(statsUint("last_success_age_seconds")), statsNullable(statsUint("next_expected_backup_at")),
         statsNullable(boolean("backup_stale")), statsNullable(statsUint("missed_backup_count_estimate")),
         statsUint("retry_count"), statsNullable(str("last_error")),
         str("recovery_readiness").oneOf({"ready", "stale", "failing", "unknown"}),
         statsNullable(statsUint("time_since_last_verified_good_state")), statsCheckedAt()}));

    out.push_back(model("VaultSecurity",
        "A vault's security posture (core/src/stats/model/VaultSecurity.cpp to_json).",
        {statsUint("vault_id"), str("overall_status"), str("encryption_status"),
         statsNullable(statsUint("current_key_version")), statsNullable(statsUint("key_created_at")),
         statsNullable(statsUint("key_age_days")), statsUint("trashed_key_versions_count"), statsUint("file_count"),
         statsUint("files_current_key_version"), statsUint("files_legacy_key_version"),
         statsUint("files_unknown_key_version"), statsUint("unauthorized_access_attempts_24h"),
         statsUint("rate_limited_attempts_24h"), statsNullable(statsUint("last_denied_access_at")),
         statsNullable(str("last_denied_access_reason")), statsNullable(statsUint("last_permission_change_at")),
         statsNullable(statsUint("last_share_policy_change_at")),
         str("integrity_check_status").desc("\"not_available\" until integrity checks exist."),
         statsNullable(statsUint("last_integrity_check_at")), statsNullable(statsUint("checksum_mismatch_count")),
         statsCheckedAt()}));

    return out;
}

std::vector<WsModel> statsSystemModels() {
    std::vector<WsModel> out;

    out.push_back(model("OperationStats",
        "Filesystem operation queue and share upload figures, one vault or the system (core/src/stats/model/"
        "OperationStats.cpp to_json).",
        {statsNullable(statsUint("vault_id")).desc("null for the system scope."),
         str("scope").oneOf({"system", "vault"}), str("overall_status").oneOf(kStatsTriStatus),
         statsUint("stale_threshold_seconds"), statsUint("pending_operations"), statsUint("in_progress_operations"),
         statsUint("failed_operations_24h"), statsUint("cancelled_operations_24h"), statsUint("stalled_operations"),
         statsNullable(statsUint("oldest_pending_operation_age_seconds")),
         statsNullable(statsUint("oldest_in_progress_operation_age_seconds")),
         mapOf("operations_by_type", uinteger("count")).desc("move, copy, rename → count."),
         mapOf("operations_by_status", uinteger("count")).desc("pending, in_progress, success, error, cancelled → "
                                                               "count."),
         statsUint("active_share_uploads"), statsUint("stalled_share_uploads"), statsUint("failed_share_uploads_24h"),
         statsUint("upload_bytes_expected_active"), statsUint("upload_bytes_received_active"),
         statsNullable(statsUint("oldest_active_upload_age_seconds")),
         objectArray("recent_operation_errors", "",
                     {str("source"), str("operation"), str("status"), str("target"), str("path"),
                      statsNullable(str("error")), statsNullable(statsUint("occurred_at"))}),
         statsCheckedAt()}));

    out.push_back(model("StorageVaultBackendStats",
        "One vault's storage backend figures (core/src/stats/model/StorageBackendStats.cpp to_json).",
        {statsUint("vault_id"), str("vault_name"), str("type"), boolean("active"), boolean("allow_fs_write"),
         statsUint("quota_bytes"), statsNullable(statsUint("free_space_bytes")),
         statsNullable(statsUint("cache_size_bytes")), statsNullable(statsUint("vault_size_bytes")),
         str("backend_status"), statsNullable(boolean("min_free_space_ok")),
         statsNullable(boolean("upstream_encryption_enabled")), statsNullable(str("bucket")),
         statsNullable(statsUint("provider_ops_total")), statsNullable(statsUint("provider_errors_total")),
         statsNullable(number("provider_error_rate")), statsNullable(number("provider_latency_avg_ms")),
         statsNullable(number("provider_latency_max_ms")), statsNullable(str("last_provider_error")),
         statsNullable(statsUint("last_provider_success_at"))}));

    out.push_back(model("StorageBackendStats",
        "Storage backend figures for every vault or one (core/src/stats/model/StorageBackendStats.cpp to_json).",
        {str("overall_status"), statsUint("vault_count_total"), statsUint("local_vault_count"),
         statsUint("s3_vault_count"), statsUint("active_vault_count"), statsUint("inactive_vault_count"),
         statsUint("degraded_vault_count"), statsUint("error_vault_count"),
         objectArray("vaults", "StorageVaultBackendStats"), statsCheckedAt()}));

    out.push_back(model("RetentionStats",
        "Retention (trash, sync events, audit log, cache) figures, one vault or the system (core/src/stats/model/"
        "RetentionStats.cpp to_json).",
        {statsNullable(statsUint("vault_id")).desc("null for the system scope."), str("scope").oneOf({"system", "vault"}),
         str("cleanup_status").oneOf({"healthy", "warning", "overdue", "unknown"}),
         statsUint("trash_retention_days"), statsUint("sync_event_retention_days"), statsUint("sync_event_max_entries"),
         statsUint("audit_log_retention_days"), statsUint("cache_expiry_days"), statsUint("cache_max_size_bytes"),
         statsUint("trashed_files_count"), statsUint("trashed_bytes_total"),
         statsNullable(statsUint("oldest_trashed_age_seconds")), statsUint("trashed_files_past_retention_count"),
         statsUint("trashed_bytes_past_retention"), statsUint("sync_events_total"),
         statsUint("sync_events_past_retention_count"), statsUint("audit_log_entries_total"),
         statsNullable(statsUint("oldest_audit_log_age_seconds")), statsUint("audit_log_entries_past_retention_count"),
         statsUint("share_access_events_total"), statsNullable(statsUint("oldest_share_access_event_age_seconds")),
         statsUint("cache_entries_total"), statsUint("cache_bytes_total"), statsUint("cache_eviction_candidates"),
         statsUint("cache_entries_expired"), statsCheckedAt()}));

    out.push_back(model("StatsTrends",
        "Metric trend series from the stats rollups (core/src/stats/model/StatsTrends.cpp to_json).",
        {str("scope").oneOf({"system", "vault"}), statsNullable(statsUint("vault_id")).desc("null for the system "
                                                                                          "scope."),
         statsUint("window_hours"),
         objectArray("series", "",
                     {str("key"), str("label"), str("unit"), str("snapshot_type"),
                      objectArray("points", "", {statsUint("created_at"), number("value")})}),
         statsCheckedAt()}));

    out.push_back(model("DbStats", "Database figures (core/src/stats/model/DbStats.cpp to_json).",
        {boolean("connected"), str("status"), statsNullable(str("error")), statsNullable(str("database_name")),
         statsUint("db_size_bytes"), statsUint("connections_active"), statsUint("connections_idle"),
         statsUint("connections_idle_in_transaction"), statsUint("connections_total"),
         statsNullable(statsUint("connections_max")), statsNullable(number("cache_hit_ratio")),
         boolean("pg_stat_statements_enabled"), statsNullable(statsUint("slow_query_count")), statsUint("deadlocks"),
         statsUint("temp_bytes"),
         statsNullable(statsUint("oldest_transaction_age_seconds"))
             .desc("null while connected means no other transaction is open; when disconnected, not measured."),
         objectArray("largest_tables", "",
                     {str("table_name"), statsUint("total_bytes"), statsUint("table_bytes"), statsUint("index_bytes"),
                      statsUint("row_estimate")}),
         statsCheckedAt()}));

    out.push_back(model("ThreadPoolSnapshot", "One thread pool (core/src/stats/model/ThreadPoolStats.cpp to_json).",
        {str("name"), statsUint("queue_depth"), statsUint("worker_count"), statsUint("idle_worker_count"),
         statsUint("busy_worker_count"), boolean("has_idle_worker"), boolean("stopped"), number("pressure_ratio"),
         str("status")}));

    out.push_back(model("ThreadPoolManagerSnapshot",
        "Every thread pool (core/src/stats/model/ThreadPoolStats.cpp to_json).",
        {str("overall_status"), statsUint("total_worker_count"), statsUint("total_queue_depth"),
         statsUint("total_idle_worker_count"), number("max_pressure_ratio"), statsUint("pressured_pool_count"),
         statsUint("saturated_pool_count"), statsCheckedAt(), objectArray("pools", "ThreadPoolSnapshot")}));

    out.push_back(model("FuseStatsSnapshot",
        "FUSE operation counters (core/src/stats/model/FuseStats.cpp to_json).",
        {statsUint("total_ops"), statsUint("total_successes"), statsUint("total_errors"), statsUint("expected_errors"),
         statsUint("alertable_errors"), number("error_rate"), number("expected_error_rate"),
         number("alertable_error_rate"), statsUint("read_bytes"), statsUint("write_bytes"),
         statsUint("open_handles_current"), statsUint("open_handles_peak"),
         objectArray("ops", "",
                     {str("op"), statsUint("count"), statsUint("successes"), statsUint("errors"),
                      statsUint("expected_errors"), statsUint("alertable_errors"), statsUint("bytes_read"),
                      statsUint("bytes_written"), statsUint("total_us"), statsUint("max_us"), number("avg_ms"),
                      number("max_ms"), number("error_rate"), number("expected_error_rate"),
                      number("alertable_error_rate")}),
         objectArray("top_errors", "",
                     {integer("errno_value"), str("name"), statsUint("count"),
                      statsUint("alertable_count").desc("Occurrences not expected for the op that returned them.")}),
         statsUint("alertable_errno_types"), statsCheckedAt()}));

    out.push_back(model("ConnectionStats",
        "Live websocket sessions (core/src/stats/model/ConnectionStats.cpp to_json).",
        {str("status").oneOf({"healthy", "warning", "critical", "unknown"}), statsUint("active_ws_sessions_total"),
         statsUint("active_human_sessions"), statsUint("active_share_sessions"),
         statsUint("active_share_pending_sessions"), statsUint("active_unauthenticated_sessions"),
         statsNullable(statsUint("oldest_session_age_seconds")),
         statsNullable(statsUint("oldest_unauthenticated_session_age_seconds")), statsUint("idle_timeout_minutes"),
         statsUint("unauthenticated_timeout_seconds"), statsUint("sweep_interval_seconds"),
         statsNullable(statsUint("sessions_swept_24h")), statsNullable(statsUint("connections_opened_24h")),
         statsNullable(statsUint("connections_closed_24h")), statsNullable(statsUint("connection_errors_24h")),
         mapOf("sessions_by_mode", uinteger("count")).desc("unauthenticated, human, share_pending, share → count."),
         strArray("top_user_agents").desc("Always empty: not collected (top_user_agents_available is false)."),
         boolean("top_user_agents_available"),
         strArray("top_remote_ips_limited").desc("Always empty: not collected (top_remote_ips_available is false)."),
         boolean("top_remote_ips_available"), statsCheckedAt()}));

    out.push_back(model("CacheStatsSnapshot",
        "Cache counters (core/src/stats/model/CacheStats.cpp to_json(CacheStatsSnapshot)).",
        {statsUint("hits"), statsUint("misses"), statsUint("evictions"), statsUint("inserts"),
         statsUint("invalidations"), statsUint("bytes_read"), statsUint("bytes_written"), statsUint("used_bytes"),
         statsNullable(statsUint("capacity_bytes")).desc("null: no byte cap (the filesystem metadata cache) or none "
                                                         "reported yet."),
         statsNullable(statsUint("free_bytes")).desc("null when capacity_bytes is."),
         object("op", "",
                {statsUint("count"), statsUint("total_us"), statsUint("max_us"), number("avg_ms"), number("max_ms")})
             .desc("The work behind misses (e.g. thumbnail generation).")}));

    std::vector<WsField> runtimeService{str("entry_name"), str("service_name"), boolean("running"),
                                        boolean("interrupted")};
    out.push_back(model("SystemHealth",
        "Runtime services, protocols, dependencies and the database pool (core/src/stats/model/SystemHealth.cpp "
        "to_json).",
        {str("overall_status").oneOf({"healthy", "degraded", "critical"}),
         object("runtime", "",
                {boolean("all_running"), statsUint("service_count"),
                 objectArray("services", "", std::move(runtimeService))}),
         object("protocols", "",
                {boolean("running"), boolean("io_context_initialized"), boolean("websocket_configured"),
                 boolean("websocket_ready"), boolean("http_preview_configured"), boolean("http_preview_ready")}),
         object("s3_gateway", "",
                {boolean("running"), boolean("configured"), boolean("ready"), str("host"), statsUint("port"),
                 statsUint("active_sessions"), statsUint("total_requests"), statsUint("failed_requests")}),
         object("deps", "",
                {boolean("storage_manager"), boolean("api_key_manager"), boolean("auth_manager"),
                 boolean("session_manager"), boolean("secrets_manager"), boolean("sync_controller"),
                 boolean("fs_cache"), boolean("shell_usage_manager"), boolean("http_cache_stats"),
                 boolean("fuse_session"),
                 str("fuse_mount").desc("\"multiuser\" (kernel FUSE bridge) or \"disabled\" (built without it)."),
                 str("mount_state").desc("disabled | mounted | not_mounted | unavailable | unsupported."),
                 str("mount_backend"),
                 str("mount_isolation").desc("enforced | unproven | not_applicable."),
                 statsNullable(str("mount_detail")),
                 str("secrets_backend").desc("\"tpm2\", or \"file\" (macOS development backend).")}),
         object("shell", "", {statsNullable(boolean("admin_uid_bound"))}),
         object("database", "",
                {statsUint("pool_size"), statsUint("idle"), statsUint("in_use"), statsUint("broken_idle"),
                 statsUint("reconnects"), statsUint("reconnect_failures"), statsUint("consecutive_reconnect_failures"),
                 statsUint("acquire_timeouts"), boolean("reachable").desc("A live bounded SELECT 1 with the snapshot."),
                 integer("probe_latency_ms"), statsNullable(str("probe_error"))})
             .nullable()
             .desc("null until the pool exists (critical)."),
         objectArray("vaults_unavailable", "",
                     {uinteger("vault_id"), str("vault_name"),
                      str("reason").oneOf({"key_missing", "key_unsealable", "version_missing", "engine_failed"})
                          .desc("vault::KeyUnavailable's code (restore with vh vault keys import), or engine_failed."),
                      str("detail")})
             .desc("Live vaults whose storage engine did not start (storage::Manager::unavailableVaults): their data "
                   "can't be read. Any entry makes the node at least degraded; empty when every vault runs."),
         object("summary", "",
                {statsUint("services_ready"), statsUint("services_total"), statsUint("deps_ready"),
                 statsUint("deps_total"), statsUint("protocols_ready"), statsUint("protocols_total"),
                 statsCheckedAt()})}));

    return out;
}

std::vector<WsModel> statsDashboardModels() {
    std::vector<WsModel> out;

    out.push_back(model("DashboardMetricSummary",
        "One metric of a dashboard card or section (core/src/stats/model/DashboardOverview.cpp to_json).",
        {str("key"), str("label"), str("value").desc("Display text."), statsNullable(str("unit")), str("tone"),
         statsNullable(number("numeric_value")), statsNullable(str("href"))}));

    out.push_back(model("DashboardIssueSummary",
        "A warning or error of a dashboard card or section (core/src/stats/model/DashboardOverview.cpp to_json).",
        {str("code"), str("severity"), str("message"), statsNullable(str("href")), statsNullable(str("metric_key"))}));

    out.push_back(model("DashboardCardSummary",
        "One dashboard card (core/src/stats/model/DashboardOverview.cpp to_json).",
        {str("id"), str("section_id"), str("title"), str("description"), str("href"), str("variant"), str("size"),
         str("severity"), boolean("available"), statsNullable(str("unavailable_reason")), str("summary"),
         objectArray("metrics", "DashboardMetricSummary"),
         objectArray("series", "",
                     {str("key"), str("label"), str("unit"), str("tone"),
                      objectArray("points", "", {statsUint("created_at"), number("value")})})
             .desc("Trend series (visual/graph variants): at most 3, each the most recent 64 points."),
         objectArray("warnings", "DashboardIssueSummary"), objectArray("errors", "DashboardIssueSummary"),
         statsCheckedAt()}));

    out.push_back(model("DashboardSectionSummary",
        "One dashboard section (core/src/stats/model/DashboardOverview.cpp to_json).",
        {str("id"), str("title"), str("description"), str("href"), str("severity"), statsUint("warning_count"),
         statsUint("error_count"), str("summary"), objectArray("metrics", "DashboardMetricSummary"),
         objectArray("warnings", "DashboardIssueSummary"), objectArray("errors", "DashboardIssueSummary"),
         statsCheckedAt()}));

    out.push_back(model("DashboardOverview",
        "The health dashboard (core/src/stats/model/DashboardOverview.cpp to_json).",
        {str("overall_status"), statsUint("warning_count"), statsUint("error_count"), statsCheckedAt(),
         objectArray("attention", "",
                     {str("code"), str("severity"), str("card_id"), str("title"), str("message"),
                      statsNullable(str("href")), statsNullable(str("metric_key"))}),
         objectArray("sections", "DashboardSectionSummary"), objectArray("cards", "DashboardCardSummary")}));

    out.push_back(model("DashboardSeverity",
        "The overview's overall severity only (core/src/stats/model/DashboardOverview.cpp dashboardSeverityJson).",
        {str("overall_status"), statsUint("error_count"), statsUint("warning_count"), statsCheckedAt()}));

    out.push_back(model("DashboardPreference",
        "A user's saved dashboard layout (core/src/stats/model/DashboardPreferences.cpp to_json).",
        {statsNullable(statsUint("id")).desc("null when nothing is saved (exists false)."), statsUint("user_id"),
         str("preference_key"),
         object("layout", "",
                {objectArray("cards", "",
                             {str("id").desc("1..128 characters."), str("size").opt().nullable(),
                              str("variant").opt().nullable(), boolean("visible").opt().nullable(),
                              uinteger("order").opt().nullable().max(100000)})
                     .opt()
                     .desc("Validated on save: at most 64 cards.")})
             .desc("As saved ({} when none): the server validates the members listed here; other members of the "
                   "layout and of each card are stored and returned as the client sent them."),
         statsNullable(statsUint("created_at")), statsNullable(statsUint("updated_at")), boolean("exists")}));

    return out;
}

}

std::vector<WsModel> statsModels() {
    std::vector<WsModel> out;
    for (auto&& part : {statsVaultModels(), statsSystemModels(), statsDashboardModels()})
        out.insert(out.end(), std::make_move_iterator(part.begin()), std::make_move_iterator(part.end()));
    return out;
}

}
