// ws models: admin — S3 price budgets (storage::s3::pricing), the settings document (config::Config) and the
// operator email delivery history.

#include "models.hpp"

namespace vh::contract::ws::detail {

namespace {

// ---- price budgets (core/src/storage/s3/pricing/PriceBudget.cpp, to_json) ----------------------------------------

const std::vector<std::string>& adminBudgetScopes() {
    static const std::vector<std::string> v{"global", "provider", "vault", "gateway_credential",
                                            "gateway_credential_vault"};
    return v;
}

const std::vector<std::string>& adminBudgetModes() {
    static const std::vector<std::string> v{"off", "report", "warn", "enforce"};
    return v;
}

const std::vector<std::string>& adminBudgetWindows() {
    static const std::vector<std::string> v{"per_run", "daily", "monthly"};
    return v;
}

const std::vector<std::string>& adminNotificationSeverities() {
    static const std::vector<std::string> v{"info", "warning", "error", "critical"};
    return v;
}

WsField adminDecimal(std::string name) { return str(std::move(name)).desc("Decimal string (8 fractional digits)."); }

WsField adminDbTime(std::string name) { return str(std::move(name)).desc("PostgreSQL timestamp text."); }

std::vector<WsModel> adminBudgetModels() {
    std::vector<WsModel> out;

    out.push_back(model("PriceBudgetPolicy",
        "An S3 price budget policy (PriceBudget.cpp to_json(PriceBudgetPolicy)). Costs are decimal strings; null "
        "means no limit for that window.",
        {uinteger("id"), str("scope").oneOf(adminBudgetScopes()), str("provider_key").nullable(),
         uinteger("vault_id").nullable(), uinteger("gateway_credential_id").nullable(),
         str("mode").oneOf(adminBudgetModes()), str("currency"), adminDecimal("max_run_cost").nullable(),
         adminDecimal("max_daily_cost").nullable(), adminDecimal("max_monthly_cost").nullable(),
         boolean("require_verified_catalog"), boolean("allow_stale_catalog"),
         integer("max_catalog_age_seconds").nullable(), boolean("is_active")}));

    out.push_back(model("PriceBudgetWindowCheck",
        "One policy window evaluated by a budget decision (PriceBudget.cpp to_json(PriceBudgetWindowCheck)).",
        {uinteger("policy_id"), str("scope").oneOf(adminBudgetScopes()), str("mode").oneOf(adminBudgetModes()),
         str("window").oneOf(adminBudgetWindows()), str("currency"),
         adminDecimal("limit").nullable().desc("Null: the window has no limit."), adminDecimal("used_before"),
         adminDecimal("remaining_before"), adminDecimal("requested"), boolean("exceeded")}));

    out.push_back(model("PriceBudgetDecision",
        "A price budget preflight decision (PriceBudget.cpp to_json(PriceBudgetDecision)). The exceeded_* and "
        "primary_blocking_* strings are empty when nothing blocks.",
        {boolean("allowed"), boolean("stalled"), strArray("warnings"), uinteger("exceeded_policy_id").nullable(),
         str("exceeded_scope"), str("limit"), str("used_before"), str("remaining_before"), str("requested"),
         str("currency"), str("reason"), objectArray("policies", "PriceBudgetPolicy"),
         objectArray("checks", "PriceBudgetWindowCheck"), objectArray("blocking_checks", "PriceBudgetWindowCheck"),
         intArray("blocking_policy_ids"), object("primary_blocking_check", "PriceBudgetWindowCheck").nullable(),
         str("primary_blocking_scope"), str("primary_blocking_window")}));

    out.push_back(model("PriceBudgetLedgerEntry",
        "A budget reservation ledger row (PriceBudget.cpp to_json(PriceBudgetLedgerEntry)).",
        {uinteger("id"), uinteger("policy_id"), str("run_uuid"), uinteger("vault_id"),
         uinteger("gateway_credential_id").nullable(), str("request_uuid").nullable(), str("operation").nullable(),
         str("object_key").nullable(), adminDecimal("estimated_cost").nullable(), str("usage_source").nullable(),
         boolean("synthetic"), str("provider_key"), str("currency"), str("window").oneOf(adminBudgetWindows()),
         adminDbTime("window_start"), adminDbTime("window_end"), adminDecimal("reserved_cost"),
         adminDecimal("committed_cost").nullable(),
         str("status").oneOf({"reserved", "committed", "released", "expired"}), adminDbTime("created_at")}));

    out.push_back(model("PriceBudgetNotification",
        "An operator (cost alert) notification (PriceBudget.cpp to_json(PriceBudgetNotification)).",
        {uinteger("id"), str("type"), str("severity").oneOf(adminNotificationSeverities()), str("title"),
         str("message"), str("scope").nullable(), uinteger("vault_id").nullable(), str("provider_key").nullable(),
         uinteger("policy_id").nullable(), str("run_uuid").nullable(),
         object("metadata").desc("Free-form details recorded with the alert ({} when none); keys vary by type."),
         adminDbTime("acknowledged_at").nullable(), uinteger("acknowledged_by").nullable(), adminDbTime("created_at"),
         adminDbTime("expires_at").nullable()}));

    out.push_back(model("PriceBudgetNotificationSummary",
        "Open (unacknowledged, unexpired) alerts in scope (PriceBudget.cpp to_json(PriceBudgetNotificationSummary)); "
        "worst_severity is null when nothing is open.",
        {uinteger("open_count"), str("worst_severity").nullable().oneOf(adminNotificationSeverities())}));

    out.push_back(model("PriceBudgetOverride",
        "A one-time budget override request (PriceBudget.cpp to_json(PriceBudgetOverride)).",
        {uinteger("id"), str("run_uuid").nullable(), uinteger("vault_id"), uinteger("requested_by").nullable(),
         uinteger("approved_by").nullable(),
         str("status").oneOf({"requested", "approved", "denied", "expired", "used", "cancelled"}),
         str("reason").nullable(), str("scope").desc("\"single_run\"."), intArray("policy_ids"),
         adminDecimal("estimated_cost").nullable(), str("currency"), adminDbTime("expires_at"),
         adminDbTime("created_at"), adminDbTime("decided_at").nullable(), adminDbTime("used_at").nullable()}));

    out.push_back(model("PriceBudgetTrendStats",
        "Spend and projection for one policy window (PriceBudget.cpp to_json(PriceBudgetTrendStats)).",
        {str("scope"), str("provider_key").nullable(), uinteger("vault_id").nullable(),
         uinteger("gateway_credential_id").nullable(), uinteger("policy_id"), str("currency"),
         str("window_type").oneOf(adminBudgetWindows()), adminDbTime("window_start"), adminDbTime("window_end"),
         adminDecimal("committed_cost"), adminDecimal("reserved_cost"), adminDecimal("total_cost"),
         adminDecimal("limit").nullable(), adminDecimal("remaining").nullable(), number("percent_used"),
         adminDecimal("projected_window_cost").nullable(), adminDecimal("projected_overage").nullable(),
         str("predicted_exhaustion_at").nullable(), str("confidence"), adminDecimal("recent_daily_average"),
         adminDecimal("recent_7d_average"), adminDecimal("recent_30d_average"), strArray("warnings")}));

    out.push_back(model("PriceBudgetDashboardStats",
        "The price budget dashboard (PriceBudget.cpp to_json(PriceBudgetDashboardStats)). The monthly spends are "
        "null when no monthly budget window (or projection) exists: not measured, never a fake zero.",
        {uinteger("active_policies"), uinteger("blocked_syncs_24h"), uinteger("warning_notifications"),
         uinteger("critical_notifications"), uinteger("unacknowledged_notifications"), uinteger("pending_overrides"),
         adminDecimal("current_monthly_spend").nullable(), adminDecimal("projected_monthly_spend").nullable(),
         str("currency"), objectArray("trends", "PriceBudgetTrendStats"),
         objectArray("active_notifications", "PriceBudgetNotification"),
         objectArray("recent_overrides", "PriceBudgetOverride")}));

    // ---- price estimates (core/src/storage/s3/pricing/PriceBotModels.cpp, LocalEstimator.cpp) ----
    out.push_back(model("PriceProfileTarget",
        "The price profile an estimate rates against (PriceBotModels.cpp to_json(PriceProfileTarget)).",
        {str("provider"), str("region"), str("storage_class"), str("profile_id")}));

    out.push_back(model("PriceEstimateBreakdownItem",
        "One metered line of an estimate (LocalEstimator.cpp makeBreakdown). Quantities, rates and cost are decimal "
        "strings. (A daemon configured with pricing.storage_rates_api.use_remote_estimator_for_debug passes the "
        "remote estimator's lines through instead.)",
        {str("meter_key"), str("quantity"), str("billable_quantity"), str("unit"), str("rate"), str("rate_unit"),
         str("cost"), strArray("notes")}));

    out.push_back(model("PriceEstimateReport",
        "An S3 cost estimate (PriceBotModels.cpp to_json(PriceEstimateReport)). estimated_cost and currency are null "
        "unless available; unavailable_reason says why not.",
        {boolean("available"), boolean("supported"), boolean("stale"), object("target", "PriceProfileTarget"),
         adminDecimal("estimated_cost").nullable(), str("currency").nullable(), str("price_profile_id").nullable(),
         str("catalog_version").nullable(), str("catalog_source").nullable(), boolean("catalog_verified"),
         integer("catalog_age_seconds").nullable(), str("confidence_level").nullable(),
         str("estimate_mode").nullable(), str("free_tier_policy").nullable(),
         boolean("free_tiers_applied").nullable(), strArray("unknowns"),
         objectArray("breakdown", "PriceEstimateBreakdownItem"), str("unavailable_reason").nullable()}));

    return out;
}

// ---- settings (core/src/config/Config.cpp, to_json) ----------------------------------------------------------------

WsField adminLogLevel(std::string name) {
    return uinteger(std::move(name)).max(6).desc("spdlog level number: 0 trace, 1 debug, 2 info, 3 warn, 4 err, "
                                                 "5 critical, 6 off.");
}

std::vector<WsModel> adminSettingsModels() {
    std::vector<WsModel> out;

    out.push_back(model("Settings",
        "The daemon's settings document: config.yaml as JSON without secrets (config::Config, Config.cpp to_json).",
        {object("websocket_server", "WebsocketServerConfig"), object("http_preview_server", "HttpPreviewServerConfig"),
         object("s3_gateway", "S3GatewayConfig"), object("device_server", "DeviceServerConfig"),
         object("caching", "CachingConfig"),
         object("preview", "PreviewConfig"), object("database", "DatabaseConfig"), object("auth", "AuthConfig"),
         object("sync", "SyncConfig"), object("pricing", "PricingConfig"), object("services", "ServicesConfig"),
         object("stats_snapshots", "StatsSnapshotsConfig"), object("sharing", "SharingConfig"),
         object("vaults", "VaultsConfig"), object("email", "EmailConfig"),
         object("operator_emails", "OperatorEmailsConfig"), object("auditing", "AuditConfig"),
         object("logging", "LoggingConfig"), object("dev", "DevConfig"),
         object("transfer", "TransferConfig")}));

    out.push_back(model("WebsocketServerConfig", "websocket_server.* (Config.cpp to_json(WebsocketConfig)).",
        {boolean("enabled"), str("host"), uinteger("port").max(65535), uinteger("max_connections"),
         uinteger("max_upload_size_bytes")}));
    out.push_back(model("HttpPreviewServerConfig", "http_preview_server.* (Config.cpp to_json(HttpPreviewConfig)).",
        {boolean("enabled"), str("host"), uinteger("port").max(65535), uinteger("max_connections"),
         uinteger("max_preview_size_bytes")}));

    out.push_back(model("DeviceServerConfig",
        "device_server.* (Config.cpp to_json(DeviceServerConfig)): the device listener. remote is changed with "
        "device.remote.enable|disable; a settings.update that changes the section rebinds the listener in place.",
        {boolean("enabled"), uinteger("port").max(65535),
         boolean("remote").desc("Every interface; else loopback only."), uinteger("max_connections")}));

    out.push_back(model("S3GatewayConfig", "s3_gateway.* (Config.cpp to_json(S3GatewayConfig)).",
        {boolean("enabled"), str("host"), uinteger("port").max(65535), uinteger("max_connections"),
         uinteger("max_body_size_bytes"), boolean("require_sigv4"), boolean("allow_path_style"),
         boolean("allow_virtual_hosted_style"), str("default_bucket_mode"), boolean("default_api_exclusive"),
         object("multipart", "S3GatewayMultipartConfig"),
         object("synthetic_local_request_cost_usd", "S3GatewaySyntheticLocalRequestCostConfig")}));
    out.push_back(model("S3GatewayMultipartConfig",
        "s3_gateway.multipart.* (Config.cpp to_json(S3GatewayMultipartConfig)).",
        {uinteger("min_part_size_mb"), uinteger("abort_after_days")}));
    out.push_back(model("S3GatewaySyntheticLocalRequestCostConfig",
        "s3_gateway.synthetic_local_request_cost_usd.*: USD decimal strings per request kind and per GB "
        "(Config.cpp to_json(S3GatewaySyntheticLocalRequestCostConfig)).",
        {str("list"), str("head"), str("get"), str("put"), str("delete"), str("copy"), str("downloaded_gb"),
         str("uploaded_gb")}));

    out.push_back(model("CachingConfig", "caching.* (Config.cpp to_json(CachingConfig)).",
        {object("thumbnails", "ThumbnailsConfig"), uinteger("max_size_mb")}));
    out.push_back(model("ThumbnailsConfig", "caching.thumbnails.* (Config.cpp to_json(ThumbnailsConfig)).",
        {strArray("formats"), WsField{.name = "sizes", .types = {"array"}, .items = "integer"},
         uinteger("expiry_days")}));

    out.push_back(model("PreviewConfig", "preview.* (Config.cpp to_json(PreviewConfig)).",
        {object("media", "PreviewMediaConfig"), object("derive", "PreviewDeriveConfig"),
         object("text", "PreviewTextConfig"), uinteger("max_render_pixels")}));
    out.push_back(model("PreviewMediaConfig", "preview.media.* (Config.cpp to_json(PreviewMediaConfig)).",
        {str("integrity").oneOf({"optimistic", "strict"}), str("remote").oneOf({"hydrate", "ranged", "off"}),
         str("hwaccel").oneOf({"auto", "software", "vaapi", "qsv", "nvenc"}),
         str("transcode").oneOf({"off", "on_demand"})}));
    out.push_back(model("PreviewDeriveConfig",
        "preview.derive.* (Config.cpp to_json(PreviewDeriveConfig)). helper_dir is read-only through the API.",
        {str("helper_dir"), uinteger("max_concurrency"), uinteger("max_queue"), uinteger("max_ram_mb"),
         uinteger("max_cpu_seconds"), uinteger("wall_timeout_seconds"), uinteger("max_output_mb"),
         uinteger("failure_ttl_hours")}));
    out.push_back(model("PreviewTextConfig", "preview.text.* (Config.cpp to_json(PreviewTextConfig)).",
        {uinteger("max_edit_bytes")}));

    out.push_back(model("TransferConfig",
        "transfer.* (Config.cpp to_json(TransferConfig)): resumable uploads (/upload/sessions, "
        "docs/reference/transfer-protocol.md). Out-of-range values are refused (invalid), never clamped.",
        {uinteger("part_default_bytes"), uinteger("part_min_bytes").min(1),
         uinteger("max_part_bytes").max(4294967296).desc("Device listener cap."),
         uinteger("max_parts_in_flight").min(1).max(16), uinteger("max_file_bytes").desc("0 = only the format limit."),
         uinteger("max_session_files").min(1).max(65536), uinteger("commit_workers").min(1).max(8),
         uinteger("session_idle_ttl_hours").min(1), uinteger("session_max_age_hours").min(1),
         object("http", "TransferHttpConfig")}));
    out.push_back(model("TransferHttpConfig", "transfer.http.* (Config.cpp to_json(TransferHttpConfig)).",
        {uinteger("max_part_bytes").desc("Web listener cap; keep <= 95000000 behind Cloudflare Free/Pro.")}));

    out.push_back(model("DatabaseConfig",
        "database.* (Config.cpp to_json(DatabaseConfig)); the password is never part of it.",
        {str("host"), uinteger("port").max(65535), str("name"), str("user"), integer("pool_size")}));
    out.push_back(model("AuthConfig", "auth.* (Config.cpp to_json(AuthConfig)); the JWT secret is never part of it.",
        {uinteger("access_token_expiry_minutes"), uinteger("refresh_token_expiry_days")}));
    out.push_back(model("SyncConfig", "sync.* (Config.cpp to_json(SyncConfig)).",
        {uinteger("event_audit_retention_days"), uinteger("event_audit_max_entries")}));

    out.push_back(model("PricingConfig", "pricing.* (Config.cpp to_json(PricingConfig)).",
        {boolean("enabled"), object("storage_rates_api", "StorageRatesApiConfig")}));
    out.push_back(model("StorageRatesApiConfig",
        "pricing.storage_rates_api.* (Config.cpp to_json(StorageRatesApiConfig)).",
        {boolean("remote_refresh_enabled"), str("base_url"), uinteger("timeout_ms"), uinteger("cache_ttl_seconds"),
         uinteger("refresh_interval_seconds"), boolean("fail_open"), boolean("signature_warning_only"),
         str("signature_public_key_path").nullable(), strArray("fallback_artifact_base_urls"),
         boolean("prefer_full_catalog"), boolean("use_remote_estimator_for_debug")}));

    out.push_back(model("ServicesConfig", "services.* (Config.cpp to_json(ServicesConfig)).",
        {object("db_sweeper", "DBSweeperConfig"),
         object("connection_lifecycle_manager", "ConnectionLifecycleManagerConfig")}));
    out.push_back(model("DBSweeperConfig", "services.db_sweeper.* (Config.cpp to_json(DBSweeperConfig)).",
        {uinteger("sweep_interval_minutes")}));
    out.push_back(model("ConnectionLifecycleManagerConfig",
        "services.connection_lifecycle_manager.* (Config.cpp to_json(ConnectionLifecycleManagerConfig)).",
        {uinteger("idle_timeout_minutes"), uinteger("unauthenticated_timeout_seconds"),
         uinteger("sweep_interval_seconds")}));
    out.push_back(model("StatsSnapshotsConfig", "stats_snapshots.* (Config.cpp to_json(StatsSnapshotsConfig)).",
        {boolean("enabled"), uinteger("runtime_interval_seconds"), uinteger("gauge_observation_interval_seconds"),
         uinteger("vault_interval_seconds"), uinteger("retention_days"), uinteger("rollup_5m_retention_days"),
         uinteger("rollup_1h_retention_days")}));

    out.push_back(model("SharingConfig",
        "sharing.*: the share-link switches (Config.cpp to_json(SharingConfig)). enabled gates every link; "
        "enable_anonymous gates access_mode public, enable_email_validated access_mode email_validated.",
        {boolean("enabled"), boolean("enable_anonymous"), boolean("enable_email_validated")}));
    out.push_back(model("VaultsConfig",
        "vaults.*: deleted-vault retention and S3 vault defaults (Config.cpp to_json(VaultsConfig)). Durations are "
        "config duration strings (\"30s\", \"5m\", \"12h\", \"90d\", \"2w\").",
        {str("retention_window"), str("tpm_retention_window"), object("s3", "VaultsS3Config")}));
    out.push_back(model("VaultsS3Config",
        "vaults.s3.*: defaults for new S3/R2 vaults (Config.cpp to_json(VaultsS3Config)).",
        {str("default_remote_sync_strategy").desc("cache | sync | mirror."),
         str("default_remote_conflict_policy").desc("ask | keep_local | keep_remote | keep_newest."),
         str("tpm_retention_window").desc("Config duration string.")}));

    out.push_back(model("EmailConfig", "email.*: the outbound email provider (Config.cpp to_json(EmailConfig)).",
        {boolean("enabled"), str("provider").oneOf({"none", "resend", "ses"}), str("from"),
         str("reply_to").nullable(), str("base_url").nullable(), object("resend", "ResendEmailConfig"),
         object("ses", "SesEmailConfig")}));
    out.push_back(model("ResendEmailConfig",
        "email.resend.* (Config.cpp to_json(ResendEmailConfig)); the API key lives in the secrets manager.",
        {str("endpoint")}));
    out.push_back(model("SesEmailConfig",
        "email.ses.* (Config.cpp to_json(SesEmailConfig)); the credentials live in the secrets manager.",
        {str("region"), str("endpoint").nullable()}));

    out.push_back(model("OperatorEmailsConfig",
        "operator_emails.*: who gets operator email and when (Config.cpp to_json(OperatorEmailsConfig)).",
        {boolean("enabled"), object("recipients", "OperatorEmailRecipientsConfig"),
         object("alerting", "OperatorEmailAlertingConfig"), object("weekly_digest", "OperatorEmailDigestConfig"),
         object("security_alerts", "OperatorEmailSecurityAlertsConfig")}));
    out.push_back(model("OperatorEmailRecipientsConfig",
        "operator_emails.recipients.*: addresses per mail kind (Config.cpp to_json(OperatorEmailRecipientsConfig)).",
        {strArray("alerts"), strArray("weekly"), strArray("security")}));
    out.push_back(model("OperatorEmailAlertingConfig",
        "operator_emails.alerting.* (Config.cpp to_json(OperatorEmailAlertingConfig)).",
        {boolean("enabled"), str("min_severity").desc("info | warning | critical."),
         uinteger("dedupe_window_minutes"), uinteger("repeat_after_hours"), boolean("send_recovery"),
         uinteger("health_poll_seconds")}));
    out.push_back(model("OperatorEmailDigestConfig",
        "operator_emails.weekly_digest.* (Config.cpp to_json(OperatorEmailDigestConfig)).",
        {boolean("enabled"), str("weekday").desc("sunday through saturday."), uinteger("hour_local").max(23),
         str("timezone")}));
    out.push_back(model("OperatorEmailSecurityAlertsConfig",
        "operator_emails.security_alerts.* (Config.cpp to_json(OperatorEmailSecurityAlertsConfig)).",
        {boolean("enabled"), boolean("admin_role_changes")}));

    out.push_back(model("AuditConfig", "auditing.* (Config.cpp to_json(AuditConfig)).",
        {object("audit_log", "AuditLogConfig"), object("encryption_waivers", "EncryptionWaiverConfig"),
         object("files_trashed", "FilesTrashedConfig")}));
    out.push_back(model("AuditLogConfig",
        "auditing.audit_log.* (Config.cpp to_json(AuditLogConfig)). Sizes are \"<n>MB\"/\"<n>GB\", the interval "
        "\"<n>h\"/\"<n>d\".",
        {uinteger("retention_days"), str("rotate_max_size"), str("rotate_interval"),
         str("compression").oneOf({"none", "gzip", "zstd"}), str("max_retained_logs_size"),
         boolean("strict_retention")}));
    out.push_back(model("EncryptionWaiverConfig",
        "auditing.encryption_waivers.* (Config.cpp to_json(EncryptionWaiverConfig)).", {uinteger("retention_days")}));
    out.push_back(model("FilesTrashedConfig", "auditing.files_trashed.* (Config.cpp to_json(FilesTrashedConfig)).",
        {uinteger("retention_days")}));

    out.push_back(model("LoggingConfig", "logging.* (Config.cpp to_json(LoggingConfig)).",
        {object("levels", "LogLevelsConfig")}));
    out.push_back(model("LogLevelsConfig", "logging.levels.* (Config.cpp to_json(LogLevelsConfig)).",
        {adminLogLevel("console_log_level"), adminLogLevel("file_log_level"),
         object("subsystem_levels", "SubsystemLogLevelsConfig")}));
    std::vector<WsField> subsystems;
    for (const auto* s : {"vaulthalla", "filesystem", "crypto", "cloud", "auth", "websocket", "http", "shell", "db",
                          "sync", "thumb", "storage", "types", "runtime"})
        subsystems.push_back(adminLogLevel(s));
    out.push_back(model("SubsystemLogLevelsConfig",
        "logging.levels.subsystem_levels.*: per-subsystem log levels (Config.cpp to_json(SubsystemLogLevelsConfig)).",
        std::move(subsystems)));

    out.push_back(model("DevConfig", "dev.* (Config.cpp to_json(DevConfig)).",
        {boolean("enabled")}));

    return out;
}

// ---- operator email history (core/src/protocols/ws/handler/Email.cpp) ---------------------------------------------

WsModel adminEmailDeliveryRecord() {
    return model("EmailDeliveryRecord",
        "One operator email delivery (Email::deliveryRecordJson, protocols/ws/handler/Email.cpp). Times are ISO-8601 "
        "UTC (\"2026-10-20T12:00:00Z\").",
        {uinteger("id"), str("event_key"), str("event_type"), str("severity"), str("provider"), str("subject"),
         str("recipient_group").nullable(), uinteger("recipient_count"), str("provider_message_id").nullable(),
         str("status").oneOf({"queued", "sent", "failed", "suppressed", "dry_run"}), str("error_summary").nullable(),
         str("fingerprint"), str("first_seen_at"), str("last_seen_at"), str("sent_at").nullable(),
         str("created_at")});
}

}

std::vector<WsModel> adminModels() {
    auto out = adminBudgetModels();
    for (auto& m : adminSettingsModels()) out.push_back(std::move(m));
    out.push_back(adminEmailDeliveryRecord());
    return out;
}

}
