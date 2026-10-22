#pragma once

#include "log/Rotator.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <spdlog/common.h> // spdlog::level::level_enum only
#include "compat/fmt_extern.hpp"
#include <nlohmann/json_fwd.hpp>
#include <chrono>

namespace vh::config {

constexpr static uintmax_t MAX_UPLOAD_SIZE_BYTES = static_cast<uintmax_t>(2) * 1024 * 1024 * 1024; // 2GB
constexpr static uintmax_t MAX_PREVIEW_SIZE_BYTES = 100 * 1024 * 1024;        // 100MB

struct WebsocketConfig {
    bool enabled = true;
    std::string host = "0.0.0.0";
    uint16_t port = 33369;
    unsigned int max_connections = 1024;
    uintmax_t max_upload_size_bytes = MAX_UPLOAD_SIZE_BYTES;
};

struct HttpPreviewConfig {
    bool enabled = true;
    std::string host = "0.0.0.0";
    uint16_t port = 33370;
    unsigned int max_connections = 512;
    uintmax_t max_preview_size_bytes = MAX_PREVIEW_SIZE_BYTES;
};

// The device listener (Vaulthalla Desktop's mutual-TLS endpoint, docs/pairing.md). There is no host: it listens on
// loopback until remote connections are turned on (`vh device remote enable`, ws device.remote.enable), then on every
// interface. That switch is the only setting operators change, and they change it through those commands.
inline constexpr uint16_t kDefaultDeviceServerPort = 36972;

struct DeviceServerConfig {
    bool enabled = true;
    uint16_t port = kDefaultDeviceServerPort;
    bool remote = false;
    unsigned int max_connections = 256;
};

struct S3GatewayMultipartConfig {
    uint32_t min_part_size_mb = 5;
    uint32_t abort_after_days = 7;
};

struct S3GatewaySyntheticLocalRequestCostConfig {
    std::string list = "0.00000001";
    std::string head = "0.00000001";
    std::string get = "0.00000001";
    std::string put = "0.00000001";
    std::string delete_ = "0.00000001";
    std::string copy = "0.00000001";
    std::string downloaded_gb = "0.00000000";
    std::string uploaded_gb = "0.00000000";
};

struct S3GatewayConfig {
    bool enabled = false;
    std::string host = "0.0.0.0";
    uint16_t port = 39000;
    unsigned int max_connections = 1024;
    uintmax_t max_body_size_bytes = 5ull * 1024ull * 1024ull * 1024ull;
    bool require_sigv4 = true;
    bool allow_path_style = true;
    bool allow_virtual_hosted_style = true;
    std::string default_bucket_mode = "local";
    bool default_api_exclusive = true;
    // default_remote_sync_strategy / default_remote_conflict_policy moved to vaults.s3 (#164); config.yaml still
    // accepts them here as deprecated aliases (loadConfig).
    S3GatewayMultipartConfig multipart;
    S3GatewaySyntheticLocalRequestCostConfig synthetic_local_request_cost_usd;
};

struct ThumbnailsConfig {
    std::vector<std::string> formats = {"jpg", "jpeg", "png", "webp", "pdf"};
    std::vector<unsigned int> sizes = {128, 256, 512};
    unsigned int expiry_days = 30;
};

struct CachingConfig {
    unsigned int max_size_mb = 10240;
    ThumbnailsConfig thumbnails;
};

// preview.* (all optional; a missing key keeps its default).
enum class PreviewIntegrityMode { Optimistic, Strict };
enum class PreviewRemoteMode { Hydrate, Ranged, Off };
enum class PreviewHwaccel { Auto, Software, Vaapi, Qsv, Nvenc };
enum class PreviewTranscodeMode { Off, OnDemand };

struct PreviewMediaConfig {
    PreviewIntegrityMode integrity = PreviewIntegrityMode::Optimistic;
    PreviewRemoteMode remote = PreviewRemoteMode::Hydrate;
    PreviewHwaccel hwaccel = PreviewHwaccel::Auto;
    PreviewTranscodeMode transcode = PreviewTranscodeMode::OnDemand;
};

// Out-of-process converters (preview::derive). Helpers are separate executables in optional packages.
struct PreviewDeriveConfig {
    std::filesystem::path helper_dir = "/usr/lib/vaulthalla/helpers";
    uint32_t max_concurrency = 2;
    uint32_t max_queue = 64;
    uint32_t max_ram_mb = 2048;            // RLIMIT_AS per helper
    uint32_t max_cpu_seconds = 300;        // RLIMIT_CPU per helper
    uint32_t wall_timeout_seconds = 600;   // SIGKILL of the helper's process group
    uint32_t max_output_mb = 512;          // artifact size cap
    uint32_t failure_ttl_hours = 24;       // negative-cache lifetime (or until the source changes)
};

struct PreviewTextConfig {
    uint64_t max_edit_bytes = 2ull * 1024 * 1024;
};

struct PreviewConfig {
    PreviewMediaConfig media;
    PreviewDeriveConfig derive;
    PreviewTextConfig text;
    uint64_t max_render_pixels = 64'000'000;  // source pixels (progressive JPEGs: half)
};

struct DatabaseConfig {
    std::string host = "localhost";
    uint16_t port = 5432;
    std::string name = "vaulthalla";
    std::string user = "vaulthalla";
    int pool_size = 10;
};

struct AuthConfig {
    unsigned int access_token_expiry_minutes = 60;
    unsigned int refresh_token_expiry_days = 7;
};

struct SyncConfig {
    uint32_t event_audit_retention_days = 30;
    uint32_t event_audit_max_entries = 10000;
};

struct StorageRatesApiConfig {
    bool remote_refresh_enabled = false;
    std::string base_url = "https://storage-rates-api.vaulthalla.cloud";
    uint32_t timeout_ms = 5000;
    uint32_t cache_ttl_seconds = 43200;
    uint32_t refresh_interval_seconds = 43200;
    bool fail_open = true;
    bool signature_warning_only = true;
    std::optional<std::filesystem::path> signature_public_key_path;
    std::vector<std::string> fallback_artifact_base_urls;
    bool prefer_full_catalog = true;
    bool use_remote_estimator_for_debug = false;
};

struct PricingConfig {
    bool enabled = true;
    StorageRatesApiConfig storage_rates_api;
};

struct DBSweeperConfig {
    uint32_t sweep_interval_minutes = 60;
};

struct ConnectionLifecycleManagerConfig {
    uint32_t idle_timeout_minutes = 30;
    uint32_t unauthenticated_timeout_seconds = 60;
    uint32_t sweep_interval_seconds = 60;
};

struct StatsSnapshotsConfig {
    bool enabled = true;
    uint32_t runtime_interval_seconds = 60;
    uint32_t gauge_observation_interval_seconds = 3;
    uint32_t vault_interval_seconds = 3600;
    uint32_t retention_days = 30;
};

struct ServicesConfig {
    DBSweeperConfig db_sweeper;
    ConnectionLifecycleManagerConfig connection_lifecycle_manager;
};

// sharing.* (#164), enforced by share::policy at link creation and on every use of a link.
// enabled is the wide gate: off, no link can be created, opened or used. Each enable_* gates one kind of link:
// enable_anonymous: access_mode "public" (anyone with the link); enable_email_validated: access_mode
// "email_validated" (recipient proves an invited address). Access for signed-in vault users is RBAC policy, not a
// share switch. config.yaml still accepts enable_public_links as a deprecated alias of enable_email_validated.
struct SharingConfig {
    bool enabled = true;
    bool enable_anonymous = true;
    bool enable_email_validated = true;
};

// vaults.s3.*: defaults for S3/R2 (remote) vaults, used when a vault is created without an explicit sync strategy
// or conflict policy. Lowercase spellings of sync::model::RemotePolicy (validated here, parsed by ops::vaults).
struct VaultsS3Config {
    std::string default_remote_sync_strategy = "cache";        // cache | sync | mirror
    std::string default_remote_conflict_policy = "ask";        // ask | keep_local | keep_remote | keep_newest (#187)
    // Key retention for S3-backed vaults (#162): their data may stay in the bucket, so the key is kept longer.
    std::chrono::seconds tpm_retention_window = std::chrono::days(180);
};

// vaults.* retention (#162). Durations are config duration strings ("30s", "5m", "12h", "90d", "2w"; util.hpp). A
// window applies to vaults deleted after it changes: each deletion records its own purge and key-retention deadlines.
struct VaultsConfig {
    // A deleted vault can be restored for this long; then its local data (and upstream data, when chosen) is purged.
    std::chrono::seconds retention_window = std::chrono::minutes(5);
    // How long a deleted vault's sealed key is kept (always the full period, even for "delete now").
    std::chrono::seconds tpm_retention_window = std::chrono::days(90);
    VaultsS3Config s3;
};

enum class EmailProviderKind {
    None,
    Resend,
    Ses
};

struct ResendEmailConfig {
    std::string endpoint = "https://api.resend.com/emails";
};

struct SesEmailConfig {
    std::string region = "us-east-1";
    std::optional<std::string> endpoint;
};

struct EmailConfig {
    bool enabled = false;
    EmailProviderKind provider = EmailProviderKind::None;
    std::string from = "Vaulthalla <ops@example.com>";
    std::optional<std::string> reply_to;
    std::optional<std::string> base_url;
    ResendEmailConfig resend;
    SesEmailConfig ses;
};

struct OperatorEmailRecipientsConfig {
    std::vector<std::string> alerts;
    std::vector<std::string> weekly;
    std::vector<std::string> security;
};

struct OperatorEmailAlertingConfig {
    bool enabled = true;
    std::string min_severity = "warning";
    uint32_t dedupe_window_minutes = 60;
    uint32_t repeat_after_hours = 24;
    bool send_recovery = true;
    uint32_t health_poll_seconds = 60;
};

struct OperatorEmailDigestConfig {
    bool enabled = true;
    std::string weekday = "monday";
    uint32_t hour_local = 8;
    std::string timezone = "UTC";
};

struct OperatorEmailSecurityAlertsConfig {
    bool enabled = true;
    bool admin_role_changes = true;
};

struct OperatorEmailsConfig {
    bool enabled = true;
    OperatorEmailRecipientsConfig recipients;
    OperatorEmailAlertingConfig alerting;
    OperatorEmailDigestConfig weekly_digest;
    OperatorEmailSecurityAlertsConfig security_alerts;
};

struct AuditLogConfig {
    std::chrono::days retention_days = std::chrono::days(30);
    uintmax_t rotate_max_size = 50 * 1024 * 1024; // 50MB
    std::chrono::hours rotate_interval = std::chrono::hours(24);
    log::Rotator::Compression compression = log::Rotator::Compression::Zstd;
    uintmax_t max_retained_logs_size = 1024 * 1024 * 1024; // 1GB
    bool strict_retention = false; // If true, retain logs for full retention days minimum, even if over the size limit
};

struct EncryptionWaiverConfig {
    std::chrono::days retention_days = std::chrono::days(180);
};

struct FilesTrashedConfig {
    std::chrono::days retention_days = std::chrono::days(60);
};

struct AuditConfig {
    AuditLogConfig audit_log;
    EncryptionWaiverConfig encryption_waivers;
    FilesTrashedConfig files_trashed;
};

// The host's FUSE mount (platform/Mount.hpp, fuse/Service.hpp). A property of the installation, not a console setting:
// read from config.yaml when present, never written back or exposed through settings.
struct MountConfig {
    std::string mode;  // disabled | service_private | multiuser; empty = this build's default (Linux: multiuser)
};

struct DevConfig {
    bool enabled = false;
};

struct SubsystemLogLevelsConfig {
    spdlog::level::level_enum vaulthalla   = spdlog::level::info;   // Top-level events like startup/shutdown
    spdlog::level::level_enum fuse         = spdlog::level::warn;   // Don’t log every op; only surface permission or IO failures
    spdlog::level::level_enum filesystem   = spdlog::level::warn;   // Only structural errors or corruption
    spdlog::level::level_enum crypto       = spdlog::level::warn;   // Rare; surface failure to encrypt/decrypt
    spdlog::level::level_enum cloud        = spdlog::level::warn;   // AWS/S3 errors, not routine syncs
    spdlog::level::level_enum auth         = spdlog::level::warn;   // Failed logins, token errors
    spdlog::level::level_enum websocket    = spdlog::level::warn;   // Auth failures, closed sockets, hijack attempts
    spdlog::level::level_enum http         = spdlog::level::warn;   // 5xx, invalid auth, etc.
    spdlog::level::level_enum shell        = spdlog::level::warn;   // CLI parsing edge cases or override violations
    spdlog::level::level_enum db           = spdlog::level::err;    // Only if DB is unreachable, failed tx, corruption
    spdlog::level::level_enum sync         = spdlog::level::warn;   // Conflict resolution issues, failed upload/download
    spdlog::level::level_enum thumb        = spdlog::level::warn;   // Failed renders only
    spdlog::level::level_enum storage      = spdlog::level::warn;   // Underlying I/O issues
    spdlog::level::level_enum types        = spdlog::level::err;    // Violations of invariants or schema errors
    spdlog::level::level_enum runtime      = spdlog::level::warn;   // Runtime service manager
};

struct LogLevelsConfig {
    spdlog::level::level_enum console_log_level = spdlog::level::info;
    spdlog::level::level_enum file_log_level = spdlog::level::warn;
    SubsystemLogLevelsConfig subsystem_levels;
};

struct LoggingConfig {
    LogLevelsConfig levels;
};

struct Config {
    WebsocketConfig websocket;
    HttpPreviewConfig http_preview;
    S3GatewayConfig s3_gateway;
    DeviceServerConfig device_server;
    CachingConfig caching;
    PreviewConfig preview;
    DatabaseConfig database;
    AuthConfig auth;
    SyncConfig sync;
    PricingConfig pricing;
    ServicesConfig services;
    StatsSnapshotsConfig stats_snapshots;
    SharingConfig sharing;
    VaultsConfig vaults;
    EmailConfig email;
    OperatorEmailsConfig operator_emails;
    AuditConfig auditing;
    DevConfig dev;
    MountConfig mount;

    LoggingConfig logging; // internal only

    // Out of line (Config.cpp): the implicit versions were emitted in every translation unit that copied or
    // destroyed a Config (~18 of them).
    Config();
    ~Config();
    Config(const Config&);
    Config(Config&&) noexcept;
    Config& operator=(const Config&);
    Config& operator=(Config&&) noexcept;

    void save() const;
};

// Deprecated keys found while loading (one message each, e.g. a renamed key). The daemon logs them once at startup,
// after the log registry is up; config is loaded before logging, so loadConfig itself never logs.
Config loadConfig(const std::string& path, std::vector<std::string>* deprecations = nullptr);
// Accepted spellings for vaults.s3.* (and the per-vault sync settings they default).
bool isRemoteSyncStrategy(std::string_view value);
bool isRemoteConflictPolicy(std::string_view value);
std::string emailProviderKindToString(EmailProviderKind kind);
EmailProviderKind emailProviderKindFromString(std::string_view value);
// Lowercase config spellings; the parsers throw std::invalid_argument on an unknown value.
std::string previewIntegrityModeToString(PreviewIntegrityMode mode);
PreviewIntegrityMode previewIntegrityModeFromString(std::string_view value);
std::string previewRemoteModeToString(PreviewRemoteMode mode);
PreviewRemoteMode previewRemoteModeFromString(std::string_view value);
std::string previewHwaccelToString(PreviewHwaccel hwaccel);
PreviewHwaccel previewHwaccelFromString(std::string_view value);
std::string previewTranscodeModeToString(PreviewTranscodeMode mode);
PreviewTranscodeMode previewTranscodeModeFromString(std::string_view value);
void to_json(nlohmann::json& j, const Config& c);
void from_json(const nlohmann::json& j, Config& c);
void to_json(nlohmann::json& j, const WebsocketConfig& c);
void from_json(const nlohmann::json& j, WebsocketConfig& c);
void to_json(nlohmann::json& j, const HttpPreviewConfig& c);
void from_json(const nlohmann::json& j, HttpPreviewConfig& c);
void to_json(nlohmann::json& j, const DeviceServerConfig& c);
void from_json(const nlohmann::json& j, DeviceServerConfig& c);
void to_json(nlohmann::json& j, const S3GatewayMultipartConfig& c);
void from_json(const nlohmann::json& j, S3GatewayMultipartConfig& c);
void to_json(nlohmann::json& j, const S3GatewaySyntheticLocalRequestCostConfig& c);
void from_json(const nlohmann::json& j, S3GatewaySyntheticLocalRequestCostConfig& c);
void to_json(nlohmann::json& j, const S3GatewayConfig& c);
void from_json(const nlohmann::json& j, S3GatewayConfig& c);
void to_json(nlohmann::json& j, const LogLevelsConfig& c);
void from_json(const nlohmann::json& j, LogLevelsConfig& c);
void to_json(nlohmann::json& j, const SubsystemLogLevelsConfig& c);
void from_json(const nlohmann::json& j, SubsystemLogLevelsConfig& c);
void to_json(nlohmann::json& j, const LoggingConfig& c);
void from_json(const nlohmann::json& j, LoggingConfig& c);
void to_json(nlohmann::json& j, const ThumbnailsConfig& c);
void from_json(const nlohmann::json& j, ThumbnailsConfig& c);
void to_json(nlohmann::json& j, const CachingConfig& c);
void from_json(const nlohmann::json& j, CachingConfig& c);
void to_json(nlohmann::json& j, const PreviewMediaConfig& c);
void from_json(const nlohmann::json& j, PreviewMediaConfig& c);
void to_json(nlohmann::json& j, const PreviewDeriveConfig& c);
void from_json(const nlohmann::json& j, PreviewDeriveConfig& c);
void to_json(nlohmann::json& j, const PreviewTextConfig& c);
void from_json(const nlohmann::json& j, PreviewTextConfig& c);
void to_json(nlohmann::json& j, const PreviewConfig& c);
void from_json(const nlohmann::json& j, PreviewConfig& c);
void to_json(nlohmann::json& j, const DatabaseConfig& c);
void from_json(const nlohmann::json& j, DatabaseConfig& c);
void to_json(nlohmann::json& j, const AuthConfig& c);
void from_json(const nlohmann::json& j, AuthConfig& c);
void to_json(nlohmann::json& j, const SyncConfig& c);
void from_json(const nlohmann::json& j, SyncConfig& c);
void to_json(nlohmann::json& j, const StorageRatesApiConfig& c);
void from_json(const nlohmann::json& j, StorageRatesApiConfig& c);
void to_json(nlohmann::json& j, const PricingConfig& c);
void from_json(const nlohmann::json& j, PricingConfig& c);
void to_json(nlohmann::json& j, const DBSweeperConfig& c);
void from_json(const nlohmann::json& j, DBSweeperConfig& c);
void to_json(nlohmann::json& j, const ConnectionLifecycleManagerConfig& c);
void from_json(const nlohmann::json& j, ConnectionLifecycleManagerConfig& c);
void to_json(nlohmann::json& j, const StatsSnapshotsConfig& c);
void from_json(const nlohmann::json& j, StatsSnapshotsConfig& c);
void to_json(nlohmann::json& j, const ServicesConfig& c);
void from_json(const nlohmann::json& j, ServicesConfig& c);
void to_json(nlohmann::json& j, const SharingConfig& c);
void from_json(const nlohmann::json& j, SharingConfig& c);
void to_json(nlohmann::json& j, const VaultsS3Config& c);
void from_json(const nlohmann::json& j, VaultsS3Config& c);
void to_json(nlohmann::json& j, const VaultsConfig& c);
void from_json(const nlohmann::json& j, VaultsConfig& c);
void to_json(nlohmann::json& j, const ResendEmailConfig& c);
void from_json(const nlohmann::json& j, ResendEmailConfig& c);
void to_json(nlohmann::json& j, const SesEmailConfig& c);
void from_json(const nlohmann::json& j, SesEmailConfig& c);
void to_json(nlohmann::json& j, const EmailConfig& c);
void from_json(const nlohmann::json& j, EmailConfig& c);
void to_json(nlohmann::json& j, const OperatorEmailRecipientsConfig& c);
void from_json(const nlohmann::json& j, OperatorEmailRecipientsConfig& c);
void to_json(nlohmann::json& j, const OperatorEmailAlertingConfig& c);
void from_json(const nlohmann::json& j, OperatorEmailAlertingConfig& c);
void to_json(nlohmann::json& j, const OperatorEmailDigestConfig& c);
void from_json(const nlohmann::json& j, OperatorEmailDigestConfig& c);
void to_json(nlohmann::json& j, const OperatorEmailSecurityAlertsConfig& c);
void from_json(const nlohmann::json& j, OperatorEmailSecurityAlertsConfig& c);
void to_json(nlohmann::json& j, const OperatorEmailsConfig& c);
void from_json(const nlohmann::json& j, OperatorEmailsConfig& c);
void to_json(nlohmann::json& j, const AuditLogConfig& c);
void from_json(const nlohmann::json& j, AuditLogConfig& c);
void to_json(nlohmann::json& j, const EncryptionWaiverConfig& c);
void from_json(const nlohmann::json& j, EncryptionWaiverConfig& c);
void to_json(nlohmann::json& j, const FilesTrashedConfig& c);
void from_json(const nlohmann::json& j, FilesTrashedConfig& c);
void to_json(nlohmann::json& j, const AuditConfig& c);
void from_json(const nlohmann::json& j, AuditConfig& c);
void to_json(nlohmann::json& j, const DevConfig& c);
void from_json(const nlohmann::json& j, DevConfig& c);

} // namespace vh::config
