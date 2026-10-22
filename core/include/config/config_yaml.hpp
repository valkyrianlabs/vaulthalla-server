#pragma once

#include "config/Config.hpp"
#include "config/util.hpp"

#include <algorithm>
#include <yaml-cpp/yaml.h>

namespace YAML {

using namespace vh::config;

template<>
struct convert<WebsocketConfig> {
    static Node encode(const WebsocketConfig& rhs) {
        Node node;
        node["enabled"] = rhs.enabled;
        node["host"] = rhs.host;
        node["port"] = rhs.port;
        node["max_connections"] = rhs.max_connections;
        node["max_upload_size_bytes"] = rhs.max_upload_size_bytes;
        return node;
    }

    static bool decode(const Node& node, WebsocketConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.enabled = node["enabled"].as<bool>(true);
        rhs.host = node["host"].as<std::string>("0.0.0.0");
        rhs.port = node["port"].as<uint16_t>(8080);
        rhs.max_connections = node["max_connections"].as<unsigned int>(1024);
        rhs.max_upload_size_bytes = node["max_upload_size_mb"].as<uintmax_t>(2048) * 1024 * 1024; // Default 2GB
        return true;
    }
};

template<>
struct convert<HttpPreviewConfig> {
    static Node encode(const HttpPreviewConfig& rhs) {
        Node node;
        node["enabled"] = rhs.enabled;
        node["host"] = rhs.host;
        node["port"] = rhs.port;
        node["max_connections"] = rhs.max_connections;
        node["max_preview_size_bytes"] = rhs.max_preview_size_bytes;
        return node;
    }

    static bool decode(const Node& node, HttpPreviewConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.enabled = node["enabled"].as<bool>(true);
        rhs.host = node["host"].as<std::string>("0.0.0.0");
        rhs.port = node["port"].as<uint16_t>(8081);
        rhs.max_connections = node["max_connections"].as<unsigned int>(512);
        rhs.max_preview_size_bytes = node["max_preview_size_mb"].as<uintmax_t>(100) * 1024 * 1024; // Default 100MB
        return true;
    }
};

template<>
struct convert<S3GatewayMultipartConfig> {
    static Node encode(const S3GatewayMultipartConfig& rhs) {
        Node node;
        node["min_part_size_mb"] = rhs.min_part_size_mb;
        node["abort_after_days"] = rhs.abort_after_days;
        return node;
    }

    static bool decode(const Node& node, S3GatewayMultipartConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.min_part_size_mb = std::max(static_cast<uint32_t>(5), node["min_part_size_mb"].as<uint32_t>(5));
        rhs.abort_after_days = std::max(static_cast<uint32_t>(1), node["abort_after_days"].as<uint32_t>(7));
        return true;
    }
};

template<>
struct convert<S3GatewaySyntheticLocalRequestCostConfig> {
    static Node encode(const S3GatewaySyntheticLocalRequestCostConfig& rhs) {
        Node node;
        node["list"] = rhs.list;
        node["head"] = rhs.head;
        node["get"] = rhs.get;
        node["put"] = rhs.put;
        node["delete"] = rhs.delete_;
        node["copy"] = rhs.copy;
        node["downloaded_gb"] = rhs.downloaded_gb;
        node["uploaded_gb"] = rhs.uploaded_gb;
        return node;
    }

    static bool decode(const Node& node, S3GatewaySyntheticLocalRequestCostConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.list = node["list"].as<std::string>(rhs.list);
        rhs.head = node["head"].as<std::string>(rhs.head);
        rhs.get = node["get"].as<std::string>(rhs.get);
        rhs.put = node["put"].as<std::string>(rhs.put);
        rhs.delete_ = node["delete"].as<std::string>(rhs.delete_);
        rhs.copy = node["copy"].as<std::string>(rhs.copy);
        rhs.downloaded_gb = node["downloaded_gb"].as<std::string>(rhs.downloaded_gb);
        rhs.uploaded_gb = node["uploaded_gb"].as<std::string>(rhs.uploaded_gb);
        return true;
    }
};

template<>
struct convert<DeviceServerConfig> {
    static Node encode(const DeviceServerConfig& rhs) {
        Node node;
        node["enabled"] = rhs.enabled;
        node["port"] = rhs.port;
        node["remote"] = rhs.remote;
        node["max_connections"] = rhs.max_connections;
        return node;
    }

    static bool decode(const Node& node, DeviceServerConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.enabled = node["enabled"].as<bool>(true);
        rhs.port = node["port"].as<uint16_t>(kDefaultDeviceServerPort);
        rhs.remote = node["remote"].as<bool>(false);
        rhs.max_connections = node["max_connections"].as<unsigned int>(256);
        return true;
    }
};

template<>
struct convert<S3GatewayConfig> {
    static Node encode(const S3GatewayConfig& rhs) {
        Node node;
        node["enabled"] = rhs.enabled;
        node["host"] = rhs.host;
        node["port"] = rhs.port;
        node["max_connections"] = rhs.max_connections;
        node["max_body_size_mb"] = rhs.max_body_size_bytes / (1024 * 1024);
        node["require_sigv4"] = rhs.require_sigv4;
        node["allow_path_style"] = rhs.allow_path_style;
        node["allow_virtual_hosted_style"] = rhs.allow_virtual_hosted_style;
        node["default_bucket_mode"] = rhs.default_bucket_mode;
        node["default_api_exclusive"] = rhs.default_api_exclusive;
        node["multipart"] = rhs.multipart;
        node["synthetic_local_request_cost_usd"] = rhs.synthetic_local_request_cost_usd;
        return node;
    }

    static bool decode(const Node& node, S3GatewayConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.enabled = node["enabled"].as<bool>(false);
        rhs.host = node["host"].as<std::string>("0.0.0.0");
        rhs.port = node["port"].as<uint16_t>(39000);
        rhs.max_connections = node["max_connections"].as<unsigned int>(1024);
        if (node["max_body_size_bytes"]) rhs.max_body_size_bytes = node["max_body_size_bytes"].as<uintmax_t>();
        else rhs.max_body_size_bytes = node["max_body_size_mb"].as<uintmax_t>(5120) * 1024ull * 1024ull;
        rhs.require_sigv4 = node["require_sigv4"].as<bool>(true);
        rhs.allow_path_style = node["allow_path_style"].as<bool>(true);
        rhs.allow_virtual_hosted_style = node["allow_virtual_hosted_style"].as<bool>(true);
        rhs.default_bucket_mode = node["default_bucket_mode"].as<std::string>("local");
        rhs.default_api_exclusive = node["default_api_exclusive"].as<bool>(true);
        // default_remote_* are read by loadConfig as deprecated aliases of vaults.s3.*.
        if (node["multipart"]) rhs.multipart = node["multipart"].as<S3GatewayMultipartConfig>();
        if (node["synthetic_local_request_cost_usd"])
            rhs.synthetic_local_request_cost_usd = node["synthetic_local_request_cost_usd"].as<S3GatewaySyntheticLocalRequestCostConfig>();
        return true;
    }
};

static std::string to_std_string(const spdlog::string_view_t sv) { return {sv.data(), sv.size()}; }

template<>
struct convert<SubsystemLogLevelsConfig> {
    static Node encode(const SubsystemLogLevelsConfig& rhs) {
        Node node;
        node["vaulthalla"]  = to_std_string(spdlog::level::to_string_view(rhs.vaulthalla));
        node["fuse"]        = to_std_string(spdlog::level::to_string_view(rhs.fuse));
        node["filesystem"]  = to_std_string(spdlog::level::to_string_view(rhs.filesystem));
        node["crypto"]      = to_std_string(spdlog::level::to_string_view(rhs.crypto));
        node["cloud"]       = to_std_string(spdlog::level::to_string_view(rhs.cloud));
        node["auth"]        = to_std_string(spdlog::level::to_string_view(rhs.auth));
        node["websocket"]   = to_std_string(spdlog::level::to_string_view(rhs.websocket));
        node["http"]        = to_std_string(spdlog::level::to_string_view(rhs.http));
        node["shell"]       = to_std_string(spdlog::level::to_string_view(rhs.shell));
        node["db"]          = to_std_string(spdlog::level::to_string_view(rhs.db));
        node["sync"]        = to_std_string(spdlog::level::to_string_view(rhs.sync));
        node["thumb"]       = to_std_string(spdlog::level::to_string_view(rhs.thumb));
        node["storage"]     = to_std_string(spdlog::level::to_string_view(rhs.storage));
        node["types"]       = to_std_string(spdlog::level::to_string_view(rhs.types));
        node["runtime"]     = to_std_string(spdlog::level::to_string_view(rhs.runtime));
        return node;
    }

    static bool decode(const Node& node, SubsystemLogLevelsConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.vaulthalla = spdlog::level::from_str(node["vaulthalla"].as<std::string>("debug"));
        rhs.fuse = spdlog::level::from_str(node["fuse"].as<std::string>("debug"));
        rhs.filesystem = spdlog::level::from_str(node["filesystem"].as<std::string>("info"));
        rhs.crypto = spdlog::level::from_str(node["crypto"].as<std::string>("info"));
        rhs.cloud = spdlog::level::from_str(node["cloud"].as<std::string>("info"));
        rhs.auth = spdlog::level::from_str(node["auth"].as<std::string>("info"));
        rhs.websocket = spdlog::level::from_str(node["websocket"].as<std::string>("info"));
        rhs.http = spdlog::level::from_str(node["http"].as<std::string>("info"));
        rhs.shell = spdlog::level::from_str(node["shell"].as<std::string>("info"));
        rhs.db = spdlog::level::from_str(node["db"].as<std::string>("warn"));
        rhs.sync = spdlog::level::from_str(node["sync"].as<std::string>("info"));
        rhs.thumb = spdlog::level::from_str(node["thumb"].as<std::string>("info"));
        rhs.storage = spdlog::level::from_str(node["storage"].as<std::string>("info"));
        rhs.types = spdlog::level::from_str(node["types"].as<std::string>("info"));
        rhs.runtime = spdlog::level::from_str(node["runtime"].as<std::string>("info"));
        return true;
    }
};

template<>
struct convert<LogLevelsConfig> {
    static Node encode(const LogLevelsConfig& rhs) {
        Node node;
        node["console_log_level"] = to_std_string(spdlog::level::to_string_view(rhs.console_log_level));
        node["file_log_level"]    = to_std_string(spdlog::level::to_string_view(rhs.file_log_level));
        node["subsystem_levels"]  = rhs.subsystem_levels;
        return node;
    }

    static bool decode(const Node& node, LogLevelsConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.console_log_level = spdlog::level::from_str(node["console_log_level"].as<std::string>("info"));
        rhs.file_log_level = spdlog::level::from_str(node["file_log_level"].as<std::string>("debug"));
        rhs.subsystem_levels = node["subsystem_levels"].as<SubsystemLogLevelsConfig>();
        return true;
    }
};

// LoggingConfig
template<>
struct convert<LoggingConfig> {
    static Node encode(const LoggingConfig& rhs) {
        Node node;
        node["log_levels"] = rhs.levels;
        return node;
    }

    static bool decode(const Node& node, LoggingConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.levels = node["log_levels"].as<LogLevelsConfig>();
        return true;
    }
};

template<>
struct convert<ThumbnailsConfig> {
    static Node encode(const ThumbnailsConfig& rhs) {
        Node node;
        node["formats"] = rhs.formats;
        node["sizes"] = rhs.sizes;
        node["expiry_days"] = rhs.expiry_days;
        return node;
    }

    static bool decode(const Node& node, ThumbnailsConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.formats = node["formats"].as<std::vector<std::string>>();
        rhs.sizes = node["sizes"].as<std::vector<unsigned int>>();
        rhs.expiry_days = node["expiry_days"].as<unsigned int>(30);
        return true;
    }
};

template<>
struct convert<CachingConfig> {
    static Node encode(const CachingConfig& rhs) {
        Node node;
        node["max_size_mb"] = rhs.max_size_mb;
        node["thumbnails"] = rhs.thumbnails;
        return node;
    }

    static bool decode(const Node& node, CachingConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.max_size_mb = node["max_size_mb"].as<unsigned int>(10240);
        rhs.thumbnails = node["thumbnails"].as<ThumbnailsConfig>();
        return true;
    }
};

template<>
struct convert<PreviewMediaConfig> {
    static Node encode(const PreviewMediaConfig& rhs) {
        Node node;
        node["integrity"] = previewIntegrityModeToString(rhs.integrity);
        node["remote"] = previewRemoteModeToString(rhs.remote);
        node["hwaccel"] = previewHwaccelToString(rhs.hwaccel);
        node["transcode"] = previewTranscodeModeToString(rhs.transcode);
        return node;
    }

    static bool decode(const Node& node, PreviewMediaConfig& rhs) {
        if (!node.IsMap()) return false;
        const PreviewMediaConfig defaults;
        rhs.integrity = node["integrity"]
            ? previewIntegrityModeFromString(node["integrity"].as<std::string>()) : defaults.integrity;
        rhs.remote = node["remote"] ? previewRemoteModeFromString(node["remote"].as<std::string>()) : defaults.remote;
        rhs.hwaccel = node["hwaccel"] ? previewHwaccelFromString(node["hwaccel"].as<std::string>()) : defaults.hwaccel;
        rhs.transcode = node["transcode"]
            ? previewTranscodeModeFromString(node["transcode"].as<std::string>()) : defaults.transcode;
        return true;
    }
};

template<>
struct convert<PreviewDeriveConfig> {
    static Node encode(const PreviewDeriveConfig& rhs) {
        Node node;
        node["helper_dir"] = rhs.helper_dir.string();
        node["max_concurrency"] = rhs.max_concurrency;
        node["max_queue"] = rhs.max_queue;
        node["max_ram_mb"] = rhs.max_ram_mb;
        node["max_cpu_seconds"] = rhs.max_cpu_seconds;
        node["wall_timeout_seconds"] = rhs.wall_timeout_seconds;
        node["max_output_mb"] = rhs.max_output_mb;
        node["failure_ttl_hours"] = rhs.failure_ttl_hours;
        return node;
    }

    static bool decode(const Node& node, PreviewDeriveConfig& rhs) {
        if (!node.IsMap()) return false;
        const PreviewDeriveConfig d;
        const auto clamped = [&node](const char* key, const uint32_t fallback, const uint32_t lo, const uint32_t hi) {
            return std::clamp(node[key].as<uint32_t>(fallback), lo, hi);
        };
        rhs.helper_dir = node["helper_dir"].as<std::string>(d.helper_dir.string());
        if (rhs.helper_dir.empty()) rhs.helper_dir = d.helper_dir;
        rhs.max_concurrency = clamped("max_concurrency", d.max_concurrency, 1u, 64u);
        rhs.max_queue = clamped("max_queue", d.max_queue, 1u, 100000u);
        rhs.max_ram_mb = clamped("max_ram_mb", d.max_ram_mb, 256u, 1024u * 1024u);
        rhs.max_cpu_seconds = clamped("max_cpu_seconds", d.max_cpu_seconds, 1u, 86400u);
        rhs.wall_timeout_seconds = clamped("wall_timeout_seconds", d.wall_timeout_seconds, 1u, 86400u);
        rhs.max_output_mb = clamped("max_output_mb", d.max_output_mb, 1u, 1024u * 1024u);
        rhs.failure_ttl_hours = clamped("failure_ttl_hours", d.failure_ttl_hours, 0u, 24u * 365u);
        return true;
    }
};

template<>
struct convert<PreviewTextConfig> {
    static Node encode(const PreviewTextConfig& rhs) {
        Node node;
        node["max_edit_bytes"] = rhs.max_edit_bytes;
        return node;
    }

    static bool decode(const Node& node, PreviewTextConfig& rhs) {
        if (!node.IsMap()) return false;
        const PreviewTextConfig d;
        rhs.max_edit_bytes = std::clamp<uint64_t>(node["max_edit_bytes"].as<uint64_t>(d.max_edit_bytes), 1024,
                                                  256ull * 1024 * 1024);
        return true;
    }
};

template<>
struct convert<PreviewConfig> {
    static Node encode(const PreviewConfig& rhs) {
        Node node;
        node["media"] = rhs.media;
        node["derive"] = rhs.derive;
        node["text"] = rhs.text;
        node["max_render_pixels"] = rhs.max_render_pixels;
        return node;
    }

    // Every subsection and key is optional: a missing one keeps its default.
    static bool decode(const Node& node, PreviewConfig& rhs) {
        if (!node.IsMap()) return false;
        const PreviewConfig d;
        if (const auto media = node["media"]) convert<PreviewMediaConfig>::decode(media, rhs.media);
        if (const auto derive = node["derive"]) convert<PreviewDeriveConfig>::decode(derive, rhs.derive);
        if (const auto text = node["text"]) convert<PreviewTextConfig>::decode(text, rhs.text);
        rhs.max_render_pixels = std::clamp<uint64_t>(node["max_render_pixels"].as<uint64_t>(d.max_render_pixels),
                                                     1'000'000, 1'000'000'000);
        return true;
    }
};

template<>
struct convert<DatabaseConfig> {
    static Node encode(const DatabaseConfig& rhs) {
        Node node;
        node["host"] = rhs.host;
        node["port"] = rhs.port;
        node["name"] = rhs.name;
        node["user"] = rhs.user;
        node["pool_size"] = rhs.pool_size;
        return node;
    }

    static bool decode(const Node& node, DatabaseConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.host = node["host"].as<std::string>("localhost");
        rhs.port = node["port"].as<uint16_t>(5432);
        rhs.name = node["name"].as<std::string>("vaulthalla");
        rhs.user = node["user"].as<std::string>("vaulthalla");
        rhs.pool_size = node["pool_size"].as<int>(10);
        return true;
    }
};

// AuthConfig

template<>
struct convert<AuthConfig> {
    static Node encode(const AuthConfig& rhs) {
        Node node;
        node["token_expiry_minutes"] = rhs.access_token_expiry_minutes;
        node["refresh_token_expiry_days"] = rhs.refresh_token_expiry_days;
        return node;
    }

    static bool decode(const Node& node, AuthConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.access_token_expiry_minutes = node["token_expiry_minutes"].as<int>(60);
        rhs.refresh_token_expiry_days = node["refresh_token_expiry_days"].as<int>(7);
        return true;
    }
};

// SyncConfig
template<>
struct convert<SyncConfig> {
    static Node encode(const SyncConfig& rhs) {
        Node node;
        node["event_audit_retention_days"] = rhs.event_audit_retention_days;
        node["event_audit_max_entries"] = rhs.event_audit_max_entries;
        return node;
    }

    static bool decode(const Node& node, SyncConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.event_audit_retention_days = std::max(static_cast<uint32_t>(7), node["event_audit_retention_days"].as<uint32_t>(30));
        rhs.event_audit_max_entries = std::max(static_cast<uint32_t>(1000), node["event_audit_max_entries"].as<uint32_t>(10000));
        return true;
    }
};

template<>
struct convert<StorageRatesApiConfig> {
    static Node encode(const StorageRatesApiConfig& rhs) {
        Node node;
        node["remote_refresh_enabled"] = rhs.remote_refresh_enabled;
        node["base_url"] = rhs.base_url;
        node["timeout_ms"] = rhs.timeout_ms;
        node["cache_ttl_seconds"] = rhs.cache_ttl_seconds;
        node["refresh_interval_seconds"] = rhs.refresh_interval_seconds;
        node["fail_open"] = rhs.fail_open;
        node["signature_warning_only"] = rhs.signature_warning_only;
        node["signature_public_key_path"] = rhs.signature_public_key_path
            ? Node(rhs.signature_public_key_path->string())
            : Node(NodeType::Null);
        node["fallback_artifact_base_urls"] = rhs.fallback_artifact_base_urls;
        node["prefer_full_catalog"] = rhs.prefer_full_catalog;
        node["use_remote_estimator_for_debug"] = rhs.use_remote_estimator_for_debug;
        return node;
    }

    static bool decode(const Node& node, StorageRatesApiConfig& rhs) {
        if (!node.IsMap()) return false;
        if (node["remote_refresh_enabled"]) rhs.remote_refresh_enabled = node["remote_refresh_enabled"].as<bool>(false);
        else rhs.remote_refresh_enabled = node["enabled"].as<bool>(false);
        rhs.base_url = node["base_url"].as<std::string>("https://storage-rates-api.vaulthalla.cloud");
        rhs.timeout_ms = std::max(static_cast<uint32_t>(100), node["timeout_ms"].as<uint32_t>(5000));
        rhs.cache_ttl_seconds = std::max(static_cast<uint32_t>(60), node["cache_ttl_seconds"].as<uint32_t>(43200));
        rhs.refresh_interval_seconds = std::max(
            static_cast<uint32_t>(60),
            node["refresh_interval_seconds"].as<uint32_t>(43200));
        rhs.fail_open = node["fail_open"].as<bool>(true);
        rhs.signature_warning_only = node["signature_warning_only"].as<bool>(true);
        if (node["signature_public_key_path"] && !node["signature_public_key_path"].IsNull())
            rhs.signature_public_key_path = node["signature_public_key_path"].as<std::filesystem::path>();
        else
            rhs.signature_public_key_path.reset();
        rhs.fallback_artifact_base_urls = node["fallback_artifact_base_urls"].as<std::vector<std::string>>(std::vector<std::string>{});
        rhs.prefer_full_catalog = node["prefer_full_catalog"].as<bool>(true);
        rhs.use_remote_estimator_for_debug = node["use_remote_estimator_for_debug"].as<bool>(false);
        return true;
    }
};

template<>
struct convert<PricingConfig> {
    static Node encode(const PricingConfig& rhs) {
        Node node;
        node["enabled"] = rhs.enabled;
        node["storage_rates_api"] = rhs.storage_rates_api;
        return node;
    }

    static bool decode(const Node& node, PricingConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.enabled = node["enabled"].as<bool>(true);
        if (node["storage_rates_api"]) rhs.storage_rates_api = node["storage_rates_api"].as<StorageRatesApiConfig>();
        return true;
    }
};

template<>
struct convert<DBSweeperConfig> {
    static Node encode(const DBSweeperConfig& rhs) {
        Node node;
        node["sweep_interval_minutes"] = rhs.sweep_interval_minutes;
        return node;
    }

    static bool decode(const Node& node, DBSweeperConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.sweep_interval_minutes = std::max(10, node["sweep_interval_minutes"].as<int>(60));
        return true;
    }
};

template<>
struct convert<ConnectionLifecycleManagerConfig> {
    static Node encode(const ConnectionLifecycleManagerConfig& rhs) {
        Node node;
        node["idle_timeout_minutes"] = rhs.idle_timeout_minutes;
        node["unauthenticated_timeout_seconds"] = rhs.unauthenticated_timeout_seconds;
        node["sweep_interval_seconds"] = rhs.sweep_interval_seconds;
        return node;
    }

    static bool decode(const Node& node, ConnectionLifecycleManagerConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.idle_timeout_minutes = std::max(5, node["idle_timeout_minutes"].as<int>(30));
        rhs.unauthenticated_timeout_seconds = std::max(30, node["unauthenticated_timeout_seconds"].as<int>(300));
        rhs.sweep_interval_seconds = std::max(15, node["sweep_interval_seconds"].as<int>(60));
        return true;
    }
};

template<>
struct convert<StatsSnapshotsConfig> {
    static Node encode(const StatsSnapshotsConfig& rhs) {
        Node node;
        node["enabled"] = rhs.enabled;
        node["runtime_interval_seconds"] = rhs.runtime_interval_seconds;
        node["gauge_observation_interval_seconds"] = rhs.gauge_observation_interval_seconds;
        node["vault_interval_seconds"] = rhs.vault_interval_seconds;
        node["retention_days"] = rhs.retention_days;
        return node;
    }

    static bool decode(const Node& node, StatsSnapshotsConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.enabled = node["enabled"].as<bool>(true);
        rhs.runtime_interval_seconds = 60;
        rhs.gauge_observation_interval_seconds = std::clamp(
            node["gauge_observation_interval_seconds"].as<uint32_t>(3),
            static_cast<uint32_t>(1),
            static_cast<uint32_t>(60)
        );
        rhs.vault_interval_seconds = std::max(static_cast<uint32_t>(300), node["vault_interval_seconds"].as<uint32_t>(3600));
        rhs.retention_days = std::max(static_cast<uint32_t>(1), node["retention_days"].as<uint32_t>(30));
        return true;
    }
};

template<>
struct convert<ServicesConfig> {
    static Node encode(const ServicesConfig& rhs) {
        Node node;
        node["db_sweeper"] = rhs.db_sweeper;
        node["connection_lifecycle_manager"] = rhs.connection_lifecycle_manager;
        return node;
    }

    static bool decode(const Node& node, ServicesConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.db_sweeper = node["db_sweeper"].as<DBSweeperConfig>();
        rhs.connection_lifecycle_manager = node["connection_lifecycle_manager"].as<ConnectionLifecycleManagerConfig>();
        return true;
    }
};

template<>
struct convert<SharingConfig> {
    static Node encode(const SharingConfig& rhs) {
        Node node;
        node["enabled"] = rhs.enabled;
        node["enable_anonymous"] = rhs.enable_anonymous;
        node["enable_email_validated"] = rhs.enable_email_validated;
        return node;
    }

    static bool decode(const Node& node, SharingConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.enabled = node["enabled"].as<bool>(true);
        rhs.enable_anonymous = node["enable_anonymous"].as<bool>(true);
        // enable_public_links is the pre-#164 name of enable_email_validated; the new key wins when both are set.
        if (node["enable_email_validated"]) rhs.enable_email_validated = node["enable_email_validated"].as<bool>();
        else rhs.enable_email_validated = node["enable_public_links"].as<bool>(true);
        return true;
    }
};

template<>
struct convert<VaultsS3Config> {
    static Node encode(const VaultsS3Config& rhs) {
        Node node;
        node["default_remote_sync_strategy"] = rhs.default_remote_sync_strategy;
        node["default_remote_conflict_policy"] = rhs.default_remote_conflict_policy;
        node["tpm_retention_window"] = durationToString(rhs.tpm_retention_window);
        return node;
    }

    static bool decode(const Node& node, VaultsS3Config& rhs) {
        if (!node.IsMap()) return false;
        rhs.default_remote_sync_strategy = node["default_remote_sync_strategy"].as<std::string>(rhs.default_remote_sync_strategy);
        rhs.default_remote_conflict_policy =
            node["default_remote_conflict_policy"].as<std::string>(rhs.default_remote_conflict_policy);
        if (node["tpm_retention_window"]) rhs.tpm_retention_window = parseDuration(node["tpm_retention_window"].as<std::string>());
        return true;
    }
};

template<>
struct convert<VaultsConfig> {
    static Node encode(const VaultsConfig& rhs) {
        Node node;
        node["retention_window"] = durationToString(rhs.retention_window);
        node["tpm_retention_window"] = durationToString(rhs.tpm_retention_window);
        node["s3"] = rhs.s3;
        return node;
    }

    static bool decode(const Node& node, VaultsConfig& rhs) {
        if (!node.IsMap()) return false;
        if (node["retention_window"]) rhs.retention_window = parseDuration(node["retention_window"].as<std::string>());
        if (node["tpm_retention_window"]) rhs.tpm_retention_window = parseDuration(node["tpm_retention_window"].as<std::string>());
        if (node["s3"]) YAML::convert<VaultsS3Config>::decode(node["s3"], rhs.s3);
        return true;
    }
};

template<>
struct convert<ResendEmailConfig> {
    static Node encode(const ResendEmailConfig& rhs) {
        Node node;
        node["endpoint"] = rhs.endpoint;
        return node;
    }

    static bool decode(const Node& node, ResendEmailConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.endpoint = node["endpoint"].as<std::string>("https://api.resend.com/emails");
        return true;
    }
};

template<>
struct convert<SesEmailConfig> {
    static Node encode(const SesEmailConfig& rhs) {
        Node node;
        node["region"] = rhs.region;
        node["endpoint"] = rhs.endpoint ? Node(*rhs.endpoint) : Node(NodeType::Null);
        return node;
    }

    static bool decode(const Node& node, SesEmailConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.region = node["region"].as<std::string>("us-east-1");
        if (node["endpoint"] && !node["endpoint"].IsNull())
            rhs.endpoint = node["endpoint"].as<std::string>();
        else
            rhs.endpoint.reset();
        return true;
    }
};

template<>
struct convert<EmailConfig> {
    static Node encode(const EmailConfig& rhs) {
        Node node;
        node["enabled"] = rhs.enabled;
        node["provider"] = emailProviderKindToString(rhs.provider);
        node["from"] = rhs.from;
        node["reply_to"] = rhs.reply_to ? Node(*rhs.reply_to) : Node(NodeType::Null);
        node["base_url"] = rhs.base_url ? Node(*rhs.base_url) : Node(NodeType::Null);
        node["resend"] = rhs.resend;
        node["ses"] = rhs.ses;
        return node;
    }

    static bool decode(const Node& node, EmailConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.enabled = node["enabled"].as<bool>(false);
        rhs.provider = emailProviderKindFromString(node["provider"].as<std::string>("none"));
        rhs.from = node["from"].as<std::string>("Vaulthalla <ops@example.com>");

        if (node["reply_to"] && !node["reply_to"].IsNull())
            rhs.reply_to = node["reply_to"].as<std::string>();
        else
            rhs.reply_to.reset();

        if (node["base_url"] && !node["base_url"].IsNull())
            rhs.base_url = node["base_url"].as<std::string>();
        else
            rhs.base_url.reset();

        if (node["resend"]) rhs.resend = node["resend"].as<ResendEmailConfig>();
        if (node["ses"]) rhs.ses = node["ses"].as<SesEmailConfig>();
        return true;
    }
};

template<>
struct convert<OperatorEmailRecipientsConfig> {
    static Node encode(const OperatorEmailRecipientsConfig& rhs) {
        Node node;
        node["alerts"] = rhs.alerts;
        node["weekly"] = rhs.weekly;
        node["security"] = rhs.security;
        return node;
    }

    static bool decode(const Node& node, OperatorEmailRecipientsConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.alerts = node["alerts"].as<std::vector<std::string>>(std::vector<std::string>{});
        rhs.weekly = node["weekly"].as<std::vector<std::string>>(std::vector<std::string>{});
        rhs.security = node["security"].as<std::vector<std::string>>(std::vector<std::string>{});
        return true;
    }
};

template<>
struct convert<OperatorEmailAlertingConfig> {
    static Node encode(const OperatorEmailAlertingConfig& rhs) {
        Node node;
        node["enabled"] = rhs.enabled;
        node["min_severity"] = rhs.min_severity;
        node["dedupe_window_minutes"] = rhs.dedupe_window_minutes;
        node["repeat_after_hours"] = rhs.repeat_after_hours;
        node["send_recovery"] = rhs.send_recovery;
        node["health_poll_seconds"] = rhs.health_poll_seconds;
        return node;
    }

    static bool decode(const Node& node, OperatorEmailAlertingConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.enabled = node["enabled"].as<bool>(true);
        rhs.min_severity = node["min_severity"].as<std::string>("warning");
        rhs.dedupe_window_minutes = std::max(static_cast<uint32_t>(1), node["dedupe_window_minutes"].as<uint32_t>(60));
        rhs.repeat_after_hours = std::max(static_cast<uint32_t>(1), node["repeat_after_hours"].as<uint32_t>(24));
        rhs.send_recovery = node["send_recovery"].as<bool>(true);
        rhs.health_poll_seconds = std::max(static_cast<uint32_t>(15), node["health_poll_seconds"].as<uint32_t>(60));
        return true;
    }
};

template<>
struct convert<OperatorEmailDigestConfig> {
    static Node encode(const OperatorEmailDigestConfig& rhs) {
        Node node;
        node["enabled"] = rhs.enabled;
        node["weekday"] = rhs.weekday;
        node["hour_local"] = rhs.hour_local;
        node["timezone"] = rhs.timezone;
        return node;
    }

    static bool decode(const Node& node, OperatorEmailDigestConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.enabled = node["enabled"].as<bool>(true);
        rhs.weekday = node["weekday"].as<std::string>("monday");
        rhs.hour_local = std::min(static_cast<uint32_t>(23), node["hour_local"].as<uint32_t>(8));
        rhs.timezone = node["timezone"].as<std::string>("UTC");
        return true;
    }
};

template<>
struct convert<OperatorEmailSecurityAlertsConfig> {
    static Node encode(const OperatorEmailSecurityAlertsConfig& rhs) {
        Node node;
        node["enabled"] = rhs.enabled;
        node["admin_role_changes"] = rhs.admin_role_changes;
        return node;
    }

    static bool decode(const Node& node, OperatorEmailSecurityAlertsConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.enabled = node["enabled"].as<bool>(true);
        rhs.admin_role_changes = node["admin_role_changes"].as<bool>(true);
        return true;
    }
};

template<>
struct convert<OperatorEmailsConfig> {
    static Node encode(const OperatorEmailsConfig& rhs) {
        Node node;
        node["enabled"] = rhs.enabled;
        node["recipients"] = rhs.recipients;
        node["alerting"] = rhs.alerting;
        node["weekly_digest"] = rhs.weekly_digest;
        node["security_alerts"] = rhs.security_alerts;
        return node;
    }

    static bool decode(const Node& node, OperatorEmailsConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.enabled = node["enabled"].as<bool>(true);
        if (node["recipients"]) rhs.recipients = node["recipients"].as<OperatorEmailRecipientsConfig>();
        if (node["alerting"]) rhs.alerting = node["alerting"].as<OperatorEmailAlertingConfig>();
        if (node["weekly_digest"]) rhs.weekly_digest = node["weekly_digest"].as<OperatorEmailDigestConfig>();
        if (node["security_alerts"]) rhs.security_alerts = node["security_alerts"].as<OperatorEmailSecurityAlertsConfig>();
        return true;
    }
};

template<>
struct convert<AuditLogConfig> {
    static Node encode(const AuditLogConfig& rhs) {
        Node node;
        node["retention_days"] = rhs.retention_days.count();
        node["rotate_max_size"] = bytesToMbOrGbStr(rhs.rotate_max_size);
        node["rotate_interval"] = hoursToDayOrHourStr(rhs.rotate_interval);
        node["compression"] = compressionToString(rhs.compression);
        node["max_retained_logs_size"] = bytesToMbOrGbStr(rhs.max_retained_logs_size);
        node["strict_retention"] = rhs.strict_retention;
        return node;
    }

    static bool decode(const Node& node, AuditLogConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.retention_days = std::chrono::days(node["retention_days"].as<unsigned int>(30));
        rhs.rotate_max_size = parseMbOrGbToByte(node["rotate_max_size"].as<std::string>("50MB"));
        rhs.rotate_interval = parseHoursFromDayOrHour(node["rotate_interval"].as<std::string>("24h"));
        rhs.compression = parseCompression(node["compression"].as<std::string>("zstd"));
        rhs.max_retained_logs_size = parseMbOrGbToByte(node["max_retained_logs_size"].as<std::string>("1GB"));
        rhs.strict_retention = node["strict_retention"].as<bool>(false);
        return true;
    }
};

template<>
struct convert<EncryptionWaiverConfig> {
    static Node encode(const EncryptionWaiverConfig& rhs) {
        Node node;
        node["retention_days"] = rhs.retention_days.count();
        return node;
    }

    static bool decode(const Node& node, EncryptionWaiverConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.retention_days = std::chrono::days(node["retention_days"].as<unsigned int>(180));
        return true;
    }
};

template<>
struct convert<FilesTrashedConfig> {
    static Node encode(const FilesTrashedConfig& rhs) {
        Node node;
        node["retention_days"] = rhs.retention_days.count();
        return node;
    }

    static bool decode(const Node& node, FilesTrashedConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.retention_days = std::chrono::days(node["retention_days"].as<unsigned int>(60));
        return true;
    }
};

template<>
struct convert<AuditConfig> {
    static Node encode(const AuditConfig& rhs) {
        Node node;
        node["audit_log"] = rhs.audit_log;
        node["encryption_waivers"] = rhs.encryption_waivers;
        node["files_trashed"] = rhs.files_trashed;
        return node;
    }

    static bool decode(const Node& node, AuditConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.audit_log = node["audit_log"].as<AuditLogConfig>();
        rhs.encryption_waivers = node["encryption_waivers"].as<EncryptionWaiverConfig>();
        rhs.files_trashed = node["files_trashed"].as<FilesTrashedConfig>();
        return true;
    }
};

template<>
struct convert<MountConfig> {
    static bool decode(const Node& node, MountConfig& rhs) {
        if (!node.IsMap()) return false;
        rhs.mode = node["mode"].as<std::string>("");
        return true;
    }
};

template<>
struct convert<DevConfig> {
    static Node encode(const DevConfig& rhs) {
        Node node;
        node["enabled"] = rhs.enabled;
        return node;
    }

    static bool decode(const Node& node, DevConfig& rhs) {
        if (!node.IsMap()) return false;
        // dev.init_r2_test_vault (removed with the dev R2 test vault) is ignored if an older config.yaml still has it.
        rhs.enabled = node["enabled"].as<bool>(false);
        return true;
    }
};

template<>
struct convert<std::filesystem::path> {
    static Node encode(const std::filesystem::path& rhs) {
        return Node(rhs.string());
    }

    static bool decode(const Node& node, std::filesystem::path& rhs) {
        if (!node.IsScalar()) return false;
        rhs = std::filesystem::path(node.as<std::string>());
        return true;
    }
};

} // namespace YAML
