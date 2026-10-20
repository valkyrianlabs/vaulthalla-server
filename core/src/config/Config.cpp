#include "config/Config.hpp"
#include "config/config_yaml.hpp"
#include "config/util.hpp"

#include <cstdlib>
#include <algorithm>
#include <array>
#include <cctype>
#include <yaml-cpp/yaml.h>
#include <fstream>
#include <sstream>
#include <paths.h>
#include <nlohmann/json.hpp>

namespace vh::config {

Config::Config() = default;
Config::~Config() = default;
Config::Config(const Config&) = default;
Config::Config(Config&&) noexcept = default;
Config& Config::operator=(const Config&) = default;
Config& Config::operator=(Config&&) noexcept = default;
    template<typename T>
    T getOrDefault(const YAML::Node &node, const std::string &key, const T &def) {
        return node[key] ? node[key].as<T>() : def;
    }

    std::string emailProviderKindToString(const EmailProviderKind kind) {
        switch (kind) {
            case EmailProviderKind::None: return "none";
            case EmailProviderKind::Resend: return "resend";
            case EmailProviderKind::Ses: return "ses";
        }
        return "none";
    }

    EmailProviderKind emailProviderKindFromString(std::string_view value) {
        std::string normalized(value);
        std::ranges::transform(normalized, normalized.begin(), [](const unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });

        if (normalized.empty() || normalized == "none") return EmailProviderKind::None;
        if (normalized == "resend") return EmailProviderKind::Resend;
        if (normalized == "ses") return EmailProviderKind::Ses;
        throw std::invalid_argument("unknown email provider: " + normalized);
    }

    namespace {
    constexpr std::array<std::string_view, 3> kRemoteSyncStrategies{"cache", "sync", "mirror"};
    constexpr std::array<std::string_view, 4> kRemoteConflictPolicies{"keep_local", "keep_remote", "keep_newest", "ask"};

    void noteDeprecation(std::vector<std::string>* deprecations, std::string message) {
        if (deprecations) deprecations->push_back(std::move(message));
    }

    void requireRemoteDefaults(const VaultsS3Config& s3) {
        if (!isRemoteSyncStrategy(s3.default_remote_sync_strategy))
            throw std::invalid_argument("vaults.s3.default_remote_sync_strategy: unknown value '" +
                                        s3.default_remote_sync_strategy + "' (cache, sync or mirror)");
        if (!isRemoteConflictPolicy(s3.default_remote_conflict_policy))
            throw std::invalid_argument("vaults.s3.default_remote_conflict_policy: unknown value '" +
                                        s3.default_remote_conflict_policy +
                                        "' (keep_local, keep_remote, keep_newest or ask)");
    }

    // Keys renamed or moved by #164. config.yaml is never rewritten on upgrade, so the old spellings keep working:
    // their value applies unless the new key is also set (then the new key wins). Each one found is reported once.
    void applyLegacyKeys(const YAML::Node& root, Config& cfg, std::vector<std::string>* deprecations) {
        // The alias value itself is applied by convert<SharingConfig>::decode; only report it here.
        if (const auto sharing = root["sharing"]; sharing && sharing.IsMap() && sharing["enable_public_links"]) {
            noteDeprecation(deprecations, sharing["enable_email_validated"]
                ? "sharing.enable_public_links is deprecated and ignored because sharing.enable_email_validated is set; "
                  "remove it"
                : "sharing.enable_public_links is deprecated: rename it to sharing.enable_email_validated (its value "
                  "still applies)");
        }

        const auto gateway = root["s3_gateway"];
        if (!gateway || !gateway.IsMap()) return;
        const auto vaults = root["vaults"];
        const auto s3 = vaults && vaults.IsMap() ? vaults["s3"] : YAML::Node();
        const auto legacy = [&](const char* key, std::string& target, bool (*valid)(std::string_view)) {
            if (!gateway[key]) return;
            const std::string oldKey = std::string("s3_gateway.") + key;
            const std::string newKey = std::string("vaults.s3.") + key;
            if (s3 && s3.IsMap() && s3[key]) {
                noteDeprecation(deprecations, oldKey + " is deprecated and ignored because " + newKey + " is set; remove it");
                return;
            }
            const auto value = gateway[key].as<std::string>("");
            if (!valid(value)) {
                // Nothing read it before #164, so it may hold anything: report it, never refuse to start over it.
                noteDeprecation(deprecations, oldKey + " is deprecated and its value '" + value + "' is not valid; using " +
                                              newKey + ": " + target);
                return;
            }
            target = value;
            noteDeprecation(deprecations, oldKey + " is deprecated: move it to " + newKey + " (its value still applies)");
        };
        legacy("default_remote_sync_strategy", cfg.vaults.s3.default_remote_sync_strategy, &isRemoteSyncStrategy);
        legacy("default_remote_conflict_policy", cfg.vaults.s3.default_remote_conflict_policy, &isRemoteConflictPolicy);
    }
    }

    bool isRemoteSyncStrategy(const std::string_view value) {
        return std::ranges::find(kRemoteSyncStrategies, value) != kRemoteSyncStrategies.end();
    }

    bool isRemoteConflictPolicy(const std::string_view value) {
        return std::ranges::find(kRemoteConflictPolicies, value) != kRemoteConflictPolicies.end();
    }

    Config loadConfig(const std::string &path, std::vector<std::string>* deprecations) {
        Config cfg;
        // const: lookups of missing keys must never add nodes.
        const YAML::Node root = YAML::LoadFile(path);

        if (auto node = root["websocket_server"]) YAML::convert<WebsocketConfig>::decode(node, cfg.websocket);
        if (auto node = root["http_preview_server"]) YAML::convert<HttpPreviewConfig>::decode(node, cfg.http_preview);
        if (auto node = root["s3_gateway"]) YAML::convert<S3GatewayConfig>::decode(node, cfg.s3_gateway);
        if (auto node = root["device_server"]) YAML::convert<DeviceServerConfig>::decode(node, cfg.device_server);
        if (auto node = root["caching"]) YAML::convert<CachingConfig>::decode(node, cfg.caching);
        if (auto node = root["preview"]) YAML::convert<PreviewConfig>::decode(node, cfg.preview);
        if (auto node = root["database"]) YAML::convert<DatabaseConfig>::decode(node, cfg.database);
        if (auto node = root["auth"]) YAML::convert<AuthConfig>::decode(node, cfg.auth);
        if (auto node = root["sync"]) YAML::convert<SyncConfig>::decode(node, cfg.sync);
        if (auto node = root["pricing"]) YAML::convert<PricingConfig>::decode(node, cfg.pricing);
        if (auto node = root["services"]) YAML::convert<ServicesConfig>::decode(node, cfg.services);
        if (auto node = root["stats_snapshots"]) YAML::convert<StatsSnapshotsConfig>::decode(node, cfg.stats_snapshots);
        if (auto node = root["sharing"]) YAML::convert<SharingConfig>::decode(node, cfg.sharing);
        if (auto node = root["vaults"]) YAML::convert<VaultsConfig>::decode(node, cfg.vaults);
        if (auto node = root["email"]) YAML::convert<EmailConfig>::decode(node, cfg.email);
        if (auto node = root["operator_emails"]) YAML::convert<OperatorEmailsConfig>::decode(node, cfg.operator_emails);
        if (auto node = root["auditing"]) YAML::convert<AuditConfig>::decode(node, cfg.auditing);
        if (auto node = root["dev"]) YAML::convert<DevConfig>::decode(node, cfg.dev);
        if (auto node = root["mount"]) {
            YAML::convert<MountConfig>::decode(node, cfg.mount);
            // A typo must not quietly become another mode. Whether this build can provide the mode is reported at
            // runtime (fuse::mountStatus()), never a reason to refuse to serve storage.
            if (const auto& m = cfg.mount.mode;
                !m.empty() && m != "disabled" && m != "service_private" && m != "multiuser")
                throw std::invalid_argument("mount.mode must be disabled|service_private|multiuser, got '" + m + "'");
        }

        if (auto node = root["logging"]) YAML::convert<LoggingConfig>::decode(node, cfg.logging);

        applyLegacyKeys(root, cfg, deprecations);
        requireRemoteDefaults(cfg.vaults.s3);
        return cfg;
    }

    void Config::save() const {
        using namespace std;
        namespace fs = std::filesystem;

        const fs::path configFile = paths::getConfigPath();
        const fs::path templateFile = paths::getConfigPath().parent_path() / "config_template.yaml.in";

        YAML::Node root;
        if (fs::exists(configFile)) root = YAML::LoadFile(configFile.string());
        else if (fs::exists(templateFile)) root = YAML::LoadFile(templateFile.string());
        else root = YAML::Node(YAML::NodeType::Map);

        if (!root || !root.IsMap()) root = YAML::Node(YAML::NodeType::Map);

        const auto put = [&root]<typename T>(const std::string& key, const T& section) {
            root[key] = YAML::convert<T>::encode(section);
        };

        put("websocket_server", websocket);
        put("http_preview_server", http_preview);
        put("s3_gateway", s3_gateway);
        put("device_server", device_server);
        put("database", database);
        put("auth", auth);
        put("sync", sync);
        put("pricing", pricing);
        put("services", services);
        put("stats_snapshots", stats_snapshots);
        put("sharing", sharing);
        put("vaults", vaults);
        put("email", email);
        put("operator_emails", operator_emails);
        put("caching", caching);
        put("preview", preview);
        put("auditing", auditing);
        put("logging", logging);
        put("dev", dev);

        // Write the final result
        ofstream out(configFile);
        if (!out.is_open()) {
            throw runtime_error("Failed to write config file");
        }

        YAML::Emitter emitted;
        emitted << root;
        out << emitted.c_str() << '\n';
        out.close();
    }

    void to_json(nlohmann::json &j, const Config &c) {
        j = {
            {"websocket_server", c.websocket},
            {"http_preview_server", c.http_preview},
            {"s3_gateway", c.s3_gateway},
            {"device_server", c.device_server},
            {"caching", c.caching},
            {"preview", c.preview},
            {"database", c.database},
            {"auth", c.auth},
            {"sync", c.sync},
            {"pricing", c.pricing},
            {"services", c.services},
            {"stats_snapshots", c.stats_snapshots},
            {"sharing", c.sharing},
            {"vaults", c.vaults},
            {"email", c.email},
            {"operator_emails", c.operator_emails},
            {"auditing", c.auditing},
            {"logging", c.logging},
            {"dev", c.dev}
        };
    }

    void from_json(const nlohmann::json &j, Config &c) {
        j.at("websocket_server").get_to(c.websocket);
        j.at("http_preview_server").get_to(c.http_preview);
        if (j.contains("s3_gateway")) j.at("s3_gateway").get_to(c.s3_gateway);
        if (j.contains("device_server")) j.at("device_server").get_to(c.device_server);
        j.at("caching").get_to(c.caching);
        if (j.contains("preview")) j.at("preview").get_to(c.preview);
        j.at("database").get_to(c.database);
        j.at("auth").get_to(c.auth);
        j.at("sync").get_to(c.sync);
        if (j.contains("pricing")) j.at("pricing").get_to(c.pricing);
        j.at("services").get_to(c.services);
        if (j.contains("stats_snapshots")) j.at("stats_snapshots").get_to(c.stats_snapshots);
        j.at("sharing").get_to(c.sharing);
        if (j.contains("vaults")) j.at("vaults").get_to(c.vaults);
        // Pre-#164 spelling from API clients: s3_gateway.default_remote_* when vaults.s3.* doesn't name the key.
        if (j.contains("s3_gateway") && j.at("s3_gateway").is_object()) {
            const auto& gateway = j.at("s3_gateway");
            const auto* s3 = j.contains("vaults") && j.at("vaults").is_object() && j.at("vaults").contains("s3")
                                 ? &j.at("vaults").at("s3") : nullptr;
            const auto legacy = [&](const char* key, std::string& target) {
                if (gateway.contains(key) && !(s3 && s3->is_object() && s3->contains(key)))
                    target = gateway.at(key).get<std::string>();
            };
            legacy("default_remote_sync_strategy", c.vaults.s3.default_remote_sync_strategy);
            legacy("default_remote_conflict_policy", c.vaults.s3.default_remote_conflict_policy);
            requireRemoteDefaults(c.vaults.s3);
        }
        if (j.contains("email")) j.at("email").get_to(c.email);
        if (j.contains("operator_emails")) j.at("operator_emails").get_to(c.operator_emails);
        j.at("auditing").get_to(c.auditing);
        if (j.contains("logging")) j.at("logging").get_to(c.logging);
        j.at("dev").get_to(c.dev);
    }

    void to_json(nlohmann::json &j, const WebsocketConfig &c) {
        j = {
            {"enabled", c.enabled},
            {"host", c.host},
            {"port", c.port},
            {"max_connections", c.max_connections},
            {"max_upload_size_bytes", c.max_upload_size_bytes}
        };
    }

    void from_json(const nlohmann::json &j, WebsocketConfig &c) {
        c.enabled = j.value("enabled", true);
        c.host = j.value("host", "0.0.0.0");
        c.port = j.value("port", 33369);
        c.max_connections = j.value("max_connections", 1024u);
        c.max_upload_size_bytes = j.value("max_upload_size_bytes", MAX_UPLOAD_SIZE_BYTES);
    }

    void to_json(nlohmann::json &j, const HttpPreviewConfig &c) {
        // Symmetric with from_json, so a settings.update round trip can't silently reset these.
        j = {
            {"enabled", c.enabled},
            {"host", c.host},
            {"port", c.port},
            {"max_connections", c.max_connections},
            {"max_preview_size_bytes", c.max_preview_size_bytes}
        };
    }

    void from_json(const nlohmann::json &j, HttpPreviewConfig &c) {
        c.enabled = j.value("enabled", true);
        c.host = j.value("host", "0.0.0.0");
        c.port = j.value("port", 33370);
        c.max_connections = j.value("max_connections", 512);
        c.max_preview_size_bytes = j.value("max_preview_size_bytes", MAX_PREVIEW_SIZE_BYTES);
    }

    void to_json(nlohmann::json &j, const DeviceServerConfig &c) {
        j = {
            {"enabled", c.enabled},
            {"port", c.port},
            {"remote", c.remote},
            {"max_connections", c.max_connections}
        };
    }

    void from_json(const nlohmann::json &j, DeviceServerConfig &c) {
        c.enabled = j.value("enabled", true);
        c.port = j.value("port", kDefaultDeviceServerPort);
        c.remote = j.value("remote", false);
        c.max_connections = j.value("max_connections", 256u);
    }

    void to_json(nlohmann::json &j, const S3GatewayMultipartConfig &c) {
        j = {
            {"min_part_size_mb", c.min_part_size_mb},
            {"abort_after_days", c.abort_after_days}
        };
    }

    void from_json(const nlohmann::json &j, S3GatewayMultipartConfig &c) {
        c.min_part_size_mb = std::max(5u, j.value("min_part_size_mb", 5u));
        c.abort_after_days = std::max(1u, j.value("abort_after_days", 7u));
    }

    void to_json(nlohmann::json &j, const S3GatewaySyntheticLocalRequestCostConfig &c) {
        j = {
            {"list", c.list},
            {"head", c.head},
            {"get", c.get},
            {"put", c.put},
            {"delete", c.delete_},
            {"copy", c.copy},
            {"downloaded_gb", c.downloaded_gb},
            {"uploaded_gb", c.uploaded_gb}
        };
    }

    void from_json(const nlohmann::json &j, S3GatewaySyntheticLocalRequestCostConfig &c) {
        c.list = j.value("list", c.list);
        c.head = j.value("head", c.head);
        c.get = j.value("get", c.get);
        c.put = j.value("put", c.put);
        c.delete_ = j.value("delete", c.delete_);
        c.copy = j.value("copy", c.copy);
        c.downloaded_gb = j.value("downloaded_gb", c.downloaded_gb);
        c.uploaded_gb = j.value("uploaded_gb", c.uploaded_gb);
    }

    void to_json(nlohmann::json &j, const S3GatewayConfig &c) {
        j = {
            {"enabled", c.enabled},
            {"host", c.host},
            {"port", c.port},
            {"max_connections", c.max_connections},
            {"max_body_size_bytes", c.max_body_size_bytes},
            {"require_sigv4", c.require_sigv4},
            {"allow_path_style", c.allow_path_style},
            {"allow_virtual_hosted_style", c.allow_virtual_hosted_style},
            {"default_bucket_mode", c.default_bucket_mode},
            {"default_api_exclusive", c.default_api_exclusive},
            {"multipart", c.multipart},
            {"synthetic_local_request_cost_usd", c.synthetic_local_request_cost_usd}
        };
    }

    void from_json(const nlohmann::json &j, S3GatewayConfig &c) {
        c.enabled = j.value("enabled", false);
        c.host = j.value("host", "0.0.0.0");
        c.port = j.value("port", static_cast<uint16_t>(39000));
        c.max_connections = j.value("max_connections", 1024u);
        if (j.contains("max_body_size_bytes"))
            c.max_body_size_bytes = j.at("max_body_size_bytes").get<uintmax_t>();
        else if (j.contains("max_body_size_mb"))
            c.max_body_size_bytes = j.at("max_body_size_mb").get<uintmax_t>() * 1024ull * 1024ull;
        else
            c.max_body_size_bytes = 5ull * 1024ull * 1024ull * 1024ull;
        c.require_sigv4 = j.value("require_sigv4", true);
        c.allow_path_style = j.value("allow_path_style", true);
        c.allow_virtual_hosted_style = j.value("allow_virtual_hosted_style", true);
        c.default_bucket_mode = j.value("default_bucket_mode", "local");
        c.default_api_exclusive = j.value("default_api_exclusive", true);
        if (j.contains("multipart")) j.at("multipart").get_to(c.multipart);
        if (j.contains("synthetic_local_request_cost_usd"))
            j.at("synthetic_local_request_cost_usd").get_to(c.synthetic_local_request_cost_usd);
    }

    void to_json(nlohmann::json &j, const LoggingConfig &c) {
        j = {
            {"levels", c.levels}
        };
    }

    void from_json(const nlohmann::json &j, LoggingConfig &c) {
        j.at("levels").get_to(c.levels);
    }

    void to_json(nlohmann::json &j, const LogLevelsConfig &c) {
        j = {
            {"console_log_level", c.console_log_level},
            {"file_log_level", c.file_log_level},
            {"subsystem_levels", c.subsystem_levels}
        };
    }

    void from_json(const nlohmann::json &j, LogLevelsConfig &c) {
        c.console_log_level = j.value("console_log_level", spdlog::level::info);
        c.file_log_level = j.value("file_log_level", spdlog::level::debug);
        j.at("subsystem_levels").get_to(c.subsystem_levels);
    }

    void to_json(nlohmann::json &j, const SubsystemLogLevelsConfig &c) {
        j = {
            {"vaulthalla", c.vaulthalla},
            {"filesystem", c.filesystem},
            {"crypto", c.crypto},
            {"cloud", c.cloud},
            {"auth", c.auth},
            {"websocket", c.websocket},
            {"http", c.http},
            {"shell", c.shell},
            {"db", c.db},
            {"sync", c.sync},
            {"thumb", c.thumb},
            {"storage", c.storage},
            {"types", c.types},
            {"runtime", c.runtime}
        };
    }

    void from_json(const nlohmann::json &j, SubsystemLogLevelsConfig &c) {
        c.vaulthalla = j.value("vaulthalla", spdlog::level::debug);
        c.filesystem = j.value("filesystem", spdlog::level::info);
        c.crypto = j.value("crypto", spdlog::level::info);
        c.cloud = j.value("cloud", spdlog::level::info);
        c.auth = j.value("auth", spdlog::level::info);
        c.websocket = j.value("websocket", spdlog::level::info);
        c.http = j.value("http", spdlog::level::info);
        c.shell = j.value("shell", spdlog::level::info);
        c.db = j.value("db", spdlog::level::warn);
        c.sync = j.value("sync", spdlog::level::info);
        c.thumb = j.value("thumb", spdlog::level::info);
        c.storage = j.value("storage", spdlog::level::info);
        c.types = j.value("types", spdlog::level::info);
        c.runtime = j.value("runtime", spdlog::level::info);
    }

    void to_json(nlohmann::json &j, const ThumbnailsConfig &c) {
        j = {
            {"formats", c.formats},
            {"sizes", c.sizes},
            {"expiry_days", c.expiry_days}
        };
    }

    void from_json(const nlohmann::json &j, ThumbnailsConfig &c) {
        c.formats = j.value("formats", std::vector<std::string>{"jpg", "jpeg", "png", "webp", "pdf"});
        c.sizes = j.value("sizes", std::vector<unsigned int>{128, 256, 512});
        c.expiry_days = j.value("expiry_days", 30);
    }

    void to_json(nlohmann::json &j, const CachingConfig &c) {
        j = {
            {"thumbnails", c.thumbnails},
            {"max_size_mb", c.max_size_mb}
        };
    }

    void from_json(const nlohmann::json &j, CachingConfig &c) {
        j.at("thumbnails").get_to(c.thumbnails);
        c.max_size_mb = j.value("max_size_mb", 10240);
    }

    namespace {
        std::string lowercasePreviewValue(const std::string_view value) {
            std::string normalized(value);
            std::ranges::transform(normalized, normalized.begin(), [](const unsigned char ch) {
                return static_cast<char>(std::tolower(ch));
            });
            return normalized;
        }
    }

    std::string previewIntegrityModeToString(const PreviewIntegrityMode mode) {
        return mode == PreviewIntegrityMode::Strict ? "strict" : "optimistic";
    }

    PreviewIntegrityMode previewIntegrityModeFromString(const std::string_view value) {
        const auto v = lowercasePreviewValue(value);
        if (v == "optimistic") return PreviewIntegrityMode::Optimistic;
        if (v == "strict") return PreviewIntegrityMode::Strict;
        throw std::invalid_argument("preview.media.integrity must be optimistic|strict, got '" + v + "'");
    }

    std::string previewRemoteModeToString(const PreviewRemoteMode mode) {
        switch (mode) {
            case PreviewRemoteMode::Hydrate: return "hydrate";
            case PreviewRemoteMode::Ranged: return "ranged";
            case PreviewRemoteMode::Off: return "off";
        }
        return "hydrate";
    }

    PreviewRemoteMode previewRemoteModeFromString(const std::string_view value) {
        const auto v = lowercasePreviewValue(value);
        if (v == "hydrate") return PreviewRemoteMode::Hydrate;
        if (v == "ranged") return PreviewRemoteMode::Ranged;
        if (v == "off") return PreviewRemoteMode::Off;
        throw std::invalid_argument("preview.media.remote must be hydrate|ranged|off, got '" + v + "'");
    }

    std::string previewHwaccelToString(const PreviewHwaccel hwaccel) {
        switch (hwaccel) {
            case PreviewHwaccel::Auto: return "auto";
            case PreviewHwaccel::Software: return "software";
            case PreviewHwaccel::Vaapi: return "vaapi";
            case PreviewHwaccel::Qsv: return "qsv";
            case PreviewHwaccel::Nvenc: return "nvenc";
        }
        return "auto";
    }

    PreviewHwaccel previewHwaccelFromString(const std::string_view value) {
        const auto v = lowercasePreviewValue(value);
        if (v == "auto") return PreviewHwaccel::Auto;
        if (v == "software") return PreviewHwaccel::Software;
        if (v == "vaapi") return PreviewHwaccel::Vaapi;
        if (v == "qsv") return PreviewHwaccel::Qsv;
        if (v == "nvenc") return PreviewHwaccel::Nvenc;
        throw std::invalid_argument("preview.media.hwaccel must be auto|software|vaapi|qsv|nvenc, got '" + v + "'");
    }

    std::string previewTranscodeModeToString(const PreviewTranscodeMode mode) {
        return mode == PreviewTranscodeMode::Off ? "off" : "on_demand";
    }

    PreviewTranscodeMode previewTranscodeModeFromString(const std::string_view value) {
        const auto v = lowercasePreviewValue(value);
        if (v == "off") return PreviewTranscodeMode::Off;
        if (v == "on_demand") return PreviewTranscodeMode::OnDemand;
        throw std::invalid_argument("preview.media.transcode must be off|on_demand, got '" + v + "'");
    }

    void to_json(nlohmann::json &j, const PreviewMediaConfig &c) {
        j = {
            {"integrity", previewIntegrityModeToString(c.integrity)},
            {"remote", previewRemoteModeToString(c.remote)},
            {"hwaccel", previewHwaccelToString(c.hwaccel)},
            {"transcode", previewTranscodeModeToString(c.transcode)}
        };
    }

    void from_json(const nlohmann::json &j, PreviewMediaConfig &c) {
        if (j.contains("integrity")) c.integrity = previewIntegrityModeFromString(j.at("integrity").get<std::string>());
        if (j.contains("remote")) c.remote = previewRemoteModeFromString(j.at("remote").get<std::string>());
        if (j.contains("hwaccel")) c.hwaccel = previewHwaccelFromString(j.at("hwaccel").get<std::string>());
        if (j.contains("transcode")) c.transcode = previewTranscodeModeFromString(j.at("transcode").get<std::string>());
    }

    void to_json(nlohmann::json &j, const PreviewDeriveConfig &c) {
        j = {
            {"helper_dir", c.helper_dir.string()},
            {"max_concurrency", c.max_concurrency},
            {"max_queue", c.max_queue},
            {"max_ram_mb", c.max_ram_mb},
            {"max_cpu_seconds", c.max_cpu_seconds},
            {"wall_timeout_seconds", c.wall_timeout_seconds},
            {"max_output_mb", c.max_output_mb},
            {"failure_ttl_hours", c.failure_ttl_hours}
        };
    }

    void from_json(const nlohmann::json &j, PreviewDeriveConfig &c) {
        c.helper_dir = j.value("helper_dir", c.helper_dir.string());
        c.max_concurrency = j.value("max_concurrency", c.max_concurrency);
        c.max_queue = j.value("max_queue", c.max_queue);
        c.max_ram_mb = j.value("max_ram_mb", c.max_ram_mb);
        c.max_cpu_seconds = j.value("max_cpu_seconds", c.max_cpu_seconds);
        c.wall_timeout_seconds = j.value("wall_timeout_seconds", c.wall_timeout_seconds);
        c.max_output_mb = j.value("max_output_mb", c.max_output_mb);
        c.failure_ttl_hours = j.value("failure_ttl_hours", c.failure_ttl_hours);
    }

    void to_json(nlohmann::json &j, const PreviewTextConfig &c) {
        j = {{"max_edit_bytes", c.max_edit_bytes}};
    }

    void from_json(const nlohmann::json &j, PreviewTextConfig &c) {
        c.max_edit_bytes = j.value("max_edit_bytes", c.max_edit_bytes);
    }

    void to_json(nlohmann::json &j, const PreviewConfig &c) {
        j = {
            {"media", c.media},
            {"derive", c.derive},
            {"text", c.text},
            {"max_render_pixels", c.max_render_pixels}
        };
    }

    void from_json(const nlohmann::json &j, PreviewConfig &c) {
        if (j.contains("media")) j.at("media").get_to(c.media);
        if (j.contains("derive")) j.at("derive").get_to(c.derive);
        if (j.contains("text")) j.at("text").get_to(c.text);
        c.max_render_pixels = j.value("max_render_pixels", c.max_render_pixels);
    }

    void to_json(nlohmann::json &j, const DatabaseConfig &c) {
        j = {
            {"host", c.host},
            {"port", c.port},
            {"name", c.name},
            {"user", c.user},
            {"pool_size", c.pool_size}
        };
    }

    void from_json(const nlohmann::json &j, DatabaseConfig &c) {
        c.host = j.value("host", "localhost");
        c.port = j.value("port", 5432);
        c.name = j.value("name", "vaulthalla");
        c.user = j.value("user", "vaulthalla");
        c.pool_size = j.value("pool_size", 10);
    }

    void to_json(nlohmann::json &j, const AuthConfig &c) {
        j = {
            {"access_token_expiry_minutes", c.access_token_expiry_minutes},
            {"refresh_token_expiry_days", c.refresh_token_expiry_days}
            // Do not serialize jwt_secret
        };
    }

    void from_json(const nlohmann::json &j, AuthConfig &c) {
        c.access_token_expiry_minutes = j.value("access_token_expiry_minutes", 60);
        c.refresh_token_expiry_days = j.value("refresh_token_expiry_days", 7);
    }

    void to_json(nlohmann::json &j, const SyncConfig &c) {
        j = {
            {"event_audit_retention_days", c.event_audit_retention_days},
            {"event_audit_max_entries", c.event_audit_max_entries}
        };
    }

    void from_json(const nlohmann::json &j, SyncConfig &c) {
        c.event_audit_retention_days = std::max(7, j.value("event_audit_retention_days", 30));
        c.event_audit_max_entries = std::max(1000, j.value("event_audit_max_entries", 10000));
    }

    void to_json(nlohmann::json &j, const StorageRatesApiConfig &c) {
        j = {
            {"remote_refresh_enabled", c.remote_refresh_enabled},
            {"base_url", c.base_url},
            {"timeout_ms", c.timeout_ms},
            {"cache_ttl_seconds", c.cache_ttl_seconds},
            {"refresh_interval_seconds", c.refresh_interval_seconds},
            {"fail_open", c.fail_open},
            {"signature_warning_only", c.signature_warning_only},
            {"signature_public_key_path", c.signature_public_key_path
                ? nlohmann::json(c.signature_public_key_path->string())
                : nlohmann::json(nullptr)},
            {"fallback_artifact_base_urls", c.fallback_artifact_base_urls},
            {"prefer_full_catalog", c.prefer_full_catalog},
            {"use_remote_estimator_for_debug", c.use_remote_estimator_for_debug}
        };
    }

    void from_json(const nlohmann::json &j, StorageRatesApiConfig &c) {
        if (j.contains("remote_refresh_enabled")) c.remote_refresh_enabled = j.value("remote_refresh_enabled", false);
        else c.remote_refresh_enabled = j.value("enabled", false);
        c.base_url = j.value("base_url", std::string("https://storage-rates-api.vaulthalla.cloud"));
        c.timeout_ms = std::max(100u, j.value("timeout_ms", 5000u));
        c.cache_ttl_seconds = std::max(60u, j.value("cache_ttl_seconds", 43200u));
        c.refresh_interval_seconds = std::max(60u, j.value("refresh_interval_seconds", 43200u));
        c.fail_open = j.value("fail_open", true);
        c.signature_warning_only = j.value("signature_warning_only", true);
        if (j.contains("signature_public_key_path") && !j.at("signature_public_key_path").is_null())
            c.signature_public_key_path = std::filesystem::path(j.at("signature_public_key_path").get<std::string>());
        else
            c.signature_public_key_path.reset();
        c.fallback_artifact_base_urls = j.value("fallback_artifact_base_urls", std::vector<std::string>{});
        c.prefer_full_catalog = j.value("prefer_full_catalog", true);
        c.use_remote_estimator_for_debug = j.value("use_remote_estimator_for_debug", false);
    }

    void to_json(nlohmann::json &j, const PricingConfig &c) {
        j = {
            {"enabled", c.enabled},
            {"storage_rates_api", c.storage_rates_api}
        };
    }

    void from_json(const nlohmann::json &j, PricingConfig &c) {
        c.enabled = j.value("enabled", true);
        if (j.contains("storage_rates_api")) j.at("storage_rates_api").get_to(c.storage_rates_api);
    }

    void to_json(nlohmann::json &j, const DBSweeperConfig &c) {
        j = {
            {"sweep_interval_minutes", c.sweep_interval_minutes}
        };
    }

    void from_json(const nlohmann::json &j, DBSweeperConfig &c) {
        c.sweep_interval_minutes = std::max(5, j.value("sweep_interval_minutes", 60));
    }

    void to_json(nlohmann::json &j, const ConnectionLifecycleManagerConfig &c) {
        j = {
            {"idle_timeout_minutes", c.idle_timeout_minutes},
            {"unauthenticated_timeout_seconds", c.unauthenticated_timeout_seconds},
            {"sweep_interval_seconds", c.sweep_interval_seconds}
        };
    }

    void from_json(const nlohmann::json &j, ConnectionLifecycleManagerConfig &c) {
        c.idle_timeout_minutes = std::max(5, j.value("idle_timeout_minutes", 30));
        c.unauthenticated_timeout_seconds = std::max(30, j.value("unauthenticated_timeout_seconds", 300));
        c.sweep_interval_seconds = std::max(15, j.value("sweep_interval_seconds", 60));
    }

    void to_json(nlohmann::json &j, const StatsSnapshotsConfig &c) {
        j = {
            {"enabled", c.enabled},
            {"runtime_interval_seconds", c.runtime_interval_seconds},
            {"gauge_observation_interval_seconds", c.gauge_observation_interval_seconds},
            {"vault_interval_seconds", c.vault_interval_seconds},
            {"retention_days", c.retention_days}
        };
    }

    void from_json(const nlohmann::json &j, StatsSnapshotsConfig &c) {
        c.enabled = j.value("enabled", true);
        c.runtime_interval_seconds = 60u;
        c.gauge_observation_interval_seconds = std::clamp(j.value("gauge_observation_interval_seconds", 3u), 1u, 60u);
        c.vault_interval_seconds = std::max(300u, j.value("vault_interval_seconds", 3600u));
        c.retention_days = std::max(1u, j.value("retention_days", 30u));
    }

    void to_json(nlohmann::json &j, const ServicesConfig &c) {
        j = {
            {"db_sweeper", c.db_sweeper},
            {"connection_lifecycle_manager", c.connection_lifecycle_manager}
        };
    }

    void from_json(const nlohmann::json &j, ServicesConfig &c) {
        j.at("db_sweeper").get_to(c.db_sweeper);
        j.at("connection_lifecycle_manager").get_to(c.connection_lifecycle_manager);
    }

    void to_json(nlohmann::json &j, const SharingConfig &c) {
        j = {
            {"enabled", c.enabled},
            {"enable_anonymous", c.enable_anonymous},
            {"enable_email_validated", c.enable_email_validated}
        };
    }

    void from_json(const nlohmann::json &j, SharingConfig &c) {
        c.enabled = j.value("enabled", true);
        c.enable_anonymous = j.value("enable_anonymous", true);
        // enable_public_links: the pre-#164 name; the new key wins when both are present.
        c.enable_email_validated = j.contains("enable_email_validated") ? j.at("enable_email_validated").get<bool>()
                                                                        : j.value("enable_public_links", true);
    }

    void to_json(nlohmann::json &j, const VaultsS3Config &c) {
        j = {
            {"default_remote_sync_strategy", c.default_remote_sync_strategy},
            {"default_remote_conflict_policy", c.default_remote_conflict_policy},
            {"tpm_retention_window", durationToString(c.tpm_retention_window)}
        };
    }

    void from_json(const nlohmann::json &j, VaultsS3Config &c) {
        const VaultsS3Config defaults;
        c.default_remote_sync_strategy = j.value("default_remote_sync_strategy", defaults.default_remote_sync_strategy);
        c.default_remote_conflict_policy = j.value("default_remote_conflict_policy", defaults.default_remote_conflict_policy);
        requireRemoteDefaults(c);
        if (j.contains("tpm_retention_window"))
            c.tpm_retention_window = parseDuration(j.at("tpm_retention_window").get<std::string>());
    }

    void to_json(nlohmann::json &j, const VaultsConfig &c) {
        j = {
            {"retention_window", durationToString(c.retention_window)},
            {"tpm_retention_window", durationToString(c.tpm_retention_window)},
            {"s3", c.s3}
        };
    }

    void from_json(const nlohmann::json &j, VaultsConfig &c) {
        if (j.contains("retention_window")) c.retention_window = parseDuration(j.at("retention_window").get<std::string>());
        if (j.contains("tpm_retention_window"))
            c.tpm_retention_window = parseDuration(j.at("tpm_retention_window").get<std::string>());
        if (j.contains("s3")) j.at("s3").get_to(c.s3);
    }

    void to_json(nlohmann::json &j, const ResendEmailConfig &c) {
        j = {
            {"endpoint", c.endpoint}
        };
    }

    void from_json(const nlohmann::json &j, ResendEmailConfig &c) {
        c.endpoint = j.value("endpoint", "https://api.resend.com/emails");
    }

    void to_json(nlohmann::json &j, const SesEmailConfig &c) {
        j = {
            {"region", c.region},
            {"endpoint", c.endpoint ? nlohmann::json(*c.endpoint) : nlohmann::json(nullptr)}
        };
    }

    void from_json(const nlohmann::json &j, SesEmailConfig &c) {
        c.region = j.value("region", "us-east-1");
        if (j.contains("endpoint") && !j.at("endpoint").is_null())
            c.endpoint = j.at("endpoint").get<std::string>();
        else
            c.endpoint.reset();
    }

    void to_json(nlohmann::json &j, const EmailConfig &c) {
        j = {
            {"enabled", c.enabled},
            {"provider", emailProviderKindToString(c.provider)},
            {"from", c.from},
            {"reply_to", c.reply_to ? nlohmann::json(*c.reply_to) : nlohmann::json(nullptr)},
            {"base_url", c.base_url ? nlohmann::json(*c.base_url) : nlohmann::json(nullptr)},
            {"resend", c.resend},
            {"ses", c.ses}
        };
    }

    void from_json(const nlohmann::json &j, EmailConfig &c) {
        c.enabled = j.value("enabled", false);
        c.provider = emailProviderKindFromString(j.value("provider", "none"));
        c.from = j.value("from", "Vaulthalla <ops@example.com>");

        if (j.contains("reply_to") && !j.at("reply_to").is_null())
            c.reply_to = j.at("reply_to").get<std::string>();
        else
            c.reply_to.reset();

        if (j.contains("base_url") && !j.at("base_url").is_null())
            c.base_url = j.at("base_url").get<std::string>();
        else
            c.base_url.reset();

        if (j.contains("resend")) j.at("resend").get_to(c.resend);
        if (j.contains("ses")) j.at("ses").get_to(c.ses);
    }

    void to_json(nlohmann::json &j, const OperatorEmailRecipientsConfig &c) {
        j = {
            {"alerts", c.alerts},
            {"weekly", c.weekly},
            {"security", c.security}
        };
    }

    void from_json(const nlohmann::json &j, OperatorEmailRecipientsConfig &c) {
        c.alerts = j.value("alerts", std::vector<std::string>{});
        c.weekly = j.value("weekly", std::vector<std::string>{});
        c.security = j.value("security", std::vector<std::string>{});
    }

    void to_json(nlohmann::json &j, const OperatorEmailAlertingConfig &c) {
        j = {
            {"enabled", c.enabled},
            {"min_severity", c.min_severity},
            {"dedupe_window_minutes", c.dedupe_window_minutes},
            {"repeat_after_hours", c.repeat_after_hours},
            {"send_recovery", c.send_recovery},
            {"health_poll_seconds", c.health_poll_seconds}
        };
    }

    void from_json(const nlohmann::json &j, OperatorEmailAlertingConfig &c) {
        c.enabled = j.value("enabled", true);
        c.min_severity = j.value("min_severity", "warning");
        c.dedupe_window_minutes = std::max(1u, j.value("dedupe_window_minutes", 60u));
        c.repeat_after_hours = std::max(1u, j.value("repeat_after_hours", 24u));
        c.send_recovery = j.value("send_recovery", true);
        c.health_poll_seconds = std::max(15u, j.value("health_poll_seconds", 60u));
    }

    void to_json(nlohmann::json &j, const OperatorEmailDigestConfig &c) {
        j = {
            {"enabled", c.enabled},
            {"weekday", c.weekday},
            {"hour_local", c.hour_local},
            {"timezone", c.timezone}
        };
    }

    void from_json(const nlohmann::json &j, OperatorEmailDigestConfig &c) {
        c.enabled = j.value("enabled", true);
        c.weekday = j.value("weekday", "monday");
        c.hour_local = std::min(23u, j.value("hour_local", 8u));
        c.timezone = j.value("timezone", "UTC");
    }

    void to_json(nlohmann::json &j, const OperatorEmailSecurityAlertsConfig &c) {
        j = {
            {"enabled", c.enabled},
            {"admin_role_changes", c.admin_role_changes}
        };
    }

    void from_json(const nlohmann::json &j, OperatorEmailSecurityAlertsConfig &c) {
        c.enabled = j.value("enabled", true);
        c.admin_role_changes = j.value("admin_role_changes", true);
    }

    void to_json(nlohmann::json &j, const OperatorEmailsConfig &c) {
        j = {
            {"enabled", c.enabled},
            {"recipients", c.recipients},
            {"alerting", c.alerting},
            {"weekly_digest", c.weekly_digest},
            {"security_alerts", c.security_alerts}
        };
    }

    void from_json(const nlohmann::json &j, OperatorEmailsConfig &c) {
        c.enabled = j.value("enabled", true);
        if (j.contains("recipients")) j.at("recipients").get_to(c.recipients);
        if (j.contains("alerting")) j.at("alerting").get_to(c.alerting);
        if (j.contains("weekly_digest")) j.at("weekly_digest").get_to(c.weekly_digest);
        if (j.contains("security_alerts")) j.at("security_alerts").get_to(c.security_alerts);
    }

    void to_json(nlohmann::json &j, const AuditLogConfig &c) {
        j = {
            {"retention_days", c.retention_days.count()},
            {"rotate_max_size", bytesToMbOrGbStr(c.rotate_max_size)},
            {"rotate_interval", hoursToDayOrHourStr(c.rotate_interval)},
            {"compression", compressionToString(c.compression)},
            {"max_retained_logs_size", bytesToMbOrGbStr(c.max_retained_logs_size)},
            {"strict_retention", c.strict_retention}
        };
    }

    void from_json(const nlohmann::json &j, AuditLogConfig &c) {
        c.retention_days = std::chrono::days(j.value("retention_days", 30));
        c.rotate_max_size = parseMbOrGbToByte(j.value("rotate_max_size", "50MB"));
        c.rotate_interval = parseHoursFromDayOrHour(j.value("rotate_interval", "24h"));
        c.compression = parseCompression(j.value("compression", "zstd"));
        c.max_retained_logs_size = parseMbOrGbToByte(j.value("max_retained_logs_size", "1GB"));
        c.strict_retention = j.value("strict_retention", false);
    }

    void to_json(nlohmann::json &j, const EncryptionWaiverConfig &c) {
        j = {
            {"retention_days", c.retention_days.count()}
        };
    }

    void from_json(const nlohmann::json &j, EncryptionWaiverConfig &c) {
        c.retention_days = std::chrono::days(j.value("retention_days", 180));
    }

    void to_json(nlohmann::json &j, const FilesTrashedConfig &c) {
        j = {
            {"retention_days", c.retention_days.count()}
        };
    }

    void from_json(const nlohmann::json &j, FilesTrashedConfig &c) {
        c.retention_days = std::chrono::days(j.value("retention_days", 60));
    }

    void to_json(nlohmann::json &j, const AuditConfig &c) {
        j = {
            {"audit_log", c.audit_log},
            {"encryption_waivers", c.encryption_waivers},
            {"files_trashed", c.files_trashed}
        };
    }

    void from_json(const nlohmann::json &j, AuditConfig &c) {
        j.at("audit_log").get_to(c.audit_log);
        j.at("encryption_waivers").get_to(c.encryption_waivers);
        j.at("files_trashed").get_to(c.files_trashed);
    }

    void to_json(nlohmann::json &j, const DevConfig &c) {
        j = {
            {"enabled", c.enabled},
            {"init_r2_test_vault", c.init_r2_test_vault}
        };
    }

    void from_json(const nlohmann::json &j, DevConfig &c) {
        c.enabled = j.value("enabled", false);
        c.init_r2_test_vault = j.value("init_r2_test_vault", false);
    }
} // namespace vh::config
