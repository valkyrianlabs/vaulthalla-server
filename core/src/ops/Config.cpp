#include "ops/Config.hpp"

#include "config/Registry.hpp"
#include "email/Message.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "rbac/PolicyEpoch.hpp"
#include "rbac/permission/admin/S3Gateway.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "protocols/device/Service.hpp"
#include "runtime/Manager.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <initializer_list>
#include <cctype>
#include <string>

namespace vh::ops::config {

namespace {

std::string lower(std::string value) {
    std::ranges::transform(value, value.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

const nlohmann::json* at(const nlohmann::json& doc, std::initializer_list<const char*> path) {
    const nlohmann::json* node = &doc;
    for (const auto* key : path) {
        if (!node->is_object() || !node->contains(key)) return nullptr;
        node = &node->at(key);
    }
    return node;
}

// Numbers the config loader would clamp: an API write must say what it means.
void requireRange(const nlohmann::json& doc, std::initializer_list<const char*> path, const int64_t min, const int64_t max,
                  const std::string& name) {
    const auto* node = at(doc, path);
    if (!node || node->is_null()) return;
    if (!node->is_number_integer() || node->get<int64_t>() < min || node->get<int64_t>() > max)
        throw Invalid(name + " must be an integer from " + std::to_string(min) +
                      (max == INT64_MAX ? " up" : " to " + std::to_string(max)));
}

void requireNonEmpty(const nlohmann::json& doc, std::initializer_list<const char*> path, const std::string& name) {
    const auto* node = at(doc, path);
    if (node && node->is_string() && node->get<std::string>().empty()) throw Invalid(name + " cannot be empty");
}

void requireAddress(const std::string& value, const std::string& name) {
    try {
        (void)email::parseAddress(value);
    } catch (const std::exception& e) {
        throw Invalid(name + ": " + e.what());
    }
}

void validateEmail(const Config& cfg) {
    requireAddress(cfg.email.from, "email.from");
    if (cfg.email.reply_to) requireAddress(*cfg.email.reply_to, "email.reply_to");
    for (const auto* group : {&cfg.operator_emails.recipients.alerts, &cfg.operator_emails.recipients.weekly,
                              &cfg.operator_emails.recipients.security})
        for (const auto& recipient : *group) requireAddress(recipient, "operator_emails.recipients");

    static constexpr std::array days{"sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"};
    if (std::ranges::find(days, lower(cfg.operator_emails.weekly_digest.weekday)) == days.end())
        throw Invalid("operator_emails.weekly_digest.weekday must be sunday through saturday");
    static constexpr std::array severities{"info", "warning", "critical"};
    if (std::ranges::find(severities, lower(cfg.operator_emails.alerting.min_severity)) == severities.end())
        throw Invalid("operator_emails.alerting.min_severity must be info, warning, or critical");
}

// `restartGateway`: restart it even if s3_gateway.enabled is unchanged (the explicit enable/disable commands).
Config commit(const Config& next, const bool restartGateway = false) {
    const bool gatewayWas = vh::config::Registry::get().s3_gateway.enabled;
    const auto deviceServerWas = nlohmann::json(vh::config::Registry::get().device_server);
    const bool sharingChanged = nlohmann::json(vh::config::Registry::get().sharing) != nlohmann::json(next.sharing);
    next.save();
    vh::config::Registry::set(next);
    // Share principals cached under the old switches (HTTP access, 15 s) must not outlive them.
    if (sharingChanged) {
        rbac::bumpPolicyEpoch();
        log::Registry::audit()->info("[ops::config] sharing -> {}", nlohmann::json(next.sharing).dump());
    }
    if (restartGateway || next.s3_gateway.enabled != gatewayWas) {
        auto& runtime = runtime::Manager::instance();
        // Only a daemon that runs the gateway restarts it; elsewhere the change applies on the next start.
        if (runtime.getS3GatewayService()) runtime.restartService("S3GatewayService");
        log::Registry::audit()->info("[ops::config] s3_gateway.enabled -> {}", next.s3_gateway.enabled);
    }
    // The device listener rebinds in place (remote connections on/off); nothing else restarts.
    if (nlohmann::json(next.device_server) != deviceServerWas) {
        if (const auto deviceServer = runtime::Manager::instance().getDeviceServer()) (void)deviceServer->applyConfig();
        log::Registry::audit()->info("[ops::config] device_server -> {}", nlohmann::json(next.device_server).dump());
    }
    return next;
}

}

void validateSettings(const nlohmann::json& settings) {
    if (!settings.is_object()) throw Invalid("settings must be an object of sections");
    requireRange(settings, {"operator_emails", "weekly_digest", "hour_local"}, 0, 23, "operator_emails.weekly_digest.hour_local");
    requireRange(settings, {"operator_emails", "alerting", "dedupe_window_minutes"}, 1, INT64_MAX,
                 "operator_emails.alerting.dedupe_window_minutes");
    requireRange(settings, {"operator_emails", "alerting", "repeat_after_hours"}, 1, INT64_MAX,
                 "operator_emails.alerting.repeat_after_hours");
    requireRange(settings, {"operator_emails", "alerting", "health_poll_seconds"}, 15, INT64_MAX,
                 "operator_emails.alerting.health_poll_seconds");
    // Both servers refuse connections past these caps; there is no "unlimited" value.
    requireRange(settings, {"websocket_server", "max_connections"}, 1, 1'000'000, "websocket_server.max_connections");
    requireRange(settings, {"http_preview_server", "max_connections"}, 1, 1'000'000,
                 "http_preview_server.max_connections");
    requireNonEmpty(settings, {"operator_emails", "weekly_digest", "timezone"}, "operator_emails.weekly_digest.timezone");
    requireNonEmpty(settings, {"email", "resend", "endpoint"}, "email.resend.endpoint");
    requireNonEmpty(settings, {"email", "ses", "region"}, "email.ses.region");
    try {
        const Config next(settings);
        validateEmail(next);
        // Which executables the daemon runs is not a console/CLI setting: the operator edits config.yaml (and the
        // runner only executes root-owned helpers in root-owned directories either way).
        if (next.preview.derive.helper_dir != vh::config::Registry::get().preview.derive.helper_dir)
            throw Invalid("preview.derive.helper_dir cannot be changed here; set it in /etc/vaulthalla/config.yaml");
    } catch (const Error&) {
        throw;
    } catch (const std::exception& e) {
        throw Invalid(std::string("invalid settings: ") + e.what());
    }
}

Config saveSettings(const Actor& actor, const nlohmann::json& settings) {
    requireActor(actor);
    if (!actor->isSuperAdmin()) throw Denied("only super admins may change settings");
    validateSettings(settings);
    return commit(Config(settings));
}

Config setDeviceRemote(const Actor& actor, const bool enabled) {
    requireActor(actor);
    if (!actor->isSuperAdmin()) throw Denied("only super admins may turn remote device connections on or off");
    auto next = vh::config::Registry::get();
    next.device_server.remote = enabled;
    return commit(next);
}

Config setGatewayEnabled(const Actor& actor, const bool enabled) {
    requireActor(actor);
    using Perm = rbac::permission::admin::S3GatewayPermissions;
    if (!actor->isSuperAdmin() && !rbac::resolver::Admin::has<Perm>({.user = actor, .permission = Perm::ManageService}))
        throw Denied("admin.s3_gateway.manage_service is required to enable or disable the S3 gateway");
    auto next = vh::config::Registry::get();
    next.s3_gateway.enabled = enabled;
    return commit(next, true);
}

}
