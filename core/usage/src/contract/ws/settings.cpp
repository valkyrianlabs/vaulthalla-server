// ws book: settings.* (core/src/protocols/ws/handler/Settings.cpp → ops::config). Shapes: the config::Config
// serializers (core/src/config/Config.cpp, to_json).

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

// The top-level sections of the settings document (config::Config's to_json), each a partial object in a patch.
std::vector<WsField> settingsPatchSections() {
    std::vector<WsField> out;
    for (const auto* section : {"websocket_server", "http_preview_server", "s3_gateway", "caching", "preview",
                                "database", "auth", "sync", "pricing", "services", "stats_snapshots", "sharing",
                                "vaults", "email", "operator_emails", "auditing", "logging", "dev"})
        out.push_back(object(section).opt().desc("Partial section: only the members to change."));
    return out;
}

}

std::vector<WsCommandUsage> settingsCommands() {
    std::vector<WsCommandUsage> out;

    out.push_back({
        .command = "settings.get",
        .description = "The daemon's whole settings document (config.yaml as JSON, without secrets). Super admins only.",
        .input = "none",
        .response = {object("settings", "Settings")},
        .refusal_codes = {"denied", "unauthorized"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "settings.policy.get",
        .description = "What any signed-in user may know of the server policy: the sharing switches and the vault "
                       "defaults (vaults.s3.*).",
        .input = "none",
        .response = {object("policy", "", {object("sharing", "SharingConfig"), object("vaults", "VaultsConfig")})},
        .refusal_codes = {"unauthorized"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "settings.update",
        .description = "Change settings with a JSON merge patch (RFC 7386) onto the current document: send only the "
                       "members that change; null removes an optional key. The merged document is validated as a "
                       "whole and saved (a s3_gateway.enabled change restarts the gateway). Super admins only; "
                       "preview.derive.helper_dir can't be changed here.",
        .payload = settingsPatchSections(),
        .response = {object("settings", "Settings")},
        .refusal_codes = {"denied", "invalid", "unauthorized"},
        .untyped_refusals = {"invalid"},
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

}
