#include "protocols/ws/handler/Settings.hpp"
#include "ops/Error.hpp"
#include "identities/User.hpp"
#include "protocols/ws/Session.hpp"
#include "config/Registry.hpp"
#include "config/Config.hpp"
#include "ops/Config.hpp"

#include <nlohmann/json.hpp>

namespace vh::protocols::ws::handler {

json Settings::get(const std::shared_ptr<Session>& session) {
    // TODO: need to make settings granular by permissions
    if (!session->user->isSuperAdmin()) throw vh::ops::Denied("Permission denied: Only admins can view settings");
    return {{"settings", vh::config::Registry::get()}};
}

json Settings::policy(const std::shared_ptr<Session>& session) {
    if (!session || !session->user) throw std::runtime_error("User not authenticated");
    const auto& cfg = vh::config::Registry::get();
    return {{"policy", {{"sharing", cfg.sharing}, {"vaults", cfg.vaults}}}};
}

json Settings::update(const json& payload, const std::shared_ptr<Session>& session) {
    if (!session || !session->user) throw std::runtime_error("User not authenticated");
    if (!payload.is_object()) throw vh::ops::Invalid("settings.update expects an object of settings sections");

    // Partial update: merge the payload onto the current settings so sections/fields the client didn't send
    // (or doesn't model) keep their values instead of being reset or rejected. Secrets are not part of this
    // JSON (the DB password is TPM-sealed, the JWT secret lives in the secrets manager) and can't be set here.
    // ops::config validates (email included) and applies it (an s3_gateway.enabled change restarts the gateway).
    nlohmann::json merged = vh::config::Registry::get();
    merged.merge_patch(payload);
    return {{"settings", ops::config::saveSettings(session->user, merged)}};
}

}
