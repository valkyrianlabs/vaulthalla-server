#include "protocols/ws/handler/Auth.hpp"
#include "ops/Error.hpp"
#include "runtime/Deps.hpp"
#include "auth/Bootstrap.hpp"
#include "auth/Manager.hpp"
#include "auth/session/Validator.hpp"
#include "identities/User.hpp"
#include "db/query/identities/User.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/ShareRateLimit.hpp"
#include "ops/Users.hpp"

using namespace vh::protocols::ws::handler;
using namespace vh::auth;
using vh::identities::User;
using vh::identities::Group;

namespace {
// Account-management handlers are routed only for authenticated human sessions, but never trust that here: a null
// session user would be a daemon-killing null dereference, not a catchable error.
const std::shared_ptr<User>& requireSessionUser(const std::shared_ptr<vh::protocols::ws::Session>& session) {
    if (!session || !session->user) throw std::runtime_error("User not authenticated");
    return session->user;
}

}

// The signed-in user as the console session needs it: role permissions reduced to {qualified, value}. The full
// permission records (descriptions, slugs, bit positions) are ~13 KB per user and are served by auth.user.get and
// roles.*; the session payload is sent on every page load.
json Auth::sessionUser(const User& user) {
    json j = user;
    const auto slim = [](json& permissions) {
        if (!permissions.is_array()) return;
        json out = json::array();
        for (const auto& p : permissions)
            out.push_back({{"qualified", p.value("qualified", std::string{})}, {"value", p.value("value", false)}});
        permissions = std::move(out);
    };
    if (j.contains("admin_role") && j["admin_role"].is_object() && j["admin_role"].contains("permissions"))
        slim(j["admin_role"]["permissions"]);
    if (j.contains("vault_roles") && j["vault_roles"].is_array())
        for (auto& role : j["vault_roles"])
            if (role.is_object() && role.contains("permissions")) slim(role["permissions"]);
    return j;
}

json Auth::login(const json &payload, const std::shared_ptr<Session> &session) {
    const auto username = payload.at("name").get<std::string>();
    const auto password = payload.at("password").get<std::string>();

    try {
        runtime::Deps::get().authManager->loginUser(username, password, session);
    } catch (...) {
        // Only failed attempts count toward the auth.login rate limit (#103).
        if (session) vh::protocols::ws::ShareRateLimit::instance().recordLoginFailure(username, *session);
        throw;
    }
    if (!session::Validator::softValidateActiveSession(session)) throw std::runtime_error(
        "Failed to validate session after login");

    session->sendAccessTokenOnNextResponse();
    return {{"user", Auth::sessionUser(*session->user)}};
}

json Auth::registerUser(const json &payload, const std::shared_ptr<Session> &session) {
    const auto created = ops::users::create(requireSessionUser(session), {
        .name = payload.at("name").get<std::string>(),
        .role = payload.at("role").get<std::string>(),
        .email = payload.contains("email") && payload.at("email").is_string()
            ? std::optional<std::string>(payload.at("email").get<std::string>()) : std::nullopt,
        .password = payload.at("password").get<std::string>(),
        .is_active = payload.value("is_active", true)
    });
    return {{"user", *created.user}};
}

json Auth::refreshToken(const std::string &token, const std::shared_ptr<Session> &session) {
    runtime::Deps::get().sessionManager->renewAccessToken(session, token);
    if (!session->user) throw std::runtime_error("Failed to resolve user during token refresh");
    return {{"user", Auth::sessionUser(*session->user)}};
}

json Auth::deleteUser(const json &payload, const std::shared_ptr<Session> &session) {
    // Without confirm the reply is an error with data.code "user_delete" and the text to show; the web asks, then
    // resends with confirm (and transfer_to to keep the vaults).
    ops::users::Remove req{.id = payload.at("id").get<unsigned int>(), .confirmed = payload.value("confirm", false)};
    if (payload.contains("transfer_to") && !payload.at("transfer_to").is_null())
        req.transfer_to = payload.at("transfer_to").get<unsigned int>();
    const auto removed = ops::users::remove(requireSessionUser(session), req);
    return {{"user_id", removed->id}};
}

json Auth::updateUser(const json &payload, const std::shared_ptr<Session> &session) {
    const auto& actor = requireSessionUser(session);

    // CLI identity is bound by Linux UID; rebinding it is an operator action on the local CLI only.
    if (payload.contains("linux_uid"))
        throw vh::ops::Denied("linux_uid can only be changed by an administrator through the local CLI");
    if (payload.contains("updated_by") || payload.contains("protected") || payload.contains("is_protected") ||
        payload.contains("system_only"))
        throw std::runtime_error("Unsupported field in user update");
    if (payload.contains("password") && payload.at("password").is_string() &&
        !payload.at("password").get<std::string>().empty())
        throw std::runtime_error("Use auth.user.change_password to change or reset a password");

    // The web edit form targets payload.id; without one the caller edits themselves.
    ops::users::Update req{
        .id = payload.contains("id") && !payload.at("id").is_null() ? payload.at("id").get<unsigned int>() : actor->id
    };
    if (payload.contains("name") && !payload.at("name").is_null()) req.name = payload.at("name").get<std::string>();
    if (payload.contains("email"))
        req.email = payload.at("email").is_null() ? std::optional<std::string>{}
                                                 : std::optional<std::string>{payload.at("email").get<std::string>()};
    if (payload.contains("is_active") && !payload.at("is_active").is_null()) req.is_active = payload.at("is_active").get<bool>();
    if (payload.contains("role") && payload.at("role").is_string() && !payload.at("role").get<std::string>().empty())
        req.role = payload.at("role").get<std::string>();

    const auto updated = ops::users::update(actor, req);
    if (updated->id == actor->id) session->user = updated;
    return {{"user", *updated}};
}

json Auth::changePassword(const json &payload, const std::shared_ptr<Session> &session) {
    const auto& actor = requireSessionUser(session);
    const auto current = payload.contains("old_password") && payload.at("old_password").is_string()
        ? std::optional<std::string>(payload.at("old_password").get<std::string>()) : std::nullopt;
    const auto updated = ops::users::changePassword(actor, payload.at("id").get<unsigned int>(), current,
                                                    payload.at("new_password").get<std::string>());
    if (updated->id == actor->id) session->user = updated;
    return {{"user", *updated}};
}

json Auth::getUser(const json &payload, const std::shared_ptr<Session> &session) {
    return {{"user", *ops::users::get(requireSessionUser(session), payload.at("id").get<unsigned int>())}};
}

json Auth::logout(const std::shared_ptr<Session> &session) {
    runtime::Deps::get().sessionManager->invalidate(session);
    return {};
}

json Auth::listUsers(const std::shared_ptr<Session> &session) {
    // The slim list projection; auth.user.get keeps the full role with its permissions.
    return {{"users", vh::identities::to_list_json(ops::users::list(requireSessionUser(session)))}};
}

json Auth::isUserAuthenticated(const std::string &token, const std::shared_ptr<Session> &session) {
    const bool isAuthenticated = runtime::Deps::get().sessionManager->validate(session, token);
    json data = {{"isAuthenticated", isAuthenticated}};
    if (isAuthenticated) data["user"] = Auth::sessionUser(*session->user);
    return data;
}

json Auth::getUserByName(const json &payload, const std::shared_ptr<Session> &session) {
    return {{"user", *ops::users::getByName(requireSessionUser(session), payload.at("name").get<std::string>())}};
}

// Security posture for a warning in the web console, never a gate: a signed-in session is fully usable either way.
// Only the super admin pays for the check (one row read, one stat), and only when the console asks for it (after
// sign-in and on a page load).
json Auth::securityStatus(const std::shared_ptr<Session>& session) {
    const auto& user = requireSessionUser(session);
    json out = {{"initial_password_file", nullptr}};
    if (user->name() == auth::bootstrap::kSuperAdminName && auth::bootstrap::initialPasswordExposed())
        out["initial_password_file"] = auth::bootstrap::initialPasswordFile().string();
    return out;
}
