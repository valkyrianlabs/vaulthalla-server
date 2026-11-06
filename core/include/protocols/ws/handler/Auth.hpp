#pragma once

#include <nlohmann/json.hpp>
#include <string>
#include <memory>
#include "identities/Fwd.hpp"
#include "protocols/ws/Fwd.hpp"

namespace vh::protocols::ws::handler {

using json = nlohmann::json;

struct Auth {
    // The signed-in user for session payloads (login, refresh, isAuthenticated): role permissions as {qualified, value}.
    static json sessionUser(const identities::User& user);
    static json login(const json& payload, const std::shared_ptr<Session>& session);
    static json registerUser(const json& payload, const std::shared_ptr<Session>& session);
    static json deleteUser(const json& payload, const std::shared_ptr<Session>& session);
    static json updateUser(const json& payload, const std::shared_ptr<Session>& session);
    static json changePassword(const json& payload, const std::shared_ptr<Session>& session);
    static json getUser(const json& payload, const std::shared_ptr<Session>& session);
    static json getUserByName(const json& payload, const std::shared_ptr<Session>& session);

    static json refreshToken(const std::string& token, const std::shared_ptr<Session>& session);
    static json isUserAuthenticated(const std::string& token, const std::shared_ptr<Session>& session);

    static json listUsers(const std::shared_ptr<Session>& session);
    static json logout(const std::shared_ptr<Session>& session);
    static json activity(const std::shared_ptr<Session>& session);

    // The caller's own signed-in web sessions (#354, ops/Sessions.hpp): auth.sessions.list / auth.sessions.revoke.
    static json listSessions(const std::shared_ptr<Session>& session);
    static json revokeSessions(const json& payload, const std::shared_ptr<Session>& session);

    // {initial_password_file: path | null}: set for the super admin while its generated password is still in use
    // and the plaintext copy is still on disk.
    static json securityStatus(const std::shared_ptr<Session>& session);
};

}
