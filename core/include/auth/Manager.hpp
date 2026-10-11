#pragma once

#include "session/Manager.hpp"
#include "auth/Fwd.hpp"
#include "identities/Fwd.hpp"
#include "protocols/ws/Fwd.hpp"
#include "storage/Fwd.hpp"

#include <memory>
#include <string>

namespace vh::auth {

class Manager {
public:
    // Creates the account (through identities::Manager) and its storage; returns the canonical user.
    std::shared_ptr<identities::User> registerUser(const identities::UserState& draft, const std::string& password);

    void loginUser(const std::string& name, const std::string& password,
                                      const std::shared_ptr<protocols::ws::Session>& session);

    std::shared_ptr<identities::User> changePassword(uint32_t userId, const std::string& oldPassword,
                                                     const std::string& newPassword);
    std::shared_ptr<identities::User> resetPassword(uint32_t userId, const std::string& newPassword);

    std::shared_ptr<identities::User> getUser(const std::string& name);
    std::shared_ptr<identities::User> getUser(uint32_t id);

    // Ends every session the user has: revokes their refresh tokens and drops their live sessions, so the next
    // request on an open socket is refused. Used when an account is deleted, deactivated, re-roled or reset.
    void revokeSessions(uint32_t userId);
};

}
