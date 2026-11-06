#pragma once

#include "session/Manager.hpp"
#include "auth/Fwd.hpp"
#include "identities/Fwd.hpp"
#include "protocols/ws/Fwd.hpp"
#include "storage/Fwd.hpp"

#include <memory>
#include <string>
#include <string_view>

namespace vh::auth {

class Manager {
public:
    // Creates the account (through identities::Manager) and its storage; returns the canonical user.
    std::shared_ptr<identities::User> registerUser(const identities::UserState& draft, const std::string& password);

    // Signs the socket in with a password (aal 1, amr {pwd}). Refused with ops::Refused(kAlreadySignedIn) when the
    // socket already has a user. Throws std::runtime_error(kLoginFailed) for every other refusal: unknown name, wrong
    // password, deactivated or system-only account (#321). The specific reason is logged, never returned.
    void loginUser(const std::string& name, const std::string& password,
                                      const std::shared_ptr<protocols::ws::Session>& session);
    static const char* const kLoginFailed;
    // ops::Refused code for a sign-in on a connection that already has a user (#354).
    static const std::string_view kAlreadySignedIn;

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
