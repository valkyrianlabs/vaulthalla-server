#pragma once

#include <string>
#include <memory>
#include <optional>
#include "identities/Fwd.hpp"

namespace vh::auth::registration {

struct Validator {
    static void validateRegistration(const identities::UserState& user, const std::string& password);
    static bool isValidName(const std::string& name);
    static bool isValidEmail(const std::string& email);
    static bool isValidPassword(const std::string& password);
    // Why the password policy refuses this password, or nullopt when it doesn't. Skipped in test mode.
    static std::optional<std::string> passwordPolicyViolation(const std::string& password);
    // The checks that need no network (everything but the breach lookup), never skipped.
    static std::optional<std::string> localPasswordPolicyViolation(const std::string& password);
    static bool isValidGroup(const std::string& group);
};

}
