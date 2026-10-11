#pragma once

#include "identities/Fwd.hpp"

#include <optional>
#include <string>

namespace vh::db::query::identities {

// Row writes behind identities::Manager (the only caller: identity state changes go through the Manager so every
// canonical object is republished). Reads are identities::Manager / db::query::identities::Loader.
class User {
public:
    // Inserts the account with its admin role, global vault policy and direct vault roles. Returns the new id.
    static unsigned int createUser(const vh::identities::UserState& draft, const std::string& passwordHash);

    // Name, email, active flag, Linux uid, updated_by, admin role, global vault policy and direct vault roles. Never
    // the password hash.
    static void updateUser(unsigned int id, const vh::identities::UserState& next);

    static void updateUserPassword(unsigned int userId, const std::string& passwordHash);
    static void deleteUser(unsigned int userId);
    static void updateLastLoggedInUser(unsigned int userId);
    static void bootstrapSetAdminLinuxUID(unsigned int linuxUid, std::optional<unsigned int> updatedBy = std::nullopt);

    [[nodiscard]] static bool authenticateUser(const std::string& name, const std::string& password);
    [[nodiscard]] static bool userExists(const std::string& name);
    [[nodiscard]] static bool adminUserExists();
};

}
