#pragma once

// Identity fixtures for tests. Accounts and groups are created through identities::Manager (as every product path
// does), so the objects a test holds are the canonical ones and see later changes.

#include "identities/Group.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "rbac/role/Admin.hpp"

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace vh::test::identities {

using vh::identities::Group;
using vh::identities::GroupState;
using vh::identities::User;
using vh::identities::UserState;

inline std::shared_ptr<User> createUser(const std::string& name, std::shared_ptr<rbac::role::Admin> role,
                                        std::optional<std::string> email = std::nullopt,
                                        const std::string& passwordHash = "x",
                                        std::optional<uint32_t> linuxUid = std::nullopt) {
    UserState draft;
    draft.name = name;
    draft.email = std::move(email);
    draft.meta.linux_uid = linuxUid;
    draft.roles.admin = std::move(role);
    return vh::identities::manager().createUser(draft, passwordHash);
}

inline std::shared_ptr<Group> createGroup(const std::string& name, std::optional<std::string> description = std::nullopt,
                                          std::optional<unsigned int> linuxGid = std::nullopt) {
    GroupState draft;
    draft.name = name;
    draft.description = std::move(description);
    draft.linux_gid = linuxGid;
    return vh::identities::manager().createGroup(draft);
}

inline void addMember(const uint32_t groupId, const uint32_t userId) {
    vh::identities::manager().addMembers(groupId, {userId});
}

inline bool isMember(const uint32_t groupId, const uint32_t userId) {
    for (const auto& m : vh::identities::manager().members(groupId))
        if (m.user->id == userId) return true;
    return false;
}

// A user outside the Manager (DB-free tests).
inline std::shared_ptr<User> detachedUser(const uint32_t id, const std::string& name,
                                          std::shared_ptr<rbac::role::Admin> role = nullptr) {
    UserState s;
    s.name = name;
    s.roles.admin = std::move(role);
    return User::detached(id, std::move(s));
}

}
