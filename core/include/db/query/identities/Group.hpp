#pragma once

#include "identities/Fwd.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace vh::db::query::identities {

// Row writes behind identities::Manager (see User.hpp). Reads are identities::Manager / Loader.
class Group {
public:
    static uint32_t createGroup(const vh::identities::GroupState& draft);
    static void updateGroup(uint32_t id, const vh::identities::GroupState& next);
    static void deleteGroup(uint32_t groupId);
    static void addMembersToGroup(uint32_t group, const std::vector<uint32_t>& members);
    static void removeMembersFromGroup(uint32_t group, const std::vector<uint32_t>& members);
    [[nodiscard]] static bool groupExists(const std::string& name);
};

}
