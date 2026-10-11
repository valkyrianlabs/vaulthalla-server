#pragma once

#include "identities/Group.hpp"
#include "identities/User.hpp"

#include <chrono>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <utility>
#include <vector>

// Bulk identity reads for identities::Manager. One REPEATABLE READ snapshot per load: the identity revision and every
// row come from the same point in commit order, and any number of users and groups cost the same ~8 statements (no
// per-user, per-group or per-assignment round trips, no group member lists, no password hashes).
namespace vh::db::query::identities {

struct UserRecord {
    uint32_t id{};
    vh::identities::UserState state;                          // groups not resolved: see memberships
    std::vector<std::pair<uint32_t, std::time_t>> memberships; // group id, joined_at
};

struct GroupRecord {
    uint32_t id{};
    vh::identities::GroupState state;
};

struct IdentitySelection {
    bool all = false;
    std::vector<uint32_t> userIds{};
    std::vector<uint32_t> groupIds{};
    std::optional<std::string> userName{};
    std::optional<uint32_t> linuxUid{};
    std::optional<std::string> groupName{};
    std::optional<uint32_t> linuxGid{};
};

struct IdentitySnapshot {
    uint64_t revision = 0;
    std::vector<UserRecord> users;    // the selected users that exist
    std::vector<GroupRecord> groups;  // the selected groups that exist + every group a loaded user belongs to
    std::vector<uint32_t> requestedUserIds;   // selected by id or resolved from a key (missing ones are deleted)
    std::vector<uint32_t> requestedGroupIds;
};

struct IdentityChange {
    std::string entity;   // user | group | admin_role | vault_role
    uint32_t id{};
    uint64_t revision{};
};

struct Credentials {
    uint32_t id{};
    std::string passwordHash;
    bool active = true;
    bool systemOnly = false;
};

class Loader {
public:
    [[nodiscard]] static IdentitySnapshot load(const IdentitySelection& selection);

    [[nodiscard]] static uint64_t currentRevision();

    // Changes after `since` up to the current revision; nullopt when the log no longer reaches back that far (pruned):
    // the caller must reload everything.
    [[nodiscard]] static std::optional<std::vector<IdentityChange>> changesSince(uint64_t since, uint64_t& upTo);

    static void pruneChangeLog(std::chrono::seconds olderThan);

    // Credential checks never go through cached identity state.
    [[nodiscard]] static std::optional<Credentials> credentialsByName(const std::string& name);
    [[nodiscard]] static std::optional<Credentials> credentialsById(uint32_t id);
};

}
