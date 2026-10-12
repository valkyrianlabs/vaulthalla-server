#pragma once

#include "concurrency/AtomicSharedPtr.hpp"

#include <atomic>
#include <ctime>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <unordered_map>
#include <nlohmann/json_fwd.hpp>
#include "identities/Fwd.hpp"
#include "rbac/Fwd.hpp"
#include "db/Fwd.hpp"

namespace vh::identities {

struct GroupMember {
    std::shared_ptr<User> user;   // canonical
    std::time_t joined_at{};
};

// One immutable version of a group (see UserState). Membership is not part of it: it lives on the member's UserState,
// so a member list is never copied into every user and a group's own change (rename, vault roles, overrides) reaches
// every member through the canonical Group without rebuilding any user.
struct GroupState {
    struct RoleAssignments {
        std::unordered_map<uint32_t, std::shared_ptr<const rbac::role::Vault>> vaults{};
    };

    std::optional<unsigned int> linux_gid{std::nullopt};
    std::string name;
    std::optional<std::string> description{std::nullopt};
    std::time_t created_at{};
    std::optional<std::time_t> updated_at{std::nullopt};

    RoleAssignments roles{};

    bool deleted = false;
    uint64_t revision = 0;
};

// The canonical, stable identity of one group (see User).
class Group final : public std::enable_shared_from_this<Group> {
public:
    const unsigned int id;

    Group(const Group&) = delete;
    Group& operator=(const Group&) = delete;

    [[nodiscard]] static std::shared_ptr<Group> detached(unsigned int id, GroupState state);

    [[nodiscard]] std::shared_ptr<const GroupState> state() const noexcept {
        return state_.load();
    }

    [[nodiscard]] std::string name() const;
    [[nodiscard]] std::optional<unsigned int> linuxGid() const;
    [[nodiscard]] std::optional<std::string> description() const;
    [[nodiscard]] bool deleted() const;

    void replaceDetachedState(GroupState next);

private:
    friend class Manager;

    Group(unsigned int id, std::shared_ptr<const GroupState> initial, bool detached);

    void publish(std::shared_ptr<const GroupState> next) noexcept { state_.store(std::move(next)); }

    concurrency::AtomicSharedPtr<const GroupState> state_;
    const bool detached_;
};

[[nodiscard]] GroupState groupStateFromRow(pqxx::row_ref row);

// `members` (from identities::Manager::members) is optional: the list views omit it.
nlohmann::json to_json(const Group& g, const std::vector<GroupMember>* members = nullptr);
nlohmann::json to_json(const std::shared_ptr<Group>& g);
nlohmann::json to_json(const std::vector<std::shared_ptr<Group>>& groups);

void to_json(nlohmann::json& j, const GroupMember& gm);
nlohmann::json to_json(const std::vector<GroupMember>& members);

std::string to_string(const std::shared_ptr<Group>& g, const std::vector<GroupMember>* members = nullptr);
std::string to_string(const std::vector<std::shared_ptr<Group>>& groups);
std::string to_string(const GroupMember& gm);
std::string to_string(const std::vector<GroupMember>& members);

}
