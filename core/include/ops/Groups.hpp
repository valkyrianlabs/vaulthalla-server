#pragma once

#include "ops/Actor.hpp"
#include "db/model/ListQueryParams.hpp"
#include "identities/Group.hpp"

#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

// Group operations shared by `vh group ...` (shell/commands/group.cpp) and the ws group.* / groups.* commands
// (ws/handler/Groups.cpp). Authorization (the caller's admin identities.groups permissions), lookup, validation
// and persistence live here once; the frontends only parse their input and format the result.
namespace vh::ops::groups {

using GroupPtr = std::shared_ptr<identities::Group>;

// A group or user as the caller named it: by id, or by its unique name.
using Ref = std::variant<unsigned int, std::string>;
using UserRef = std::variant<unsigned int, std::string>;

struct Create {
    std::string name;
    std::string description{};
    std::optional<unsigned int> linux_gid{};
};

// Patch semantics: an empty optional leaves the field unchanged.
struct Update {
    Ref group;
    std::optional<std::string> name{};
    std::optional<std::string> description{};
    std::optional<unsigned int> linux_gid{};
};

struct Membership {
    Ref group;
    UserRef user;
};

[[nodiscard]] GroupPtr create(const Actor& actor, const Create& req);
[[nodiscard]] GroupPtr update(const Actor& actor, const Update& req);
// Returns the group as it was just before deletion.
GroupPtr remove(const Actor& actor, const Ref& group);
[[nodiscard]] GroupPtr get(const Actor& actor, const Ref& group);

// Every group for a caller who may view groups; otherwise the caller's own groups.
[[nodiscard]] std::vector<GroupPtr> list(const Actor& actor, db::model::ListQueryParams params = {});
// The groups `userId` belongs to. Viewing someone else's memberships needs the group view permission.
[[nodiscard]] std::vector<GroupPtr> listForUser(const Actor& actor, unsigned int userId);

// Both return the group as it is after the change.
GroupPtr addMember(const Actor& actor, const Membership& req);
GroupPtr removeMember(const Actor& actor, const Membership& req);
[[nodiscard]] std::vector<identities::GroupMember> members(const Actor& actor, const Ref& group);

}
