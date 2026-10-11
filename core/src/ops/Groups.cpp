#include "ops/Groups.hpp"
#include "rbac/PolicyEpoch.hpp"

#include "auth/registration/Validator.hpp"
#include "identities/Group.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "rbac/permission/admin/identities/Groups.hpp"

#include <string>
#include <utility>

namespace vh::ops::groups {

namespace {

rbac::permission::admin::identities::Groups perms(const Actor& actor) {
    requireActor(actor);
    return actor->groupPerms();
}

std::string describe(const Ref& ref) {
    if (const auto* id = std::get_if<unsigned int>(&ref)) return std::to_string(*id);
    return std::get<std::string>(ref);
}

GroupPtr findGroup(const Ref& ref) {
    if (const auto* id = std::get_if<unsigned int>(&ref)) {
        if (*id == 0) throw Invalid("group ID must be a positive integer");
        return identities::manager().group(*id);
    }
    return identities::manager().groupByName(std::get<std::string>(ref));
}

GroupPtr requireGroup(const Ref& ref) {
    auto group = findGroup(ref);
    if (!group) throw NotFound("group not found: " + describe(ref));
    return group;
}

std::shared_ptr<identities::User> requireUser(const UserRef& ref) {
    std::shared_ptr<identities::User> user;
    if (const auto* id = std::get_if<unsigned int>(&ref)) {
        if (*id == 0) throw Invalid("user ID must be a positive integer");
        user = identities::manager().user(*id);
    } else {
        user = identities::manager().userByName(std::get<std::string>(ref));
    }
    if (!user) throw NotFound("user not found: " + describe(ref));
    return user;
}

void validateName(const std::string& name) {
    if (!auth::registration::Validator::isValidGroup(name)) throw Invalid("invalid group name '" + name + "'");
}

void validateLinuxGid(const unsigned int gid) {
    if (gid == 0) throw Invalid("linux_gid must be a positive integer");
}

// Names and Linux GIDs are UNIQUE in the schema; refuse up front with a clear reason instead of a constraint
// violation. `selfId` is the group being updated (0 on create).
void requireNameFree(const std::string& name, const unsigned int selfId) {
    if (const auto other = identities::manager().groupByName(name); other && other->id != selfId)
        throw Conflict("group already exists: " + name);
}

void requireGidFree(const unsigned int gid, const unsigned int selfId) {
    if (const auto other = identities::manager().groupByLinuxGid(gid); other && other->id != selfId)
        throw Conflict("linux_gid " + std::to_string(gid) + " is already used by group '" + other->name() + "'");
}

}

GroupPtr create(const Actor& actor, const Create& req) {
    if (!perms(actor).canAdd()) throw Denied("you do not have permission to create groups");

    validateName(req.name);
    if (req.linux_gid) validateLinuxGid(*req.linux_gid);
    requireNameFree(req.name, 0);
    if (req.linux_gid) requireGidFree(*req.linux_gid, 0);

    identities::GroupState draft;
    draft.name = req.name;
    draft.description = req.description;
    draft.linux_gid = req.linux_gid;
    return identities::manager().createGroup(draft);
}

GroupPtr update(const Actor& actor, const Update& req) {
    const struct EpochOnExit { ~EpochOnExit() { rbac::bumpPolicyEpoch(); } } bumpPolicyEpochOnExit{};
    if (!perms(actor).canEdit()) throw Denied("you do not have permission to update groups");

    const auto group = requireGroup(req.group);
    if (req.name) {
        validateName(*req.name);
        requireNameFree(*req.name, group->id);
    }
    if (req.linux_gid) {
        validateLinuxGid(*req.linux_gid);
        requireGidFree(*req.linux_gid, group->id);
    }

    return identities::manager().updateGroup(group->id, [&](identities::GroupState& s) {
        if (req.name) s.name = *req.name;
        if (req.description) s.description = *req.description;
        if (req.linux_gid) s.linux_gid = *req.linux_gid;
    });
}

GroupPtr remove(const Actor& actor, const Ref& ref) {
    const struct EpochOnExit { ~EpochOnExit() { rbac::bumpPolicyEpoch(); } } bumpPolicyEpochOnExit{};
    if (!perms(actor).canDelete()) throw Denied("you do not have permission to delete groups");

    auto group = requireGroup(ref);
    identities::manager().deleteGroup(group->id);
    return group;
}

GroupPtr get(const Actor& actor, const Ref& ref) {
    if (!perms(actor).canView()) throw Denied("you do not have permission to view group information");
    return requireGroup(ref);
}

std::vector<GroupPtr> list(const Actor& actor, db::model::ListQueryParams params) {
    (void)params; // the group list was never paginated
    if (perms(actor).canView()) return identities::manager().groups();
    return identities::manager().groupsOf(actor->id);
}

std::vector<GroupPtr> listForUser(const Actor& actor, const unsigned int userId) {
    if (!perms(actor).canView() && userId != actor->id)
        throw Denied("you do not have permission to view another user's groups");
    return identities::manager().groupsOf(userId);
}

GroupPtr addMember(const Actor& actor, const Membership& req) {
    const struct EpochOnExit { ~EpochOnExit() { rbac::bumpPolicyEpoch(); } } bumpPolicyEpochOnExit{};
    if (!perms(actor).canAddMember()) throw Denied("you do not have permission to add users to groups");

    const auto group = requireGroup(req.group);
    const auto user = requireUser(req.user);
    identities::manager().addMembers(group->id, {user->id});
    return group;
}

GroupPtr removeMember(const Actor& actor, const Membership& req) {
    const struct EpochOnExit { ~EpochOnExit() { rbac::bumpPolicyEpoch(); } } bumpPolicyEpochOnExit{};
    if (!perms(actor).canRemoveMember()) throw Denied("you do not have permission to remove users from groups");

    const auto group = requireGroup(req.group);
    const auto user = requireUser(req.user);
    identities::manager().removeMembers(group->id, {user->id});
    return group;
}

std::vector<identities::GroupMember> members(const Actor& actor, const Ref& ref) {
    if (!perms(actor).canViewMembers()) throw Denied("you do not have permission to view group members");
    return identities::manager().members(requireGroup(ref)->id);
}

}
