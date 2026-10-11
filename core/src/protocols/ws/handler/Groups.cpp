#include "protocols/ws/handler/Groups.hpp"
#include "protocols/ws/Session.hpp"
#include "identities/Group.hpp"
#include "ops/Groups.hpp"

#include <nlohmann/json.hpp>

using namespace vh::protocols::ws::handler;

namespace {

namespace group_ops = vh::ops::groups;

std::optional<std::string> groupPayloadString(const json& payload, const char* key) {
    if (!payload.contains(key) || payload.at(key).is_null()) return std::nullopt;
    return payload.at(key).get<std::string>();
}

std::optional<unsigned int> groupPayloadUInt(const json& payload, const char* key) {
    if (!payload.contains(key) || payload.at(key).is_null()) return std::nullopt;
    return payload.at(key).get<unsigned int>();
}

// WebSocketCommandMap types group.member.* as {group_id, user_id}. The handlers used to read groupId plus
// memberName (add) or userId (remove), so the console's calls failed; both spellings are accepted.
group_ops::Ref memberGroupRef(const json& payload) {
    if (const auto id = groupPayloadUInt(payload, "group_id")) return *id;
    return payload.at("groupId").get<unsigned int>();
}

group_ops::UserRef memberUserRef(const json& payload) {
    if (const auto id = groupPayloadUInt(payload, "user_id")) return *id;
    if (const auto id = groupPayloadUInt(payload, "userId")) return *id;
    return payload.at("memberName").get<std::string>();
}

json membershipResponse(const group_ops::GroupPtr& group, const json& payload) {
    json out{{"group", vh::identities::to_json(group)}, {"group_id", group->id}};
    // Echo whichever member keys the caller used, so legacy {groupId, memberName|userId} clients keep their shape.
    for (const auto* key : {"user_id", "groupId", "userId", "memberName"})
        if (payload.contains(key)) out[key] = payload.at(key);
    return out;
}

}

json Groups::add(const json& payload, const std::shared_ptr<Session>& session) {
    const auto group = group_ops::create(session->user, {
        .name = payload.at("name").get<std::string>(),
        .description = payload.value("description", ""),
        .linux_gid = groupPayloadUInt(payload, "linux_gid")
    });
    return {{"name", group->name()}, {"group", vh::identities::to_json(group)}};
}

json Groups::remove(const json& payload, const std::shared_ptr<Session>& session) {
    const auto group = group_ops::remove(session->user, payload.at("id").get<unsigned int>());
    return {{"id", group->id}};
}

json Groups::addMember(const json& payload, const std::shared_ptr<Session>& session) {
    const auto group = group_ops::addMember(session->user, {.group = memberGroupRef(payload), .user = memberUserRef(payload)});
    return membershipResponse(group, payload);
}

json Groups::removeMember(const json& payload, const std::shared_ptr<Session>& session) {
    const auto group = group_ops::removeMember(session->user, {.group = memberGroupRef(payload), .user = memberUserRef(payload)});
    return membershipResponse(group, payload);
}

json Groups::list(const std::shared_ptr<Session>& session) {
    return {{"groups", vh::identities::to_json(group_ops::list(session->user))}};
}

json Groups::get(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"group", vh::identities::to_json(group_ops::get(session->user, payload.at("id").get<unsigned int>()))}};
}

json Groups::getByName(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"group", vh::identities::to_json(group_ops::get(session->user, payload.at("name").get<std::string>()))}};
}

json Groups::update(const json& payload, const std::shared_ptr<Session>& session) {
    const auto group = group_ops::update(session->user, {
        .group = payload.at("id").get<unsigned int>(),
        .name = groupPayloadString(payload, "name"),
        .description = groupPayloadString(payload, "description"),
        .linux_gid = groupPayloadUInt(payload, "linux_gid")
    });
    return {{"id", group->id}, {"name", group->name()}, {"group", vh::identities::to_json(group)}};
}

json Groups::listByUser(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"groups", vh::identities::to_json(group_ops::listForUser(session->user, payload.at("user_id").get<unsigned int>()))}};
}
