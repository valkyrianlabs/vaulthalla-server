// ws book: group.* / groups.* (core/src/protocols/ws/handler/Groups.cpp).

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

WsField groupIdField(std::string name = "id") { return uinteger(std::move(name)).gen(gen::ref("group", {"id"})); }

WsField groupObject() { return object("group", "Group"); }

WsField groupLinuxGid() {
    return uinteger("linux_gid").opt().nullable().gen(gen::testLinuxId()).desc("Positive and unique.");
}

std::vector<WsField> membershipPayload() {
    return {groupIdField("group_id").desc("Legacy clients may send groupId instead."),
            uinteger("user_id").gen(gen::ref("user", {"id"})).desc("Legacy clients may send userId or memberName.")};
}

std::vector<WsField> membershipResponse() {
    return {groupObject(), uinteger("group_id"), uinteger("user_id").desc("Echoed from the request.")};
}

}

std::vector<WsCommandUsage> groupCommands() {
    std::vector<WsCommandUsage> out;

    out.push_back({
        .command = "group.add",
        .description = "Create a group.",
        .payload = {str("name").gen(gen::freshName("group_")),
                    str("description").opt().gen(gen::pattern("group {a}{a}{a}{a}{a}")),
                    groupLinuxGid()},
        .response = {str("name"), groupObject()},
        .refusal_codes = opsRefusals(),
        .operation = "groups.create",
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "group.remove",
        .description = "Delete a group.",
        .payload = {groupIdField()},
        .response = {uinteger("id")},
        .refusal_codes = opsRefusals(),
        .operation = "groups.delete",
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "group.update",
        .description = "Patch a group: name, description and linux_gid are each optional.",
        .payload = {groupIdField(),
                    str("name").opt().nullable().gen(gen::freshName("group_")),
                    str("description").opt().nullable().gen(gen::pattern("group {a}{a}{a}{a}{a}")),
                    groupLinuxGid()},
        .response = {uinteger("id"), str("name"), groupObject()},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "group.get",
        .description = "One group by id.",
        .payload = {groupIdField()},
        .response = {groupObject()},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "group.get.byName",
        .description = "One group by name.",
        .payload = {str("name").gen(gen::ref("group", {"name"}))},
        .response = {groupObject()},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "groups.list",
        .description = "Every group for group viewers; otherwise only the caller's own groups.",
        .input = "none",
        .response = {objectArray("groups", "Group")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "groups.list.byUser",
        .description = "The groups a user belongs to.",
        .payload = {uinteger("user_id").gen(gen::ref("user", {"id"}))},
        .response = {objectArray("groups", "Group")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "group.member.add",
        .description = "Add a user to a group.",
        .payload = membershipPayload(),
        .response = membershipResponse(),
        .refusal_codes = opsRefusals(),
        .operation = "groups.add_user",
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "group.member.remove",
        .description = "Remove a user from a group.",
        .payload = membershipPayload(),
        .response = membershipResponse(),
        .refusal_codes = opsRefusals(),
        .operation = "groups.remove_user",
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

}
