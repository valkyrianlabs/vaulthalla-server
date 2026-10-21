// ws book: permission.* / permissions.list (core/src/protocols/ws/handler/rbac/Permissions.cpp). Any signed-in user;
// the permission catalog is not RBAC-filtered.

#include "fields.hpp"

namespace vh::contract::ws::detail {

std::vector<WsCommandUsage> permissionCommands() {
    std::vector<WsCommandUsage> out;

    out.push_back({
        .command = "permission.get",
        .description = "One permission of the catalog by id.",
        .payload = {uinteger("id").gen(gen::ref("permission", {"id"}))},
        .response = {object("permission", "Permission")},
        .refusal_codes = {"not_found", "unauthorized"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "permission.get.byName",
        .description = "One permission of the catalog by its qualified name.",
        .payload = {str("name").gen(gen::ref("permission", {"name"}))},
        .response = {object("permission", "Permission")},
        .refusal_codes = {"not_found", "unauthorized"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "permissions.list",
        .description = "The whole permission catalog.",
        .input = "none",
        .response = {objectArray("permissions", "Permission")},
        .refusal_codes = {"unauthorized"},
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

}
