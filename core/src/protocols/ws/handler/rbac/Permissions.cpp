#include "protocols/ws/handler/rbac/Permissions.hpp"
#include "protocols/ws/Session.hpp"
#include "db/query/rbac/Permission.hpp"
#include "rbac/permission/Permission.hpp"
#include "ops/Error.hpp"

#include <nlohmann/json.hpp>

using namespace vh::protocols::ws::handler::rbac;

json Permissions::get(const json& payload) {
    const auto permissionId = payload.at("id").get<unsigned int>();
    auto permission = db::query::rbac::Permission::getPermission(permissionId);
    if (!permission) throw vh::ops::NotFound("Permission not found");

    return {{"permission", *permission}};
}

json Permissions::getByName(const json& payload) {
    const auto permissionName = payload.at("name").get<std::string>();
    auto permission = db::query::rbac::Permission::getPermissionByName(permissionName);
    if (!permission) throw vh::ops::NotFound("Permission not found");

    return {{"permission", *permission}};
}

json Permissions::list() {
    return {{"permissions", db::query::rbac::Permission::listPermissions()}};
}
