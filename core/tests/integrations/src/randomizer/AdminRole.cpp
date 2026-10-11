#include "randomizer/AdminRole.hpp"

#include "identities/User.hpp"
#include "identities/Group.hpp"

#include "rbac/role/Admin.hpp"
#include "db/query/rbac/role/Admin.hpp"

#include <stdexcept>

using namespace vh;
using namespace vh::rbac;
using namespace vh::test::integration::randomizer;

std::shared_ptr<role::Admin> AdminRole::getRandomRole() {
    const auto roles = db::query::rbac::role::Admin::list();
    if (roles.empty()) throw std::runtime_error("randomizer: no roles to pick from");
    return roles[generateRandomIndex(roles.size())];
}

void AdminRole::assignRandomRole(const std::shared_ptr<identities::User> &user) {
    {
        auto next = *user->state();
        next.roles.admin = getRandomRole();
        user->replaceDetachedState(std::move(next));
    }
}

void AdminRole::assignRandomPermissions(const std::shared_ptr<role::Admin>& role) {
    randomizePerms<permission::admin::keys::APIPermissions>(role->keys.apiKeys.admin);
    randomizePerms<permission::admin::keys::APIPermissions>(role->keys.apiKeys.self);
    randomizePerms<permission::admin::keys::APIPermissions>(role->keys.apiKeys.user);
    randomizePerms<permission::admin::keys::EncryptionKeyPermissions>(role->keys.encryptionKeys);
    randomizePerms<permission::admin::identities::IdentityPermissions>(role->identities.admins);
    randomizePerms<permission::admin::identities::IdentityPermissions>(role->identities.users);
    randomizePerms<permission::admin::identities::GroupPermissions>(role->identities.groups);
    randomizePerms<permission::admin::roles::RolesPermissions>(role->roles.admin);
    randomizePerms<permission::admin::roles::RolesPermissions>(role->roles.vault);
    randomizePerms<permission::admin::AuditPermissions>(role->audits);
    randomizePerms<permission::admin::settings::SettingsPermissions>(role->settings.websocket);
    randomizePerms<permission::admin::settings::SettingsPermissions>(role->settings.http);
    randomizePerms<permission::admin::settings::SettingsPermissions>(role->settings.auth);
    randomizePerms<permission::admin::settings::SettingsPermissions>(role->settings.caching);
    randomizePerms<permission::admin::settings::SettingsPermissions>(role->settings.database);
    randomizePerms<permission::admin::settings::SettingsPermissions>(role->settings.logging);
    randomizePerms<permission::admin::settings::SettingsPermissions>(role->settings.sharing);
    randomizePerms<permission::admin::settings::SettingsPermissions>(role->settings.services);
    randomizePerms<permission::admin::VaultPermissions>(role->vaults.admin);
    randomizePerms<permission::admin::VaultPermissions>(role->vaults.self);
    randomizePerms<permission::admin::VaultPermissions>(role->vaults.user);
}
