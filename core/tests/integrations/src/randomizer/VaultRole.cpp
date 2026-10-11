#include "randomizer/VaultRole.hpp"

#include "identities/User.hpp"
#include "identities/Group.hpp"

#include "rbac/role/Vault.hpp"
#include "db/query/rbac/role/Vault.hpp"

#include <stdexcept>

using namespace vh;
using namespace vh::rbac;
using namespace vh::test::integration::randomizer;

std::shared_ptr<role::Vault> VaultRole::getRandomRole() {
    const auto roles = db::query::rbac::role::Vault::list();
    if (roles.empty()) throw std::runtime_error("randomizer: no roles to pick from");
    return roles[generateRandomIndex(roles.size())];
}

void VaultRole::assignRandomPermissions(const std::shared_ptr<role::Vault>& vRole) {
    randomizePerms<permission::vault::RolePermissions>(vRole->roles);
    randomizePerms<permission::vault::sync::SyncActionPermissions>(vRole->sync.action);
    randomizePerms<permission::vault::sync::SyncConfigPermissions>(vRole->sync.config);
    randomizePerms<permission::vault::fs::SharePermissions>(vRole->fs.files.share);
    randomizePerms<permission::vault::fs::SharePermissions>(vRole->fs.directories.share);
    randomizePerms<permission::vault::fs::FilePermissions>(vRole->fs.files);
    randomizePerms<permission::vault::fs::DirectoryPermissions>(vRole->fs.directories);
}
