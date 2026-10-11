#pragma once

#include "rbac/permission/vault/Filesystem.hpp"
#include "rbac/permission/vault/sync/Action.hpp"
#include "rbac/permission/vault/sync/Config.hpp"

namespace vh::rbac::resolver {
    template<typename EnumT>
    struct VaultResolverMode {
        static constexpr bool policy_only = false;
        // A vault role on the vault (the account's own or one of its groups') grants the permission too, in addition
        // to the admin vault globals. Filesystem actions get the same from the policy evaluator. Role management
        // stays on the globals: a group-held role must not let its members hand out roles.
        static constexpr bool vault_roles = false;
    };

    template<>
    struct VaultResolverMode<permission::vault::FilesystemAction> {
        static constexpr bool policy_only = true;
        static constexpr bool vault_roles = false;
    };

    template<>
    struct VaultResolverMode<permission::vault::sync::SyncConfigPermissions> {
        static constexpr bool policy_only = false;
        static constexpr bool vault_roles = true;
    };

    template<>
    struct VaultResolverMode<permission::vault::sync::SyncActionPermissions> {
        static constexpr bool policy_only = false;
        static constexpr bool vault_roles = true;
    };
}
