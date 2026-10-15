#pragma once

#include "Traits.hpp"
#include "TargetTraits.hpp"
#include "policy/all.hpp"
#include "rbac/resolver/Permission.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"
#include "rbac/role/vault/Global.hpp"

namespace vh::rbac::resolver {
    template<>
struct PermissionResolverEnumPack<std::shared_ptr<role::Admin>> {
        using type = PermissionResolver<
            std::shared_ptr<role::Admin>,
            permission::admin::keys::APIPermissions,
            permission::admin::keys::EncryptionKeyPermissions,
            permission::admin::VaultPermissions,
            permission::admin::S3GatewayPermissions,
            permission::admin::identities::IdentityPermissions,
            permission::admin::identities::GroupPermissions,
            permission::admin::settings::SettingsPermissions,
            permission::admin::AuditPermissions,
            permission::admin::StatsPermissions,
            permission::admin::UpstreamPermissions,
            permission::admin::roles::RolesPermissions
        >;
    };

    template<>
    struct PermissionResolverEnumPack<std::shared_ptr<role::Vault>> {
        using type = PermissionResolver<
            std::shared_ptr<role::Vault>,
            permission::vault::RolePermissions,
            permission::vault::sync::SyncActionPermissions,
            permission::vault::sync::SyncConfigPermissions,
            permission::vault::fs::FilePermissions,
            permission::vault::fs::DirectoryPermissions,
            permission::vault::fs::SharePermissions
        >;
    };

    template<>
    struct PermissionResolverEnumPack<std::shared_ptr<role::vault::Global>> {
        using type = PermissionResolver<
            std::shared_ptr<role::vault::Global>,
            permission::vault::RolePermissions,
            permission::vault::sync::SyncActionPermissions,
            permission::vault::sync::SyncConfigPermissions,
            permission::vault::fs::FilePermissions,
            permission::vault::fs::DirectoryPermissions,
            permission::vault::fs::SharePermissions
        >;
    };
}
