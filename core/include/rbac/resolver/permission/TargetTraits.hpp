#pragma once

#include "Traits.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"
#include "rbac/role/vault/Base.hpp"

namespace vh::rbac::resolver {
    template<>
    struct PermissionTargetTraits<permission::admin::AuditPermissions> {
        static constexpr auto domain = RoleDomain::Admin;
        static constexpr bool canOverride = false;

        static auto& target(role::Admin& role) { return role.audits; }
        static const auto& target(const role::Admin& role) { return role.audits; }
    };

    template<>
    struct PermissionTargetTraits<permission::admin::StatsPermissions> {
        static constexpr auto domain = RoleDomain::Admin;
        static constexpr bool canOverride = false;

        static auto& target(role::Admin& role) { return role.stats; }
        static const auto& target(const role::Admin& role) { return role.stats; }
    };

    template<>
    struct PermissionTargetTraits<permission::admin::UpstreamPermissions> {
        static constexpr auto domain = RoleDomain::Admin;
        static constexpr bool canOverride = false;

        static auto& target(role::Admin& role) { return role.upstream; }
        static const auto& target(const role::Admin& role) { return role.upstream; }
    };

    template<>
    struct PermissionTargetTraits<permission::admin::keys::EncryptionKeyPermissions> {
        static constexpr auto domain = RoleDomain::Admin;
        static constexpr bool canOverride = false;

        static auto& target(role::Admin& role) { return role.keys.encryptionKeys; }
        static const auto& target(const role::Admin& role) { return role.keys.encryptionKeys; }
    };

    template<>
    struct PermissionTargetTraits<permission::admin::S3GatewayPermissions> {
        static constexpr auto domain = RoleDomain::Admin;
        static constexpr bool canOverride = false;

        static auto& target(role::Admin& role) { return role.s3Gateway; }
        static const auto& target(const role::Admin& role) { return role.s3Gateway; }
    };

    template<>
    struct PermissionTargetTraits<permission::admin::identities::GroupPermissions> {
        static constexpr auto domain = RoleDomain::Admin;
        static constexpr bool canOverride = false;

        static auto& target(role::Admin& role) { return role.identities.groups; }
        static const auto& target(const role::Admin& role) { return role.identities.groups; }
    };

    template<>
    struct PermissionTargetTraits<permission::vault::RolePermissions> {
        static constexpr auto domain = RoleDomain::Vault;
        static constexpr bool canOverride = false;

        static auto& target(role::vault::Base& role) { return role.roles; }
        static const auto& target(const role::vault::Base& role) { return role.roles; }
    };

    template<>
    struct PermissionTargetTraits<permission::vault::sync::SyncConfigPermissions> {
        static constexpr auto domain = RoleDomain::Vault;
        static constexpr bool canOverride = false;

        static auto& target(role::vault::Base& role) { return role.sync.config; }
        static const auto& target(const role::vault::Base& role) { return role.sync.config; }
    };

    template<>
    struct PermissionTargetTraits<permission::vault::sync::SyncActionPermissions> {
        static constexpr auto domain = RoleDomain::Vault;
        static constexpr bool canOverride = false;

        static auto& target(role::vault::Base& role) { return role.sync.action; }
        static const auto& target(const role::vault::Base& role) { return role.sync.action; }
    };

    template<>
    struct PermissionTargetTraits<permission::vault::fs::FilePermissions> {
        static constexpr auto domain = RoleDomain::Vault;
        static constexpr bool canOverride = true;

        static auto& target(role::vault::Base& role) { return role.fs.files; }
        static const auto& target(const role::vault::Base& role) { return role.fs.files; }
    };

    template<>
    struct PermissionTargetTraits<permission::vault::fs::DirectoryPermissions> {
        static constexpr auto domain = RoleDomain::Vault;
        static constexpr bool canOverride = true;

        static auto& target(role::vault::Base& role) { return role.fs.directories; }
        static const auto& target(const role::vault::Base& role) { return role.fs.directories; }
    };
}
