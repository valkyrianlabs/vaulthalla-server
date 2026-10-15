#pragma once

#include "rbac/resolver/ResolverTraits/Fwd.hpp"

#include "rbac/permission/admin/Identities.hpp"
#include "rbac/permission/admin/Keys.hpp"
#include "rbac/permission/admin/S3Gateway.hpp"
#include "rbac/role/Admin.hpp"
#include "identities/User.hpp"

#include <utility>

namespace vh::rbac::resolver {

    template<>
    struct AdminResolverTraits<permission::admin::keys::APIPermissions> {
        static constexpr auto domain = Domain::APIKey;

        static const auto& direct(const role::Admin& role) { return role.keys; }
        static const auto& self(const decltype(std::declval<identities::User>().apiKeysPerms().self)& perms) { return perms; }
        static const auto& admin(const decltype(std::declval<identities::User>().apiKeysPerms().admin)& perms) { return perms; }
        static const auto& user(const decltype(std::declval<identities::User>().apiKeysPerms().user)& perms) { return perms; }
    };

    template <>
    struct AdminResolverTraits<permission::admin::identities::IdentityPermissions> {
        static constexpr auto domain = Domain::Identity;

        static const auto& direct(const role::Admin& role) { return role.identities; }
        static const auto& group(const decltype(std::declval<identities::User>().identities().groups)& perms) { return perms; }
        static const auto& admin(const decltype(std::declval<identities::User>().identities().admins)& perms) { return perms; }
        static const auto& user(const decltype(std::declval<identities::User>().identities().users)& perms) { return perms; }
    };

    template <>
    struct AdminResolverTraits<permission::admin::VaultPermissions> {
        static constexpr auto domain = Domain::Vault;
        static const auto& direct(const role::Admin& role) { return role.vaults; }
        static const auto& self(const decltype(std::declval<identities::User>().vaultsPerms().self)& perms) { return perms; }
        static const auto& admin(const decltype(std::declval<identities::User>().vaultsPerms().admin)& perms) { return perms; }
        static const auto& user(const decltype(std::declval<identities::User>().vaultsPerms().user)& perms) { return perms; }
    };

    template <>
    struct AdminResolverTraits<permission::admin::S3GatewayPermissions> {
        static constexpr auto domain = Domain::Global;
        static const auto& direct(const role::Admin& role) { return role.s3Gateway; }
    };

    template <>
    struct AdminResolverTraits<permission::admin::StatsPermissions> {
        static constexpr auto domain = Domain::Global;
        static const auto& direct(const role::Admin& role) { return role.stats; }
    };

    template <>
    struct AdminResolverTraits<permission::admin::UpstreamPermissions> {
        static constexpr auto domain = Domain::Global;
        static const auto& direct(const role::Admin& role) { return role.upstream; }
    };

}
