#pragma once

#include "admin/Context.hpp"
#include "ResolverTraits/Fwd.hpp"
#include "admin/policy/Base.hpp"
#include "admin/ResolvedContext.hpp"

#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "rbac/permission/admin/VaultGlobals.hpp"
#include "runtime/Deps.hpp"
#include "db/query/vault/APIKey.hpp"
#include "storage/Manager.hpp"
#include "rbac/role/Admin.hpp"
#include "vault/model/Vault.hpp"

#include <memory>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <algorithm>
#include <vector>

namespace vh::rbac::resolver {
    class Admin {
        template<typename EnumT>
        static std::vector<EnumT> collectPermissions(const admin::Context<EnumT> &ctx) {
            static_assert(std::is_enum_v<EnumT>,
                          "vh::rbac::resolver::Admin::collectPermissions(): EnumT must be an enum type");

            // One allocation, filled in place (growing after reserve() trips GCC's -O3 -Wfree-nonheap-object).
            std::vector<EnumT> out((ctx.permission ? 1u : 0u) + ctx.permissions.size());
            auto next = out.begin();
            if (ctx.permission) *next++ = *ctx.permission;
            std::ranges::copy(ctx.permissions, next);

            if (out.empty())
                throw std::invalid_argument(
                    "vh::rbac::resolver::Admin::has(): Context must provide either permission or permissions");

            return out;
        }

        template<typename EnumT>
        static bool checkSinglePermission(const std::shared_ptr<identities::User> &user,
                                          const admin::ResolvedContext &resolved,
                                          const admin::Context<EnumT> &ctx,
                                          const EnumT permission) {
            static_assert(std::is_enum_v<EnumT>,
                          "vh::rbac::resolver::Admin::checkSinglePermission(): EnumT must be an enum type");

            if (!user || !resolved.isValid()) return false;

            bool allowed = false;

            if constexpr (AdminResolverTraits<EnumT>::domain == Domain::APIKey) {
                const auto &perms = user->apiKeysPerms();

                if (!resolved.owner) return false;

                if (user->id == resolved.owner->id)
                    allowed = AdminResolverTraits<EnumT>::self(perms.self).has(permission);
                else if (resolved.owner->isAdmin())
                    allowed = AdminResolverTraits<EnumT>::admin(perms.admin).has(permission);
                else
                    allowed = AdminResolverTraits<EnumT>::user(perms.user).has(permission);
            }
            else if constexpr (AdminResolverTraits<EnumT>::domain == Domain::Identity) {
                const auto &perms = user->identities();

                if (!resolved.identity) return false;

                switch (*resolved.identity) {
                    case admin::Entity::Group:
                        // Groups are governed by GroupPermissions (their own enum and target trait), not these.
                        allowed = false;
                        break;

                    case admin::Entity::User:
                        allowed = AdminResolverTraits<EnumT>::user(perms.users).has(permission);
                        break;

                    case admin::Entity::Admin:
                        allowed = AdminResolverTraits<EnumT>::admin(perms.admins).has(permission);
                        break;
                }
            }
            else if constexpr (AdminResolverTraits<EnumT>::domain == Domain::Vault) {
                const auto &perms = user->vaultsPerms();

                if (!resolved.owner) return false;
                if (!resolved.vault && permission != vh::rbac::permission::admin::VaultPermissions::Create) return false;

                if (resolved.owner->id == user->id)
                    allowed = AdminResolverTraits<EnumT>::self(perms.self).has(permission);
                else if (resolved.owner->isAdmin())
                    allowed = AdminResolverTraits<EnumT>::admin(perms.admin).has(permission);
                else
                    allowed = AdminResolverTraits<EnumT>::user(perms.user).has(permission);
            }
            else if constexpr (AdminResolverTraits<EnumT>::domain == Domain::Global) {
                const auto state = user->state();
                if (!state->authorizing() || !state->roles.admin) return false;
                allowed = AdminResolverTraits<EnumT>::direct(*state->roles.admin).has(permission);
            }
            else {
                static_assert([] { return false; }(), "Unhandled AdminResolverTraits domain");
            }

            if (!allowed) return false;

            return admin::ContextPolicy<EnumT>::validate(user, resolved, permission, ctx);
        }

        template<typename EnumT>
        static bool checkPermissions(const std::shared_ptr<identities::User> &user,
                                     const admin::ResolvedContext &resolved,
                                     const admin::Context<EnumT> &ctx) {
            const auto permissions = collectPermissions(ctx);

            for (const auto permission : permissions)
                if (!checkSinglePermission(user, resolved, ctx, permission))
                    return false;

            return true;
        }

        template<typename EnumT>
        static admin::ResolvedContext resolveContext(const admin::Context<EnumT> &ctx) {
            static_assert(std::is_enum_v<EnumT>,
                          "vh::rbac::resolver::Admin::resolveContext(): EnumT must be an enum type");

            admin::ResolvedContext resolved{};
            resolved.identity = ctx.identity;

            if constexpr (AdminResolverTraits<EnumT>::domain == Domain::APIKey) {
                if (ctx.api_key_id)
                    if (const auto ownerId = db::query::vault::APIKey::getAPIKeyOwnerId(*ctx.api_key_id))
                        resolved.owner = vh::identities::manager().user(*ownerId);

                if (ctx.target_user_id && !resolved.owner)
                    resolved.owner = vh::identities::manager().user(*ctx.target_user_id);

                if (ctx.vault_id)
                    resolved.engine = runtime::Deps::get().storageManager->getEngine(*ctx.vault_id);

                if (resolved.engine)
                    resolved.vault = resolved.engine->vault;
            }
            else if constexpr (AdminResolverTraits<EnumT>::domain == Domain::Identity) {
                if (ctx.target_user_id)
                    resolved.owner = vh::identities::manager().user(*ctx.target_user_id);

                // if/when you support real group resolution:
                // if (ctx.group_id)
                //     resolved.group = db::query::identities::Group::getById(*ctx.group_id);
            }
            else if constexpr (AdminResolverTraits<EnumT>::domain == Domain::Vault) {
                if (ctx.vault) resolved.vault = ctx.vault;
                else if (ctx.vault_id)
                    resolved.engine = runtime::Deps::get().storageManager->getEngine(*ctx.vault_id);

                if (resolved.engine)
                    resolved.vault = resolved.engine->vault;

                if (resolved.vault)
                    resolved.owner = resolved.vault->owner_id == ctx.user->id
                                         ? ctx.user
                                         : vh::identities::manager().user(resolved.vault->owner_id);

                if (ctx.target_user_id && !resolved.owner)
                    resolved.owner = vh::identities::manager().user(*ctx.target_user_id);
            }
            else if constexpr (AdminResolverTraits<EnumT>::domain == Domain::Global) {
                resolved.owner = ctx.user;
            }

            return resolved;
        }

    public:
        template<typename EnumT>
        static bool has(admin::Context<EnumT> &&ctx) {
            if (!ctx.isValid()) return false;
            // A deactivated or deleted account (a tombstone still held somewhere) authorizes nothing.
            if (!ctx.user->authorizing()) return false;

            if (ctx.user->isSuperAdmin()) return true;

            const auto resolved = resolveContext(ctx);
            if (!resolved.isValid()) return false;

            return checkPermissions(ctx.user, resolved, ctx);
        }

        template<typename EnumT>
        static bool has(const admin::Context<EnumT> &ctx) {
            return has(rbac::resolver::admin::Context<EnumT>{ctx});
        }

        template<typename... ContextTs>
        static bool hasAll(ContextTs &&... ctxs) {
            return (has(std::forward<ContextTs>(ctxs)) && ...);
        }

        template<typename... ContextTs>
        static bool hasAny(ContextTs &&... ctxs) {
            return (has(std::forward<ContextTs>(ctxs)) || ...);
        }
    };
}
