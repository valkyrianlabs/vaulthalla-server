#pragma once

#include "vault/Context.hpp"
#include "vault/ResolvedContext.hpp"
#include "ResolverTraits/Fwd.hpp"
#include "vault/policy/Base.hpp"
#include "vault/ResolverMode.hpp"
#include "rbac/resolver/vault/policy/Filesystem.hpp"
#include "rbac/resolver/vault/policy/Roles.hpp"

#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "rbac/role/Vault.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/permission/admin/VaultGlobals.hpp"
#include "vault/model/Vault.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/Path.hpp"
#include "rbac/fs/policy/Evaluator.hpp"

#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <algorithm>
#include <vector>

namespace vh::rbac::resolver {
    class Vault {
        template<typename EnumT>
        static bool checkSinglePermissionTraits(
            const std::shared_ptr<identities::User> &user,
            const vault::ResolvedContext &resolved,
            const vault::Context<EnumT> &ctx,
            const EnumT permission
        ) {
            // One state for the whole check (no copy of the global policy per permission).
            const auto state = user->state();
            if (!state->authorizing() || !state->roles.admin) return false;
            const auto &globalPerms = state->roles.admin->vGlobals;
            bool allowed = false;

            if (user->id == resolved.vault->owner_id)
                allowed = VaultResolverTraits<EnumT>::self(globalPerms.self).has(permission);
            else if (resolved.owner->isAdmin())
                allowed = VaultResolverTraits<EnumT>::admin(globalPerms.admin).has(permission);
            else
                allowed = VaultResolverTraits<EnumT>::user(globalPerms.user).has(permission);

            if (!allowed) return false;
            return vault::ContextPolicy<EnumT>::validate(user, resolved, permission, ctx);
        }

        template<typename EnumT>
        static std::vector<EnumT> collectPermissions(const vault::Context<EnumT> &ctx) {
            static_assert(std::is_enum_v<EnumT>,
                          "vh::rbac::resolver::Vault::collectPermissions(): EnumT must be an enum type");

            // One allocation, filled in place (growing after reserve() trips GCC's -O3 -Wfree-nonheap-object).
            std::vector<EnumT> out((ctx.permission ? 1u : 0u) + ctx.permissions.size());
            auto next = out.begin();
            if (ctx.permission) *next++ = *ctx.permission;
            std::ranges::copy(ctx.permissions, next);

            if (out.empty())
                throw std::invalid_argument(
                    "vh::rbac::resolver::Vault::has(): Context must provide either permission or permissions");

            return out;
        }

        template<typename EnumT>
        static bool checkSinglePermission(
            const std::shared_ptr<identities::User> &user,
            const vault::ResolvedContext &resolved,
            const vault::Context<EnumT> &ctx,
            const EnumT permission
        ) {
            static_assert(std::is_enum_v<EnumT>,
                          "vh::rbac::resolver::Vault::checkSinglePermission(): EnumT must be an enum type");

            if (!user || !resolved.isValid()) return false;

            if constexpr (VaultResolverMode<EnumT>::policy_only)
                return vault::ContextPolicy<EnumT>::validate(user, resolved, permission, ctx);
            else return checkSinglePermissionTraits(user, resolved, ctx, permission);
        }

        template<typename EnumT>
        static bool checkPermissions(
            const std::shared_ptr<identities::User> &user,
            const vault::ResolvedContext &resolved,
            const vault::Context<EnumT> &ctx
        ) {
            const auto permissions = collectPermissions(ctx);

            for (const auto permission: permissions)
                if (!checkSinglePermission(user, resolved, ctx, permission))
                    return false;

            return true;
        }

        static std::shared_ptr<storage::Engine> resolveEngine(
            const std::optional<uint32_t> &vaultId,
            const std::optional<std::filesystem::path> &path,
            const std::shared_ptr<::vh::fs::model::Entry> &entry
        ) {
            const auto storageManager = runtime::Deps::get().storageManager;
            if (!storageManager)
                throw std::runtime_error(
                    "vh::rbac::resolver::Vault::resolveEngine(): StorageManager dependency not available");

            if (vaultId && *vaultId != 0)
                if (auto engine = storageManager->getEngine(*vaultId))
                    return engine;

            if (path && !path->empty())
                if (auto engine = storageManager->resolveStorageEngine(*path))
                    return engine;

            if (entry && entry->vault_id && *entry->vault_id != 0)
                if (auto engine = storageManager->getEngine(*entry->vault_id))
                    return engine;

            if (entry && !entry->path.empty())
                if (auto engine = storageManager->resolveStorageEngine(entry->path))
                    return engine;

            return nullptr;
        }

        static vault::ResolvedContext resolveVaultContext(
            const std::optional<uint32_t> &vaultId,
            const std::optional<std::filesystem::path> &path,
            const std::shared_ptr<::vh::fs::model::Entry> &entry,
            const std::optional<std::string> &targetSubjectType,
            const std::optional<uint32_t> &targetSubjectId,
            const std::shared_ptr<identities::User> &actor
        ) {
            vault::ResolvedContext resolved{};

            resolved.engine = resolveEngine(vaultId, path, entry);
            if (!resolved.engine) return resolved;

            resolved.vault = resolved.engine->vault;
            if (!resolved.vault) return resolved;

            // The owner only answers "is the vault owned by an admin": the caller when it owns the vault, else the
            // canonical owner (memory, no database round trip on a warm index).
            resolved.owner = actor && actor->id == resolved.vault->owner_id
                                 ? actor
                                 : vh::identities::manager().user(resolved.vault->owner_id);
            if (!resolved.owner) return resolved;

            if (targetSubjectType && targetSubjectId) {
                if (*targetSubjectType == "user")
                    resolved.targetUser = vh::identities::manager().user(*targetSubjectId);
                else if (*targetSubjectType == "group")
                    resolved.targetGroup = vh::identities::manager().group(*targetSubjectId);
            }

            return resolved;
        }

    public:
        template<typename EnumT>
        static bool has(vault::Context<EnumT> &&ctx) {
            if (!ctx.isValid()) return false;
            // A deactivated or deleted account (a tombstone still held somewhere) authorizes nothing.
            if (!ctx.user->authorizing()) return false;
            if (ctx.user->isSuperAdmin()) return true;

            const auto resolved = resolveVaultContext(
                ctx.vault_id,
                ctx.path,
                ctx.entry,
                ctx.target_subject_type,
                ctx.target_subject_id,
                ctx.user
            );

            if (!resolved.isValid()) {
                log::Registry::auth()->warn("vh::rbac::resolver::Vault::resolveVaultContext(): Failed to resolve:\n{}",
                                            ctx.dump());
                return false;
            }

            return checkPermissions(ctx.user, resolved, ctx);
        }

        template<typename EnumT>
        static bool has(const vault::Context<EnumT> &ctx) {
            return has(vault::Context<EnumT>{ctx});
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
