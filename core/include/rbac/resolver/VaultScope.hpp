#pragma once

#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "rbac/permission/admin/VaultGlobals.hpp"

#include <cstdint>
#include <optional>

namespace vh::rbac::resolver {
    // The scope a vault falls under for the account asking about it: its own vault (self), a vault owned by an admin
    // identity (admin), any other account's vault (user). The one rule for every per-scope vault permission: the admin
    // role's vault permissions (admin.vaults.<scope>) and the account's global vault policy
    // (user_global_vault_policy, scope self | admin | user). "Admin" is User::isAdmin() of the owner.
    enum class VaultScope : uint8_t { Self, Admin, User };

    [[nodiscard]]
    inline VaultScope vaultScope(const uint32_t actorId, const identities::User &owner) {
        if (owner.id == actorId) return VaultScope::Self;
        return owner.isAdmin() ? VaultScope::Admin : VaultScope::User;
    }

    // The same, for a vault known by its owner's id (the canonical account; memory, no database round trip on a warm
    // index). nullopt when the owner is unknown: no scope applies, so nothing is granted.
    [[nodiscard]]
    inline std::optional<VaultScope> vaultScope(const identities::User &actor, const uint32_t ownerId) {
        if (ownerId == actor.id) return VaultScope::Self;
        const auto owner = identities::manager().user(ownerId);
        if (!owner) return std::nullopt;
        return vaultScope(actor.id, *owner);
    }

    // The member of a self/admin/user triple that `scope` names.
    template<typename T>
    [[nodiscard]] const T &inScope(const VaultScope scope, const T &self, const T &admin, const T &user) {
        switch (scope) {
            case VaultScope::Self: return self;
            case VaultScope::Admin: return admin;
            case VaultScope::User: return user;
        }
        return user;
    }

    [[nodiscard]]
    inline const role::vault::Global &inScope(const VaultScope scope, const permission::admin::VaultGlobals &globals) {
        return inScope(scope, globals.self, globals.admin, globals.user);
    }
}
