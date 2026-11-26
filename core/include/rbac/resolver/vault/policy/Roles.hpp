#pragma once

#include "rbac/resolver/vault/policy/Base.hpp"
#include "rbac/resolver/vault/ResolvedContext.hpp"
#include "rbac/role/Vault.hpp"
#include "identities/User.hpp"
#include "vault/model/Vault.hpp"

namespace vh::rbac::resolver::vault {
    template<>
    struct ContextPolicy<permission::vault::RolePermissions> {
    private:
        static bool validateAssignUser(const std::shared_ptr<identities::User> &actor,
                                       const ResolvedContext &resolved) {
            if (!resolved.targetUser) return false;
            if (resolved.targetUser->id == actor->id) return false;
            if (resolved.targetUser->id == resolved.vault->owner_id) return false;
            if (resolved.targetUser->isSuperAdmin()) return false;
            if (resolved.targetUser->isAdmin() && !actor->isAdmin()) return false;
            return true;
        }

        static bool validateAssignGroup(const std::shared_ptr<identities::User> &actor,
                                        const ResolvedContext &resolved) {
            if (!actor) return false;
            if (!resolved.targetGroup) return false;

            // Add group-specific guardrails here as they emerge.
            // For now: group target exists, actor already passed base permission check.
            return true;
        }

        static bool validateAssign(const std::shared_ptr<identities::User> &actor,
                                   const ResolvedContext &resolved) {
            if (!actor || !resolved.isValid()) return false;
            if (!resolved.hasTargetSubject()) return false;

            if (resolved.hasTargetUser())
                return validateAssignUser(actor, resolved);

            if (resolved.hasTargetGroup())
                return validateAssignGroup(actor, resolved);

            // A linked server: no account-shaped guard applies (it is nobody's own role, never an admin); the switch,
            // the caller's channel and the row itself are ops::peer_policy's and ops::roles' (ops/PeerPolicy.hpp).
            if (resolved.hasTargetPeer()) return true;

            return false;
        }

    public:
        static bool validate(const std::shared_ptr<identities::User> &actor,
                     const ResolvedContext &resolved,
                     permission::vault::RolePermissions permission,
                     const Context<permission::vault::RolePermissions> &) {
            if (!actor || !resolved.isValid()) return false;

            switch (permission) {
                case permission::vault::RolePermissions::Assign:
                    return validateAssign(actor, resolved);

                default:
                    return true;
            }
        }
    };
}
