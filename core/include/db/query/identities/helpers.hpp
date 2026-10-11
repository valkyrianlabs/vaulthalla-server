#pragma once

#include <memory>
#include <unordered_map>
#include <cstdint>
#include <pqxx/pqxx>
#include "identities/Fwd.hpp"
#include "rbac/Fwd.hpp"

namespace vh::rbac::permission::admin { struct VaultGlobals; }

namespace vh::db::query::identities {
    // Admin role assignment, global vault policy and direct vault roles of `state` for account `userId`.
    void upsertUserRoles(pqxx::work& txn, uint32_t userId, const vh::identities::UserState& state);

    void upsertVaultRoles(pqxx::work& txn,
                          const std::unordered_map<uint32_t, std::shared_ptr<const vh::rbac::role::Vault>>& vRoles,
                          const std::string &subjectType, uint32_t subjectId);

    void upsertGlobalVRoles(pqxx::work& txn, const vh::rbac::permission::admin::VaultGlobals &vGlobal, uint32_t userId);

    void upsertAdminRoleAssignment(pqxx::work& txn, uint32_t userId, uint32_t roleId);
}
