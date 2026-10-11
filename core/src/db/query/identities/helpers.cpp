#include "db/query/identities/helpers.hpp"
#include "rbac/role/Vault.hpp"
#include "log/Registry.hpp"
#include "identities/User.hpp"
#include "rbac/permission/admin/VaultGlobals.hpp"
#include "rbac/role/Admin.hpp"

#include <array>

namespace vh::db::query::identities {

    void upsertUserRoles(pqxx::work &txn, const uint32_t userId, const vh::identities::UserState &state) {
        upsertAdminRoleAssignment(txn, userId, state.roles.admin->id);
        upsertGlobalVRoles(txn, state.roles.admin->vGlobals, userId);
        upsertVaultRoles(txn, state.roles.vaults, "user", userId);
    }

    void upsertVaultRoles(pqxx::work& txn,
                          const std::unordered_map<uint32_t, std::shared_ptr<const rbac::role::Vault>>& vRoles,
                          const std::string &subjectType, const uint32_t subjectId) {
        for (const auto &[_, role]: vRoles) {
            if (!role || !role->assignment) {
                log::Registry::db()->debug("[User] User role assignment not set");
                continue;
            }

            pqxx::params roleParams{
                role->assignment->vault_id,
                subjectType,
                subjectId,
                role->id
            };

            const auto res = txn.exec(
                pqxx::prepped{"vault_role_assignment_upsert"},
                roleParams
            );

            if (res.empty()) continue;
            const auto assignmentId = res.one_row_ref()["id"].as<unsigned int>();

            for (const auto &override: role->fs.overrides) {
                txn.exec(
                    pqxx::prepped{"vault_permission_override_upsert"},
                    pqxx::params{
                        assignmentId,
                        override.permission.id,
                        override.glob_path(),
                        override.enabled,
                        to_string(override.effect)
                    }
                );
            }
        }
    }

    void upsertGlobalVRoles(pqxx::work &txn, const rbac::permission::admin::VaultGlobals& vGlobal, const uint32_t userId) {
        const std::array userGlobalVaultRoles{ vGlobal.self, vGlobal.user, vGlobal.admin };

        for (const auto &globalPolicy: userGlobalVaultRoles) {
            txn.exec(
                pqxx::prepped{"user_global_vault_policy_upsert"},
                pqxx::params{
                    userId,
                    globalPolicy.template_role_id,
                    globalPolicy.enforce_template,
                    rbac::role::vault::to_string(globalPolicy.scope),
                    globalPolicy.fs.files.toBitString(),
                    globalPolicy.fs.directories.toBitString(),
                    globalPolicy.sync.toBitString(),
                    globalPolicy.roles.toBitString()
                }
            );
        }
    }

    void upsertAdminRoleAssignment(pqxx::work &txn, uint32_t userId, uint32_t roleId) {
        txn.exec(
                pqxx::prepped{"admin_role_assignment_upsert"},
                pqxx::params{userId, roleId}
            );
    }
}
