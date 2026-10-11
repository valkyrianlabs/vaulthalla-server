#include "db/query/identities/User.hpp"

#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"
#include "rbac/role/vault/Global.hpp"
#include "crypto/util/hash.hpp"
#include "db/Transactions.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "db/query/identities/helpers.hpp"

#include <stdexcept>
#include <optional>
#include <pqxx/pqxx>

namespace vh::db::query::identities {
    namespace {
        using State = vh::identities::UserState;

        bool rowBool(pqxx::row_ref row, const char* column, const bool fallback = false) {
            try {
                const auto field = row[column];
                if (field.is_null()) return fallback;
                return field.as<bool>();
            } catch (...) {
                return fallback;
            }
        }

        void guardNormalUserCreate(const State& user) {
            if (user.isProtected || user.systemOnly)
                throw std::runtime_error("protected/system-only user flags are bootstrap-only");

            if (user.meta.linux_uid && *user.meta.linux_uid == 0)
                throw std::runtime_error("linux_uid 0 is reserved for the root principal");
        }

        void guardNormalUserUpdate(pqxx::work& txn, const unsigned int id, const State& user) {
            const auto res = txn.exec(
                R"SQL(
                    SELECT u.id, u.protected
                    FROM users u
                    WHERE u.id = $1
                )SQL",
                pqxx::params{id}
            );

            if (res.empty())
                throw std::runtime_error("User not found: " + std::to_string(id));

            if (rowBool(res.one_row_ref(), "protected"))
                throw std::runtime_error("protected users cannot be updated through normal user paths");

            if (user.isProtected || user.systemOnly)
                throw std::runtime_error("protected/system-only user flags are bootstrap-only");

            if (user.meta.linux_uid && *user.meta.linux_uid == 0)
                throw std::runtime_error("linux_uid 0 is reserved for the root principal");
        }

        void guardNormalUserDelete(pqxx::work& txn, const unsigned int userId) {
            const auto res = txn.exec(
                "SELECT protected FROM users WHERE id = $1",
                pqxx::params{userId}
            );

            if (res.empty()) return;
            if (rowBool(res.one_row_ref(), "protected"))
                throw std::runtime_error("protected users cannot be deleted");
        }

        bool systemOnlyUser(pqxx::work& txn, const unsigned int userId) {
            const auto res = txn.exec(
                "SELECT system_only FROM users WHERE id = $1",
                pqxx::params{userId}
            );
            return !res.empty() && rowBool(res.one_row_ref(), "system_only");
        }
    }

    unsigned int User::createUser(const State& draft, const std::string& passwordHash) {
        guardNormalUserCreate(draft);

        log::Registry::db()->debug("[User] Creating user: {}", draft.name);

        if (!draft.roles.admin) throw std::runtime_error("User admin role must be set before creating a user");

        return Transactions::exec("User::createUser", [&](pqxx::work &txn) -> unsigned int {
            const pqxx::params userParams{
                draft.name,
                draft.email,
                passwordHash,
                draft.meta.is_active,
                draft.meta.linux_uid,
                draft.meta.updated_by
            };

            const auto id = txn.exec(
                pqxx::prepped{"insert_user"},
                userParams
            ).one_row_ref()[0].as<uint32_t>();

            upsertUserRoles(txn, id, draft);

            return id;
        });
    }

    void User::updateUser(const unsigned int id, const State& next) {
        Transactions::exec("User::updateUser", [&](pqxx::work &txn) {
            guardNormalUserUpdate(txn, id, next);

            const pqxx::params userParams{
                id,
                next.name,
                next.email,
                next.meta.is_active,
                next.meta.linux_uid,
                next.meta.updated_by
            };

            txn.exec(pqxx::prepped{"update_user"}, userParams);

            // Simplest bridge shape for now: replace all global policies for user, then upsert current set.
            txn.exec(
                pqxx::prepped{"user_global_vault_policy_delete_all_for_user"},
                pqxx::params{id}
            );

            upsertUserRoles(txn, id, next);
        });
    }

    bool User::authenticateUser(const std::string &name, const std::string &password) {
        return Transactions::exec("User::authenticateUser", [&](pqxx::work &txn) -> bool {
            const auto res = txn.exec(
                "SELECT password_hash, system_only FROM users WHERE name = $1",
                pqxx::params{name}
            );

            if (res.empty()) return false;
            if (rowBool(res.one_row_ref(), "system_only")) return false;

            const auto storedHash = res.one_row_ref()["password_hash"].as<std::string>();
            return vh::crypto::hash::verifyPassword(password, storedHash);
        });
    }

    void User::updateUserPassword(const unsigned int userId, const std::string &passwordHash) {
        Transactions::exec("User::updateUserPassword", [&](pqxx::work &txn) {
            if (systemOnlyUser(txn, userId))
                throw std::runtime_error("system-only users cannot receive normal user passwords");

            const auto res = txn.exec(
                pqxx::prepped{"update_user_password"},
                pqxx::params{userId, passwordHash}
            );

            if (res.affected_rows() != 1)
                throw std::runtime_error("User not found: " + std::to_string(userId));
        });
    }

    void User::deleteUser(const unsigned int userId) {
        Transactions::exec("User::deleteUser", [&](pqxx::work &txn) {
            guardNormalUserDelete(txn, userId);

            txn.exec(
                pqxx::prepped{"delete_user"},
                pqxx::params{userId}
            );
        });
    }

    void User::updateLastLoggedInUser(const unsigned int userId) {
        Transactions::exec("User::updateLastLoggedInUser", [&](pqxx::work &txn) {
            txn.exec(
                pqxx::prepped{"update_user_last_login"},
                pqxx::params{userId}
            );
        });
    }

    void User::bootstrapSetAdminLinuxUID(const unsigned int linuxUid, const std::optional<unsigned int> updatedBy) {
        if (linuxUid == 0)
            throw std::runtime_error("admin cannot be assigned linux_uid 0");

        Transactions::exec("User::bootstrapSetAdminLinuxUID", [&](pqxx::work &txn) {
            txn.exec("SELECT set_config('vaulthalla.bootstrap', 'on', true)");

            const auto res = txn.exec(
                R"SQL(
                    UPDATE users
                    SET linux_uid = $1,
                        last_modified_by = $2,
                        updated_at = NOW()
                    WHERE name = 'admin'
                    RETURNING id
                )SQL",
                pqxx::params{linuxUid, updatedBy}
            );

            if (res.empty())
                throw std::runtime_error("admin user record not found");
        });
    }

    bool User::userExists(const std::string &name) {
        return Transactions::exec("User::userExists", [&](pqxx::work &txn) -> bool {
            return txn.exec(
                pqxx::prepped{"user_exists"},
                pqxx::params{name}
            ).one_field_ref().as<bool>();
        });
    }

    bool User::adminUserExists() {
        return Transactions::exec("User::adminUserExists", [](pqxx::work &txn) -> bool {
            return txn.exec(
                pqxx::prepped{"admin_user_exists"}
            ).one_field_ref().as<bool>();
        });
    }
}
