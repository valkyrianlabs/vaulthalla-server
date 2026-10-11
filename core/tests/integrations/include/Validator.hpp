#pragma once

#include "identities/Manager.hpp"
#include "types/Type.hpp"
#include "types/AssertionResult.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/vault/Vault.hpp"
#include "db/query/identities/Group.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/rbac/role/Vault.hpp"

#include "identities/User.hpp"
#include "vault/model/Vault.hpp"
#include "identities/Group.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"

#include <type_traits>
#include <string>
#include <memory>
#include <vector>

namespace vh::test::integration {

template <EntityType type, typename T>
struct Validator {
    // Nice hard error if someone mismatches <type, T>
    static constexpr bool TypeOK =
        (type == EntityType::USER      && std::is_same_v<T, identities::User>)      ||
        (type == EntityType::VAULT     && std::is_same_v<T, vault::model::Vault>)     ||
        (type == EntityType::GROUP     && std::is_same_v<T, identities::Group>)     ||
        (type == EntityType::ADMIN_ROLE && std::is_same_v<T, rbac::role::Admin>)  ||
        (type == EntityType::VAULT_ROLE&& std::is_same_v<T, rbac::role::Vault>);
    static_assert(TypeOK, "Validator<type,T> mismatch: T must match the entity class for 'type'.");

    static AssertionResult assert_all_exist(const std::vector<std::shared_ptr<T>>& entities) {
        for (const auto& e : entities) {
            const auto r = assert_exists(e);
            if (!r.ok) return r;
        }
        return AssertionResult::Pass();
    }

    static AssertionResult assert_exists(const std::shared_ptr<T>& entity) {
        if constexpr (type == EntityType::USER) {
            if (!db::query::identities::User::userExists(entity->name()))
                return AssertionResult::Fail("User '" + entity->name() + "' not found in DB");
            return AssertionResult::Pass();
        } else if constexpr (type == EntityType::VAULT) {
            // T is Vault here
            if (!db::query::vault::Vault::vaultExists(entity->name, entity->owner_id))
                return AssertionResult::Fail("Vault '" + entity->name + "' not found in DB");
            return AssertionResult::Pass();
        } else if constexpr (type == EntityType::GROUP) {
            if (!db::query::identities::Group::groupExists(entity->name()))
                return AssertionResult::Fail("Group '" + entity->name() + "' not found in DB");
            return AssertionResult::Pass();
        } else if constexpr (type == EntityType::ADMIN_ROLE) {
            if (!db::query::rbac::role::Admin::exists(entity->name))
                return AssertionResult::Fail("Role '" + entity->name + "' not found in DB");
            return AssertionResult::Pass();
        } else if constexpr (type == EntityType::VAULT_ROLE) {
            if (!db::query::rbac::role::Vault::exists(entity->name))
                return AssertionResult::Fail("Role '" + entity->name + "' not found in DB");
            return AssertionResult::Pass();
        } else {
            return AssertionResult::Fail("Validator: unsupported entity type for existence check");
        }
    }

    static AssertionResult assert_not_exists(const std::shared_ptr<T>& entity) {
        if constexpr (type == EntityType::USER) {
            if (db::query::identities::User::userExists(entity->name()))
                return AssertionResult::Fail("User '" + entity->name() + "' unexpectedly found in DB");
            return AssertionResult::Pass();
        } else if constexpr (type == EntityType::VAULT) {
            if (db::query::vault::Vault::vaultExists(entity->name, entity->owner_id))
                return AssertionResult::Fail("Vault '" + entity->name + "' unexpectedly found in DB");
            return AssertionResult::Pass();
        } else if constexpr (type == EntityType::GROUP) {
            if (db::query::identities::Group::groupExists(entity->name()))
                return AssertionResult::Fail("Group '" + entity->name() + "' unexpectedly found in DB");
            return AssertionResult::Pass();
        } else if constexpr (type == EntityType::ADMIN_ROLE) {
            if (db::query::rbac::role::Admin::exists(entity->name))
                return AssertionResult::Fail("Role '" + entity->name + "' unexpectedly found in DB");
            return AssertionResult::Pass();
        } else if constexpr (type == EntityType::VAULT_ROLE) {
            if (db::query::rbac::role::Vault::exists(entity->name))
                return AssertionResult::Fail("Role '" + entity->name + "' unexpectedly found in DB");
            return AssertionResult::Pass();
        } else {
            return AssertionResult::Fail("Validator: unsupported entity type for non-existence check");
        }
    }

    static AssertionResult assert_count_at_least(unsigned int count) {
        if constexpr (type == EntityType::USER) {
            const auto actual = vh::identities::manager().users().size();
            if (actual < count)
                return AssertionResult::Fail("Expected at least " + std::to_string(count) + " users, found " + std::to_string(actual));
            return AssertionResult::Pass();
        } else if constexpr (type == EntityType::VAULT) {
            const auto actual = db::query::vault::Vault::listVaults().size();
            if (actual < count)
                return AssertionResult::Fail("Expected at least " + std::to_string(count) + " vaults, found " + std::to_string(actual));
            return AssertionResult::Pass();
        } else if constexpr (type == EntityType::GROUP) {
            const auto actual = vh::identities::manager().groups().size();
            if (actual < count)
                return AssertionResult::Fail("Expected at least " + std::to_string(count) + " groups, found " + std::to_string(actual));
            return AssertionResult::Pass();
        } else if constexpr (type == EntityType::ADMIN_ROLE) {
            const auto actual = db::query::rbac::role::Admin::list().size();
            if (actual < count)
                return AssertionResult::Fail("Expected at least " + std::to_string(count) + " user roles, found " + std::to_string(actual));
            return AssertionResult::Pass();
        } else if constexpr (type == EntityType::VAULT_ROLE) {
            const auto actual = db::query::rbac::role::Vault::list().size();
            if (actual < count)
                return AssertionResult::Fail("Expected at least " + std::to_string(count) + " vault roles, found " + std::to_string(actual));
            return AssertionResult::Pass();
        } else {
            return AssertionResult::Fail("Validator: unsupported entity type for count check");
        }
    }
};

}
