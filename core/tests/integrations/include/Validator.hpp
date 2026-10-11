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
#include <optional>
#include <string>
#include <memory>
#include <vector>

// State oracles: what the DB and the identity manager hold, compared with the harness's model of each entity (the
// model only takes a command's change after the command succeeded). Text output is never the oracle here.
namespace vh::test::integration {

namespace validator_detail {

inline std::string show(const std::optional<std::string>& v) { return v ? "'" + *v + "'" : "null"; }
inline std::string show(const std::optional<uint32_t>& v) { return v ? std::to_string(*v) : "null"; }
inline std::string show(const std::string& v) { return "'" + v + "'"; }
inline std::string show(const uintmax_t v) { return std::to_string(v); }
inline std::string show(const uint32_t v) { return std::to_string(v); }

// Collects every field that differs instead of stopping at the first one.
struct Diff {
    std::string what;
    std::string out;

    template <typename A, typename B>
    void field(const char* name, const A& model, const B& actual) {
        if (model == actual) return;
        out += std::string(out.empty() ? "" : "; ") + name + ": model " + show(model) + ", actual " + show(actual);
    }

    [[nodiscard]] AssertionResult result() const {
        return out.empty() ? AssertionResult::Pass() : AssertionResult::Fail(what + " differs from the model: " + out);
    }
};

// NULL and "" are the same "no description" to an operator.
inline std::optional<std::string> nonEmpty(const std::optional<std::string>& v) {
    return v && !v->empty() ? v : std::nullopt;
}

}

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
        std::string failures;
        for (const auto& e : entities)
            if (const auto r = assert_exists(e); !r.ok) failures += (failures.empty() ? "" : "\n") + r.message;
        return failures.empty() ? AssertionResult::Pass() : AssertionResult::Fail(failures);
    }

    // The entity exists under its id and holds exactly the fields the model expects.
    static AssertionResult assert_exists(const std::shared_ptr<T>& entity) {
        using validator_detail::Diff;
        using validator_detail::nonEmpty;
        if constexpr (type == EntityType::USER) {
            const auto label = "User " + std::to_string(entity->id) + " ('" + entity->name() + "')";
            if (!db::query::identities::User::userExists(entity->name()))
                return AssertionResult::Fail(label + " not found in DB by name");
            const auto live = vh::identities::manager().user(entity->id);
            if (!live || live->state()->deleted) return AssertionResult::Fail(label + " not found in the identity manager");
            const auto model = entity->state();
            const auto actual = live->state();
            Diff d{label, {}};
            d.field("name", model->name, actual->name);
            d.field("email", nonEmpty(model->email), nonEmpty(actual->email));
            d.field("admin role id", model->roles.admin ? std::optional<uint32_t>(model->roles.admin->id) : std::nullopt,
                    actual->roles.admin ? std::optional<uint32_t>(actual->roles.admin->id) : std::nullopt);
            d.field("linux_uid", model->meta.linux_uid, actual->meta.linux_uid);
            return d.result();
        } else if constexpr (type == EntityType::VAULT) {
            const auto label = "Vault " + std::to_string(entity->id) + " ('" + entity->name + "')";
            const auto live = db::query::vault::Vault::getVault(entity->id);
            if (!live) return AssertionResult::Fail(label + " not found in DB (or scheduled for deletion)");
            Diff d{label, {}};
            d.field("name", entity->name, live->name);
            d.field("owner_id", entity->owner_id, live->owner_id);
            d.field("description", nonEmpty(entity->description), nonEmpty(live->description));
            d.field("quota", entity->quota, live->quota);
            return d.result();
        } else if constexpr (type == EntityType::GROUP) {
            const auto label = "Group " + std::to_string(entity->id) + " ('" + entity->name() + "')";
            if (!db::query::identities::Group::groupExists(entity->name()))
                return AssertionResult::Fail(label + " not found in DB by name");
            const auto live = vh::identities::manager().group(entity->id);
            if (!live) return AssertionResult::Fail(label + " not found in the identity manager");
            const auto model = entity->state();
            const auto actual = live->state();
            Diff d{label, {}};
            d.field("name", model->name, actual->name);
            d.field("description", nonEmpty(model->description), nonEmpty(actual->description));
            d.field("linux_gid", std::optional<uint32_t>(model->linux_gid), std::optional<uint32_t>(actual->linux_gid));
            return d.result();
        } else if constexpr (type == EntityType::ADMIN_ROLE) {
            const auto label = "Admin role " + std::to_string(entity->id) + " ('" + entity->name + "')";
            const auto live = db::query::rbac::role::Admin::get(entity->id);
            if (!live) return AssertionResult::Fail(label + " not found in DB");
            Diff d{label, {}};
            d.field("name", entity->name, live->name);
            d.field("description", nonEmpty(entity->description), nonEmpty(live->description));
            d.field("permissions", entity->toFlagsString(), live->toFlagsString());
            return d.result();
        } else if constexpr (type == EntityType::VAULT_ROLE) {
            const auto label = "Vault role " + std::to_string(entity->id) + " ('" + entity->name + "')";
            const auto live = db::query::rbac::role::Vault::get(entity->id);
            if (!live) return AssertionResult::Fail(label + " not found in DB");
            Diff d{label, {}};
            d.field("name", entity->name, live->name);
            d.field("description", nonEmpty(entity->description), nonEmpty(live->description));
            d.field("permissions", entity->toFlagsString(), live->toFlagsString());
            return d.result();
        } else {
            return AssertionResult::Fail("Validator: unsupported entity type for existence check");
        }
    }

    // Gone from the live set after a successful delete. A deleted vault keeps its row (and name) until it is purged
    // (#162), so "gone" for a vault means getVault() no longer returns it.
    static AssertionResult assert_not_exists(const std::shared_ptr<T>& entity) {
        if constexpr (type == EntityType::USER) {
            if (db::query::identities::User::userExists(entity->name()))
                return AssertionResult::Fail("User '" + entity->name() + "' unexpectedly found in DB");
            if (const auto live = vh::identities::manager().user(entity->id); live && !live->state()->deleted)
                return AssertionResult::Fail("User " + std::to_string(entity->id) + " still live in the identity manager");
            return AssertionResult::Pass();
        } else if constexpr (type == EntityType::VAULT) {
            if (db::query::vault::Vault::getVault(entity->id))
                return AssertionResult::Fail("Vault " + std::to_string(entity->id) + " ('" + entity->name + "') is still live");
            return AssertionResult::Pass();
        } else if constexpr (type == EntityType::GROUP) {
            if (db::query::identities::Group::groupExists(entity->name()))
                return AssertionResult::Fail("Group '" + entity->name() + "' unexpectedly found in DB");
            if (vh::identities::manager().group(entity->id))
                return AssertionResult::Fail("Group " + std::to_string(entity->id) + " still live in the identity manager");
            return AssertionResult::Pass();
        } else if constexpr (type == EntityType::ADMIN_ROLE) {
            if (db::query::rbac::role::Admin::exists(entity->id))
                return AssertionResult::Fail("Admin role " + std::to_string(entity->id) + " ('" + entity->name + "') unexpectedly found in DB");
            return AssertionResult::Pass();
        } else if constexpr (type == EntityType::VAULT_ROLE) {
            if (db::query::rbac::role::Vault::exists(entity->id))
                return AssertionResult::Fail("Vault role " + std::to_string(entity->id) + " ('" + entity->name + "') unexpectedly found in DB");
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
