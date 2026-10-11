#pragma once

#include "types/Type.hpp"
#include "cmd/generators.hpp"
#include "cli/Context.hpp"
#include "identities/User.hpp"
#include "vault/model/Vault.hpp"
#include "identities/Group.hpp"
#include "entity/Edit.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"
#include "randomizer/AdminRole.hpp"
#include "randomizer/VaultRole.hpp"

#include <string>
#include <memory>
#include <optional>

using vh::identities::User;
using vh::identities::Group;
using namespace vh::rbac;
using namespace vh::vault::model;

namespace vh::test::integration::entity {

class Factory {
public:
    explicit Factory(const std::shared_ptr<cli::Context>& ctx) : ctx_(ctx) {}

    [[nodiscard]] std::shared_ptr<void> create(const EntityType& type) const {
        if (type == EntityType::USER) {
            const std::string usage = "user/create";
            vh::identities::UserState spec;
            spec.name = generateName(usage);
            if (coin()) spec.email = generateEmail(usage);
            spec.roles.admin = ctx_->randomAdminRole();
            return User::detached(0, std::move(spec));
        }

        if (type == EntityType::VAULT) {
            const std::string usage = "vault/create";
            const auto vault = std::make_shared<Vault>();
            vault->name = generateName(usage);
            vault->setQuotaFromStr(generateQuotaStr(usage));
            vault->owner_id = ctx_->pickRandomUser()->id;
            return vault;
        }

        if (type == EntityType::GROUP) {
            vh::identities::GroupState spec;
            spec.name = generateName("group/create");
            return Group::detached(0, std::move(spec));
        }

        if (type == EntityType::ADMIN_ROLE) {
            const auto role = std::make_shared<role::Admin>();
            role->name = generateRoleName(type, "role/create");
            role->description = "Auto-generated user role";
            randomizer::AdminRole::assignRandomPermissions(role);
            return role;
        }

        if (type == EntityType::VAULT_ROLE) {
            const auto role = std::make_shared<role::Vault>();
            role->name = generateRoleName(type, "role/create");
            role->description = "Auto-generated vault role";
            randomizer::VaultRole::assignRandomPermissions(role);
            return role;
        }

        return nullptr;
    }

    void seedBaseline(const std::shared_ptr<cli::Context>& ctx);

private:
    std::shared_ptr<cli::Context> ctx_;
};

}
