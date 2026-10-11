#pragma once

#include "cmd/Builder.hpp"
#include "types/Type.hpp"
#include "UsageManager.hpp"

#include <memory>

namespace vh::test::integration::cmd {

class Registry {
public:
    std::shared_ptr<UserCommandBuilder> userBuilder;
    std::shared_ptr<VaultCommandBuilder> vaultBuilder;
    std::shared_ptr<GroupCommandBuilder> groupBuilder;
    std::shared_ptr<AdminRoleCommandBuilder> userRoleBuilder;
    std::shared_ptr<VaultRoleCommandBuilder> vaultRoleBuilder;


    Registry(const Registry&) = delete;

    Registry& operator=(const Registry&) = delete;

    static Registry& instance() {
        static Registry instance;
        return instance;
    }

    static void init(const std::shared_ptr<protocols::shell::UsageManager>& usage, const std::shared_ptr<cli::Context>& ctx) {
        auto& registry = instance();
        registry.userBuilder = std::make_shared<UserCommandBuilder>(usage, ctx);
        registry.vaultBuilder = std::make_shared<VaultCommandBuilder>(usage, ctx);
        registry.groupBuilder = std::make_shared<GroupCommandBuilder>(usage, ctx);
        registry.userRoleBuilder = std::make_shared<AdminRoleCommandBuilder>(usage, ctx);
        registry.vaultRoleBuilder = std::make_shared<VaultRoleCommandBuilder>(usage, ctx);
    }

    [[nodiscard]] std::string buildCommand(const EntityType& entityType, const CommandType& cmdType,
                                           const std::shared_ptr<void>& entity) const {
        switch (entityType) {
        case EntityType::USER: switch (cmdType) {
            case CommandType::CREATE: return userBuilder->create(std::static_pointer_cast<identities::User>(entity));
            case CommandType::DELETE: return userBuilder->remove(std::static_pointer_cast<identities::User>(entity));
            case CommandType::INFO: return userBuilder->info(std::static_pointer_cast<identities::User>(entity));
            case CommandType::LIST: return userBuilder->list();
            default: throw std::runtime_error("CommandBuilderRegistry: unsupported command type for USER");
            }
        case EntityType::VAULT: switch (cmdType) {
            case CommandType::CREATE: return vaultBuilder->create(std::static_pointer_cast<vault::model::Vault>(entity));
            case CommandType::DELETE: return vaultBuilder->remove(std::static_pointer_cast<vault::model::Vault>(entity));
            case CommandType::INFO: return vaultBuilder->info(std::static_pointer_cast<vault::model::Vault>(entity));
            case CommandType::LIST: return vaultBuilder->list();
            default: throw std::runtime_error("CommandBuilderRegistry: unsupported command type for VAULT");
            }
        case EntityType::GROUP: switch (cmdType) {
            case CommandType::CREATE: return groupBuilder->create(std::static_pointer_cast<identities::Group>(entity));
            case CommandType::DELETE: return groupBuilder->remove(std::static_pointer_cast<identities::Group>(entity));
            case CommandType::INFO: return groupBuilder->info(std::static_pointer_cast<identities::Group>(entity));
            case CommandType::LIST: return groupBuilder->list();
            default: throw std::runtime_error("CommandBuilderRegistry: unsupported command type for GROUP");
            }
        case EntityType::ADMIN_ROLE: switch (cmdType) {
            case CommandType::CREATE: return userRoleBuilder->create(std::static_pointer_cast<rbac::role::Admin>(entity));
            case CommandType::DELETE: return userRoleBuilder->remove(std::static_pointer_cast<rbac::role::Admin>(entity));
            case CommandType::INFO: return userRoleBuilder->info(std::static_pointer_cast<rbac::role::Admin>(entity));
            case CommandType::LIST: return userRoleBuilder->list();
            default: throw std::runtime_error("CommandBuilderRegistry: unsupported command type for USER_ROLE");
            }
        case EntityType::VAULT_ROLE: switch (cmdType) {
            case CommandType::CREATE: return vaultRoleBuilder->create(
                    std::static_pointer_cast<rbac::role::Vault>(entity));
            case CommandType::DELETE: return vaultRoleBuilder->remove(
                    std::static_pointer_cast<rbac::role::Vault>(entity));
            case CommandType::INFO: return vaultRoleBuilder->info(std::static_pointer_cast<rbac::role::Vault>(entity));
            case CommandType::LIST: return vaultRoleBuilder->list();
            default: throw std::runtime_error("CommandBuilderRegistry: unsupported command type for VAULT_ROLE");
            }
        default: throw std::runtime_error("CommandBuilderRegistry: unsupported entity type");
        }
    }

    // Updates return the proposed model change with the command; the caller commits it once the command succeeded.
    [[nodiscard]] BuiltCommand buildUpdate(const EntityType& entityType, const std::shared_ptr<void>& entity) const {
        switch (entityType) {
        case EntityType::USER: return userBuilder->update(std::static_pointer_cast<identities::User>(entity));
        case EntityType::VAULT: return vaultBuilder->update(std::static_pointer_cast<vault::model::Vault>(entity));
        case EntityType::GROUP: return groupBuilder->update(std::static_pointer_cast<identities::Group>(entity));
        case EntityType::ADMIN_ROLE: return userRoleBuilder->update(std::static_pointer_cast<rbac::role::Admin>(entity));
        case EntityType::VAULT_ROLE: return vaultRoleBuilder->update(std::static_pointer_cast<rbac::role::Vault>(entity));
        default: throw std::runtime_error("CommandBuilderRegistry: unsupported entity type for update");
        }
    }

    [[nodiscard]] std::string buildCommand(const EntityType& entityType,
                                           const EntityType& targetType,
                                           const EntityType& subjectType,
                                           const CommandType& cmdType,
                                           const std::shared_ptr<void>& entity,
                                           const std::shared_ptr<void>& target,
                                           const std::shared_ptr<void>& subject) const {
        if (entityType != EntityType::VAULT) throw std::runtime_error("CommandBuilderRegistry: only VAULT supports role assignments");
        if (targetType != EntityType::VAULT_ROLE) throw std::runtime_error("CommandBuilderRegistry: only VAULT_ROLE supported as target for role assignments");
        if (cmdType != CommandType::ASSIGN && cmdType != CommandType::UNASSIGN)
            throw std::runtime_error("CommandBuilderRegistry: only ASSIGN and UNASSIGN supported for role assignments");
        if (subjectType != EntityType::USER && subjectType != EntityType::GROUP)
            throw std::runtime_error("CommandBuilderRegistry: only USER and GROUP supported for role assignments");

        if (cmdType == CommandType::ASSIGN)
            return vaultBuilder->assignVaultRole(std::static_pointer_cast<vault::model::Vault>(entity),
                                            std::static_pointer_cast<rbac::role::Vault>(target),
                                            subjectType,
                                            subject);

        return vaultBuilder->unassignVaultRole(std::static_pointer_cast<vault::model::Vault>(entity),
                                              std::static_pointer_cast<rbac::role::Vault>(target),
                                              subjectType,
                                              subject);
    }

    [[nodiscard]] std::string buildCommand(const EntityType& entityType,
                                           const EntityType& targetType,
                                           const ActionType& actionType,
                                           const std::shared_ptr<void>& entity,
                                           const std::shared_ptr<void>& target) const {
        switch (entityType) {
        case EntityType::GROUP: switch (targetType) {
            case EntityType::USER: switch (actionType) {
                case ActionType::ADD: return groupBuilder->addUser(std::static_pointer_cast<identities::Group>(entity),
                                                                   std::static_pointer_cast<identities::User>(target));
                case ActionType::REMOVE: return groupBuilder->removeUser(
                        std::static_pointer_cast<identities::Group>(entity),
                        std::static_pointer_cast<identities::User>(target));
                default: throw std::runtime_error("CommandBuilderRegistry: unsupported action type for GROUP-USER assignment");
                }
            default: throw std::runtime_error("CommandBuilderRegistry: unsupported target entity type for GROUP assignment");
            }
            default: throw std::runtime_error("CommandBuilderRegistry: unsupported entity type for assignment");
        }
    }

private
:
    Registry() = default; // private ctor
};

}