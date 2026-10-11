#pragma once

#include "rbac/role/Vault.hpp"
#include "identities/Group.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "vault/model/Vault.hpp"
#include "protocols/shell/Router.hpp"
#include "cli/Context.hpp"
#include "cmd/Registry.hpp"
#include "types/Type.hpp"
#include "entity/Factory.hpp"
#include "protocols/shell/commands/all.hpp"
#include "db/query/identities/User.hpp"

#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <iostream>

namespace vh::test::integration::entity {

struct SeedContext {
    unsigned int numUsers = 10;
    unsigned int numVaults = 15;
    unsigned int numGroups = 5;
    unsigned int numUserRoles = 7;
    unsigned int numVaultRoles = 7;
};

class Registrar {
public:
    explicit Registrar(const std::shared_ptr<cli::Context>& ctx)
        : factory_(std::make_shared<Factory>(ctx)),
          router_(std::make_shared<protocols::shell::Router>()), ctx_(ctx) {
        if (!router_) throw std::runtime_error("EntityRegistrar: router is null");
        protocols::shell::commands::registerAllCommands(router_);
    }

        [[nodiscard]] EntityResult create(const EntityType& type) const {
        const auto cmd = ctx_->getCommand(type, "create");
        if (!cmd) throw std::runtime_error("EntityRegistrar: command usage not found for creation");

        const auto admin = vh::identities::manager().userByName("admin");
        int fd = -1;
        const auto io = std::make_unique<protocols::shell::SocketIO>(fd);

        const auto buildCommand = [&](const std::shared_ptr<void>& entity) {
            const auto command = cmd::Registry::instance().buildCommand(type, CommandType::CREATE, entity);
            std::cout << command << std::endl;
            return command;
        };

        if (type == EntityType::USER) {
            const auto user = factory_->create(EntityType::USER);
            const auto command = buildCommand(user);
            return { router_->executeLine(command, admin, io.get()), user };
        }

        if (type == EntityType::VAULT) {
            const auto vault = factory_->create(EntityType::VAULT);
            const auto command = buildCommand(vault);
            return { router_->executeLine(command, admin, io.get()), vault };
        }

        if (type == EntityType::GROUP) {
            const auto group = factory_->create(EntityType::GROUP);
            const auto command = buildCommand(group);
            return { router_->executeLine(command, admin, io.get()), group };
        }

        if (type == EntityType::ADMIN_ROLE) {
            const auto role = factory_->create(EntityType::ADMIN_ROLE);
            const auto command = buildCommand(role);
            return { router_->executeLine(command, admin, io.get()), role };
        }

        if (type == EntityType::VAULT_ROLE) {
            const auto role = factory_->create(EntityType::VAULT_ROLE);
            const auto command = buildCommand(role);
            return { router_->executeLine(command, admin, io.get()), role };
        }

        throw std::runtime_error("EntityRegistrar: unsupported entity type for creation");
    }

    [[nodiscard]] std::vector<EntityResult> create(const EntityType& type, const std::size_t count) const {
        std::vector<EntityResult> results;
        for (std::size_t i = 0; i < count; ++i) results.push_back(create(type));
        return results;
    }

    template <typename T>
    [[nodiscard]] EntityResult update(const EntityType& type, const std::shared_ptr<T>& entity) const {
        const auto command = cmd::Registry::instance().buildCommand(type, CommandType::UPDATE, entity);
        std::cout << command << std::endl;
        const auto admin = vh::identities::manager().userByName("admin");
        int fd = -1;
        const auto io = std::make_unique<protocols::shell::SocketIO>(fd);
        return {router_->executeLine(command, admin, io.get()), entity};
    }

    [[nodiscard]] EntityResult list(const EntityType& type) const {
        const auto cmd = ctx_->getCommand(type, "list");
        if (!cmd) throw std::runtime_error("EntityRegistrar: command usage not found for listing");
        const auto command = cmd::Registry::instance().buildCommand(type, CommandType::LIST, nullptr);
        std::cout << command << std::endl;
        const auto admin = vh::identities::manager().userByName("admin");
        int fd = -1;
        const auto io = std::make_unique<protocols::shell::SocketIO>(fd);
        return {router_->executeLine(command, admin, io.get())};
    }

    template <typename T>
    [[nodiscard]] EntityResult info(const EntityType& type, const std::shared_ptr<T>& entity) const {
        const auto cmd = ctx_->getCommand(type, "info");
        if (!cmd) throw std::runtime_error("EntityRegistrar: command usage not found for info");
        const auto command = cmd::Registry::instance().buildCommand(type, CommandType::INFO, entity);
        std::cout << command << std::endl;
        const auto admin = vh::identities::manager().userByName("admin");
        int fd = -1;
        const auto io = std::make_unique<protocols::shell::SocketIO>(fd);
        return {router_->executeLine(command, admin, io.get())};
    }

    [[nodiscard]] EntityResult remove(const EntityType& type, const std::shared_ptr<void>& entity) const {
        const auto cmd = ctx_->getCommand(type, "delete");
        if (!cmd) throw std::runtime_error("EntityRegistrar: command usage not found for deletion");

        const auto admin = vh::identities::manager().userByName("admin");
        int fd = -1;
        const auto io = std::make_unique<protocols::shell::SocketIO>(fd);

        const auto command = cmd::Registry::instance().buildCommand(type, CommandType::DELETE, entity);
        std::cout << command << std::endl;
        return { router_->executeLine(command, admin, io.get()), entity };
    }

    [[nodiscard]] EntityResult manageGroup(const EntityType& type, const ActionType& action, const std::shared_ptr<Group>& group, const std::shared_ptr<User>& user) const {
        if (type != EntityType::USER && type != EntityType::VAULT)
            throw std::runtime_error("EntityRegistrar: manageGroup only supports USER and VAULT entity types");

        const auto admin = vh::identities::manager().userByName("admin");
        int fd = -1;
        const auto io = std::make_unique<protocols::shell::SocketIO>(fd);

        const auto command = cmd::Registry::instance().buildCommand(EntityType::GROUP, type, action, group, user);

        std::cout << command << std::endl;
        return { router_->executeLine(command, admin, io.get()), group };
    }

    [[nodiscard]] EntityResult manageVaultRoleAssignments(const EntityType& type, const CommandType& cmdType,
                                                          const std::shared_ptr<Vault>& vault,
                                                          const std::shared_ptr<role::Vault>& role,
                                                          const std::shared_ptr<void>& entity) const {
        if (type != EntityType::USER && type != EntityType::GROUP)
            throw std::runtime_error("EntityRegistrar: manageVaultRoleAssignments only supports USER and GROUP entity types");

        if (cmdType != CommandType::ASSIGN && cmdType != CommandType::UNASSIGN)
            throw std::runtime_error("EntityRegistrar: manageVaultRoleAssignments only supports ASSIGN and UNASSIGN command types");

        const auto admin = vh::identities::manager().userByName("admin");
        int fd = -1;
        const auto io = std::make_unique<protocols::shell::SocketIO>(fd);

        const auto command = cmd::Registry::instance().buildCommand(EntityType::VAULT, EntityType::VAULT_ROLE, type, cmdType, vault, role, entity);

        std::cout << command << std::endl;
        return { router_->executeLine(command, admin, io.get()), role };
    }

private:
    static constexpr std::string_view ID_REGEX = R"(ID:\s*(\d+))";
    std::shared_ptr<Factory> factory_;
    std::shared_ptr<protocols::shell::Router> router_;
    std::shared_ptr<cli::Context> ctx_;

    static std::regex toRegex(const std::string_view& pattern) {
        return std::regex(std::string(pattern), std::regex::icase);
    }

    static unsigned int extractId(const std::string& output) {
        std::smatch match;
        if (std::regex_search(output, match, toRegex(ID_REGEX)) && match.size() > 1)
            return std::stoi(match.str(1));
        throw std::runtime_error("EntityRegistrar: failed to parse ID from output");
    }
};

}
