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
        if (type != EntityType::USER && type != EntityType::VAULT && type != EntityType::GROUP &&
            type != EntityType::ADMIN_ROLE && type != EntityType::VAULT_ROLE)
            throw std::runtime_error("EntityRegistrar: unsupported entity type for creation");

        const auto entity = factory_->create(type);
        return run(cmd::Registry::instance().buildCommand(type, CommandType::CREATE, entity), entity);
    }

    [[nodiscard]] std::vector<EntityResult> create(const EntityType& type, const std::size_t count) const {
        std::vector<EntityResult> results;
        for (std::size_t i = 0; i < count; ++i) results.push_back(create(type));
        return results;
    }

    // The model takes an update's new values only after the command succeeded (F7).
    template <typename T>
    [[nodiscard]] EntityResult update(const EntityType& type, const std::shared_ptr<T>& entity) const {
        auto built = cmd::Registry::instance().buildUpdate(type, entity);
        auto res = run(built.line, entity);
        if (res.result.exit_code == 0 && built.commit) built.commit();
        return res;
    }

    [[nodiscard]] EntityResult list(const EntityType& type) const {
        const auto cmd = ctx_->getCommand(type, "list");
        if (!cmd) throw std::runtime_error("EntityRegistrar: command usage not found for listing");
        return run(cmd::Registry::instance().buildCommand(type, CommandType::LIST, nullptr), nullptr);
    }

    template <typename T>
    [[nodiscard]] EntityResult info(const EntityType& type, const std::shared_ptr<T>& entity) const {
        const auto cmd = ctx_->getCommand(type, "info");
        if (!cmd) throw std::runtime_error("EntityRegistrar: command usage not found for info");
        return run(cmd::Registry::instance().buildCommand(type, CommandType::INFO, entity), nullptr);
    }

    [[nodiscard]] EntityResult remove(const EntityType& type, const std::shared_ptr<void>& entity) const {
        const auto cmd = ctx_->getCommand(type, "delete");
        if (!cmd) throw std::runtime_error("EntityRegistrar: command usage not found for deletion");
        return run(cmd::Registry::instance().buildCommand(type, CommandType::DELETE, entity), entity);
    }

    [[nodiscard]] EntityResult manageGroup(const EntityType& type, const ActionType& action, const std::shared_ptr<Group>& group, const std::shared_ptr<User>& user) const {
        if (type != EntityType::USER && type != EntityType::VAULT)
            throw std::runtime_error("EntityRegistrar: manageGroup only supports USER and VAULT entity types");
        return run(cmd::Registry::instance().buildCommand(EntityType::GROUP, type, action, group, user), group);
    }

    [[nodiscard]] EntityResult manageVaultRoleAssignments(const EntityType& type, const CommandType& cmdType,
                                                          const std::shared_ptr<Vault>& vault,
                                                          const std::shared_ptr<role::Vault>& role,
                                                          const std::shared_ptr<void>& entity) const {
        if (type != EntityType::USER && type != EntityType::GROUP)
            throw std::runtime_error("EntityRegistrar: manageVaultRoleAssignments only supports USER and GROUP entity types");

        if (cmdType != CommandType::ASSIGN && cmdType != CommandType::UNASSIGN)
            throw std::runtime_error("EntityRegistrar: manageVaultRoleAssignments only supports ASSIGN and UNASSIGN command types");

        return run(cmd::Registry::instance().buildCommand(EntityType::VAULT, EntityType::VAULT_ROLE, type, cmdType,
                                                          vault, role, entity), role);
    }

private:
    std::shared_ptr<Factory> factory_;
    std::shared_ptr<protocols::shell::Router> router_;
    std::shared_ptr<cli::Context> ctx_;

    // Runs one generated line as the admin, in-process through shell::Router (no socket framing: F3). An exception
    // that escapes executeLine becomes what the CLI server replies with (shell/Server.cpp: exit 1, the message on
    // stderr), marked so the report shows it was not a handled error.
    [[nodiscard]] EntityResult run(const std::string& command, const std::shared_ptr<void>& entity) const {
        std::cout << command << std::endl;
        const auto admin = vh::identities::manager().userByName("admin");
        int fd = -1;
        const auto io = std::make_unique<protocols::shell::SocketIO>(fd);
        try {
            return {router_->executeLine(command, admin, io.get()), entity, command};
        } catch (const std::exception& e) {
            protocols::shell::CommandResult r;
            r.exit_code = 1;
            r.stderr_text = std::string("exception escaped shell::Router::executeLine: ") + e.what();
            return {r, entity, command};
        }
    }
};

}
