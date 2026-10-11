#pragma once

#include "protocols/shell/types.hpp"

#include <memory>
#include <string>

namespace vh::test::integration {
    enum class EntityType {
        USER,
        VAULT,
        GROUP,
        ADMIN_ROLE,
        VAULT_ROLE
    };

    enum class CommandType {
        CREATE,
        UPDATE,
        DELETE,
        LIST,
        INFO,
        ASSIGN,
        UNASSIGN
    };

    enum class ActionType {
        ADD,
        REMOVE,
        SET
    };

    struct ExecResult {
        int exit_code = -1; // 0 on success, else the errno that decided the outcome
        std::string stdout_text; // "OK <op> ..." lines, listings, file contents
        std::string stderr_text;
        std::string command{};   // what ran (for the report)
        bool wedge = false;      // the per-op deadline expired (fuse/Actor.hpp)
    };

    struct EntityResult {
        protocols::shell::CommandResult result{};
        std::shared_ptr<void> entity{};
        std::string command{};   // the generated `vh ...` line
    };

    inline std::string EntityTypeToString(const EntityType &type) {
        switch (type) {
            case EntityType::USER: return "user";
            case EntityType::VAULT: return "vault";
            case EntityType::GROUP: return "group";
            case EntityType::ADMIN_ROLE:
            case EntityType::VAULT_ROLE: return "role";
            default: return "unknown";
        }
    }

    inline std::string CommandTypeToString(const CommandType &type) {
        switch (type) {
            case CommandType::CREATE: return "create";
            case CommandType::UPDATE: return "update";
            case CommandType::DELETE: return "delete";
            case CommandType::LIST: return "list";
            case CommandType::INFO: return "info";
            case CommandType::ASSIGN: return "assign";
            case CommandType::UNASSIGN: return "unassign";
            default: return "unknown";
        }
    }

    inline std::string ActionTypeToString(const ActionType &type) {
        switch (type) {
            case ActionType::ADD: return "add";
            case ActionType::REMOVE: return "remove";
            case ActionType::SET: return "set";
            default: return "unknown";
        }
    }
}
