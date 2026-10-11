#pragma once

#include "types/Type.hpp"
#include "types/AssertionResult.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace vh::test::integration {

struct TestCase {
    std::string name{};
    std::string path{};          // e.g. "user/create"
    int expect_exit{0};
    std::optional<EntityType> subjectType{std::nullopt};
    std::vector<std::string> must_contain{};     // stdout contains
    std::vector<std::string> must_not_contain{}; // stdout must NOT contain
    std::shared_ptr<void> entity{nullptr}, target{nullptr}, subject{nullptr}; // optional entity to be used in the tes
    protocols::shell::CommandResult result{}; // filled after execution
    AssertionResult assertion{};
    std::string command{};       // the generated command line or probe that ran
    std::string stream{};        // seed stream label: the test's RNG is h64(root, stream, streamIndex)
    uint64_t streamIndex{0};
    double duration_ms{0};
    bool wedge{false};           // a filesystem probe hit its deadline (fuse/Actor.hpp)

    // Records another reason this test failed, keeping the earlier ones.
    void fail(const std::string& why) {
        if (assertion.ok || assertion.message.empty()) assertion = AssertionResult::Fail(why);
        else assertion = AssertionResult::Fail(assertion.message + "\n" + why);
    }

    static TestCase List(const EntityType& type, const int expect_exit = 0) {
        const auto typeStr = EntityTypeToString(type);
        const std::string actionStr = "list";
        auto name = actionStr + " " + typeStr;
        auto path = typeStr + "/" + actionStr;
        if (type == EntityType::ADMIN_ROLE) {
            name += " (admin)";
            path += "/admin";
        } else if (type == EntityType::VAULT_ROLE) {
            name += " (vault)";
            path += "/vault";
        }
        return TestCase{
            .name = name,
            .path = path,
            .expect_exit = expect_exit,
            .must_contain = {},
            .must_not_contain = {},
            .entity = nullptr,
            .assertion = {}
        };
    }

    static TestCase Delete(const EntityType& type, const std::shared_ptr<void>& entity, const int expect_exit = 0) {
        const auto typeStr = EntityTypeToString(type);
        const std::string actionStr = "delete";
        auto name = actionStr + " " + typeStr;
        auto path = typeStr + "/" + actionStr;
        if (type == EntityType::ADMIN_ROLE) {
            name += " (admin)";
            path += "/admin";
        } else if (type == EntityType::VAULT_ROLE) {
            name += " (vault)";
            path += "/vault";
        }
        return TestCase{
            .name = name,
            .path = path,
            .expect_exit = expect_exit,
            .must_contain = {},
            .must_not_contain = {},
            .entity = entity,
            .assertion = {}
        };
    }

    static TestCase Generate(const EntityType& type, const CommandType& command, const std::shared_ptr<void>& entity = nullptr) {
        const auto typeStr = EntityTypeToString(type);
        const auto actionStr = CommandTypeToString(command);
        auto name = actionStr + " " + typeStr;
        auto path = typeStr + "/" + actionStr;
        if (type == EntityType::ADMIN_ROLE) {
            name += " (admin)";
            path += "/admin";
        } else if (type == EntityType::VAULT_ROLE) {
            name += " (vault)";
            path += "/vault";
        }
        return TestCase{
            .name = name,
            .path = path,
            .expect_exit = 0,
            .must_contain = {},
            .must_not_contain = {},
            .entity = entity,
            .assertion = {}
        };
    }

    static TestCase Generate(const EntityType& type, const EntityType& targetType, const ActionType& action, const std::shared_ptr<void>& entity, const std::shared_ptr<void>& target) {
        const auto typeStr = EntityTypeToString(type);
        const auto targetTypeStr = EntityTypeToString(targetType);
        const auto actionStr = ActionTypeToString(action);
        const auto name = typeStr + " " + actionStr + " " + targetTypeStr;
        const auto path = typeStr + "/" + targetTypeStr + "/" + actionStr;
        return TestCase{
            .name = name,
            .path = path,
            .expect_exit = 0,
            .must_contain = {},
            .must_not_contain = {},
            .entity = entity,
            .target = target,
            .assertion = {}
        };
    }

    static std::shared_ptr<TestCase> Generate(const EntityType& type, const EntityType& targetType, const EntityType& subjectType, const CommandType& command, const std::shared_ptr<void>& entity, const std::shared_ptr<void>& target, const std::shared_ptr<void>& subject) {
        const auto typeStr = EntityTypeToString(type);
        const auto targetTypeStr = EntityTypeToString(targetType);
        const auto commandStr = CommandTypeToString(command);
        const auto subjectTypeStr = EntityTypeToString(subjectType);
        const auto name = typeStr + " " + commandStr + " " + targetTypeStr + " to " + subjectTypeStr;
        const auto path = typeStr + "/" + targetTypeStr + "/" + commandStr;
        return std::make_shared<TestCase>(TestCase{
            .name = name,
            .path = path,
            .expect_exit = 0,
            .subjectType = subjectType,
            .must_contain = {},
            .must_not_contain = {},
            .entity = entity,
            .target = target,
            .subject = subject,
            .assertion = {}
        });
    }
};

}
