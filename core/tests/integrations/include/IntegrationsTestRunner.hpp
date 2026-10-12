#pragma once

#include "cli/Config.hpp"
#include "RunOptions.hpp"
#include "rbac/permission/Override.hpp"
#include "TestStage.hpp"
#include "identities/Fwd.hpp"
#include "protocols/shell/Fwd.hpp"

#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <atomic>
#include <optional>

namespace vh::test::integration {
    struct TestCase;
    namespace concurrency { class TestThreadPool; }
    namespace cli { struct Context; }
    namespace cmd { struct Router; }

enum class EntityType;

struct Expectations {
    std::vector<std::string> must_have;
    std::vector<std::string> must_not_have;
};

class IntegrationsTestRunner {
public:
    explicit IntegrationsTestRunner(RunOptions options);

    void registerStdoutContains(const std::string& path, std::string needle);
    void registerStdoutNotContains(const std::string& path, std::string needle);
    void registerStdoutContains(const std::string& path, std::vector<std::string> needles);
    void registerStdoutNotContains(const std::string& path, std::vector<std::string> needles);

    // Runs the selected stages, prints the results, writes the reports; returns the process exit status (non-zero
    // when any test failed or none ran).
    int operator()();

    static std::optional<unsigned int> extractId(std::string_view output, std::string_view idPrefix);

private:
    RunOptions options_;
    cli::Config config_;
    std::shared_ptr<cli::Context> ctx_;
    std::shared_ptr<protocols::shell::UsageManager> usage_;
    std::shared_ptr<cmd::Router> router_;
    std::shared_ptr<std::atomic<bool>> interruptFlag;
    std::shared_ptr<concurrency::TestThreadPool> threadPool_;
    std::chrono::system_clock::time_point startedAt_;

    // Expectations are keyed by command path
    std::unordered_map<std::string, Expectations> expectations_by_path_;

    // Pipeline stages executed in order
    std::vector<TestStage> stages_;

    // Open Linux users
    std::vector<unsigned int> linux_uids_;
    std::vector<unsigned int> linux_gids_;

    void registerAllContainsAssertions();

    // Runs one stage; an exception becomes a failed test in an "<name> (aborted)" stage instead of ending the run.
    void runStage(const std::string& name, const std::function<void()>& fn);

    // Pipeline steps
    void seed();
    void assign();
    void readStage();
    void updateStage();
    void validateAllTestObjects();
    void teardownStage();

    // FUSE steps
    std::shared_ptr<identities::User> createUser(unsigned int vaultId, const std::optional<uint16_t>& vaultPerms = std::nullopt, const std::vector<rbac::permission::Override>& overrides = {});
    void runFUSETests();

    // Helpers
    void validateStage(const TestStage& stage) const;
    int  printResults() const;
    void writeReports(int exitStatus) const;

    template <EntityType E>
    void finish_seed(const std::vector<std::shared_ptr<TestCase>>& res);
};

}
