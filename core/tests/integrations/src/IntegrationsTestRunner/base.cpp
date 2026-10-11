#include "IntegrationsTestRunner.hpp"
#include "Validator.hpp"

#include "UsageManager.hpp"
#include "cli/Context.hpp"
#include "entity/Registrar.hpp"

#include "cmd/Router.hpp"
#include "cmd/Registry.hpp"
#include "types/Type.hpp"

#include "concurrency/TestThreadPool.hpp"
#include "TestCase.hpp"
#include "concurrency/TestTask.hpp"
#include "cli/Task.hpp"

#include "identities/User.hpp"
#include "identities/Group.hpp"
#include "vault/model/Vault.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"

#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <optional>
#include <string_view>
#include <utility>
#include <future>

using namespace vh::args;
using vh::identities::User;
using vh::identities::Group;
using namespace vh::vault::model;
using namespace vh::rbac;

namespace vh::test::integration {

// ---------- Small utilities

std::optional<unsigned int>
IntegrationsTestRunner::extractId(std::string_view output, std::string_view idPrefix) {
    const auto pos = output.find(idPrefix);
    if (pos == std::string_view::npos) return std::nullopt;
    const auto start = pos + idPrefix.size();
    const auto nl = output.find('\n', start);
    const auto end = (nl == std::string_view::npos) ? output.size() : nl;
    try {
        return static_cast<unsigned int>(std::stoul(std::string(output.substr(start, end - start))));
    } catch (...) {
        return std::nullopt;
    }
}

// ---------- Traits describing each entity bucket

template <EntityType E> struct EntityTraits;

template <> struct EntityTraits<EntityType::USER> {
    using Type = User;
    static constexpr std::string_view kStage = "Users";
    static constexpr std::string_view kIdPrefix = "User ID:";
    static std::vector<std::shared_ptr<Type>>& vec(cli::Context& c) { return c.users; }
};

template <> struct EntityTraits<EntityType::GROUP> {
    using Type = Group;
    static constexpr std::string_view kStage = "Groups";
    static constexpr std::string_view kIdPrefix = "Group ID:";
    static std::vector<std::shared_ptr<Type>>& vec(cli::Context& c) { return c.groups; }
};

template <> struct EntityTraits<EntityType::VAULT> {
    using Type = Vault;
    static constexpr std::string_view kStage = "Vaults";
    static constexpr std::string_view kIdPrefix = "ID:";
    static std::vector<std::shared_ptr<Type>>& vec(cli::Context& c) { return c.vaults; }
};

template <> struct EntityTraits<EntityType::ADMIN_ROLE> {
    using Type = role::Admin;
    static constexpr std::string_view kStage = "Admin Roles";
    static constexpr std::string_view kIdPrefix = "Role ID:";
    static std::vector<std::shared_ptr<Type>>& vec(cli::Context& c) { return c.adminRoles; }
};

// VaultRole
template <> struct EntityTraits<EntityType::VAULT_ROLE> {
    using Type = role::Vault;
    static constexpr std::string_view kStage = "Vault Roles";
    static constexpr std::string_view kIdPrefix = "Role ID:";
    static std::vector<std::shared_ptr<Type>>& vec(cli::Context& c) { return c.vaultRoles; }
};

// ---------- Tiny generic helpers (local to this TU)

template <EntityType E>
static std::vector<std::shared_ptr<TestCase>>
makeCreateTests(std::size_t count) {
    std::vector<std::shared_ptr<TestCase>> v;
    v.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        v.push_back(std::make_shared<TestCase>(TestCase::Generate(E, CommandType::CREATE)));
    }
    return v;
}

template <EntityType E>
static std::vector<std::shared_ptr<TestCase>>
makeInfoTests(const std::vector<std::shared_ptr<typename EntityTraits<E>::Type>>& src) {
    std::vector<std::shared_ptr<TestCase>> v;
    v.reserve(src.size());
    for (const auto& e : src) {
        v.push_back(std::make_shared<TestCase>(TestCase::Generate(E, CommandType::INFO, e)));
    }
    return v;
}

template <EntityType E>
static std::vector<std::shared_ptr<TestCase>>
makeUpdateTests(const std::vector<std::shared_ptr<typename EntityTraits<E>::Type>>& src) {
    std::vector<std::shared_ptr<TestCase>> v;
    v.reserve(src.size());
    for (const auto& e : src) {
        v.push_back(std::make_shared<TestCase>(TestCase::Generate(E, CommandType::UPDATE, e)));
    }
    return v;
}

template <EntityType E>
static std::vector<std::shared_ptr<TestCase>>
makeDeleteTests(const std::vector<std::shared_ptr<typename EntityTraits<E>::Type>>& src) {
    std::vector<std::shared_ptr<TestCase>> v;
    v.reserve(src.size());
    for (const auto& e : src) {
        v.push_back(std::make_shared<TestCase>(TestCase::Delete(E, e)));
    }
    return v;
}

// one LIST per-entity type
template <EntityType E>
static std::shared_ptr<TestCase> makeListTest() {
    return std::make_shared<TestCase>(TestCase::List(E));
}

// Inject IDs into ctx after CREATE
template <EntityType E>
static void harvestIdsIntoContext(
    cli::Context& ctx,
    const std::vector<std::shared_ptr<TestCase>>& results,
    std::string_view idPrefix,
    std::ostream& err
) {
    using T = EntityTraits<E>::Type;
    auto& bucket = EntityTraits<E>::vec(ctx);

    for (const auto& r : results) {
        if (!r) continue;
        if (!r->result.stderr_text.empty()) err << r->result.stderr_text << '\n';

        if (const auto id = IntegrationsTestRunner::extractId(r->result.stdout_text, idPrefix); id.has_value() && r->entity) {
            auto obj = std::static_pointer_cast<T>(r->entity);
            if constexpr (std::is_same_v<T, identities::User> || std::is_same_v<T, identities::Group>) {
                // Identity ids are immutable: the created spec is re-minted with its id.
                obj = T::detached(*id, *obj->state());
                r->entity = obj;
            } else {
                obj->id = *id;
            }
            bucket.push_back(obj);
        } else {
            std::cerr << "Warning: failed to extract ID from output for " << r->name << '\n' << r->result.stdout_text << '\n';
            r->assertion = AssertionResult::Fail("Seed: failed to extract ID from output for " + r->name);
        }
    }
}

// ---------- Runner

IntegrationsTestRunner::IntegrationsTestRunner(cli::Config&& cfg)
    : config_(cfg),
      ctx_(std::make_shared<cli::Context>()),
      usage_(std::make_shared<protocols::shell::UsageManager>()),
      router_(std::make_shared<cmd::Router>(ctx_)),
      interruptFlag(std::make_shared<std::atomic<bool>>(false)),
      threadPool_(std::make_shared<concurrency::TestThreadPool>(interruptFlag, std::thread::hardware_concurrency())) {
    cmd::Registry::init(usage_, ctx_);
    registerAllContainsAssertions();
}

// ----- pipeline

int IntegrationsTestRunner::operator()() {
    seed();
    assign();
    readStage();
    updateStage();
    validateAllTestObjects();
    runFUSETests();
    teardownStage();
    return printResults();
}

static std::vector<std::vector<std::shared_ptr<TestCase>>> split(const std::vector<std::shared_ptr<TestCase>>& tests, const std::size_t n) {
    std::vector<std::vector<std::shared_ptr<TestCase>>> result;
    if (n == 0) return result;
    result.resize(n);
    for (std::size_t i = 0; i < tests.size(); ++i) result[i % n].push_back(tests[i]);
    return result;
}

void IntegrationsTestRunner::seed() {
    const auto numThreads = std::max(1u, std::thread::hardware_concurrency() / 2);

    const struct SeedJob {
        EntityType type;
        std::vector<std::shared_ptr<TestCase>> tests;
    } jobs[] = {
        { EntityType::ADMIN_ROLE,  makeCreateTests<EntityType::ADMIN_ROLE>(config_.numAdminRoles) },
        { EntityType::VAULT_ROLE, makeCreateTests<EntityType::VAULT_ROLE>(config_.numVaultRoles) },
        { EntityType::USER,       makeCreateTests<EntityType::USER>(config_.numUsers) },
        { EntityType::GROUP,      makeCreateTests<EntityType::GROUP>(config_.numGroups) },
        { EntityType::VAULT,      makeCreateTests<EntityType::VAULT>(config_.numVaults) }
    };

    for (const auto& [type, tests] : jobs) {
        const auto splits = split(tests, numThreads);

        std::vector<std::pair<std::optional<std::future<concurrency::TestFuture>>, EntityType>> futures;

        for (const auto& splitVec : splits) {
            if (splitVec.empty()) continue;

            const auto task = std::make_shared<cli::Task>(router_, splitVec);
            futures.emplace_back(task->getFuture(), type);
            threadPool_->submit(task);
            std::this_thread::sleep_for(std::chrono::milliseconds(50)); // light stagger
        }

        // Recombine results across splits
        std::vector<std::shared_ptr<TestCase>> combined;

        for (auto& [fut, futType] : futures) {
            if (!fut.has_value()) continue;
            const auto res = fut->get();

            const auto* ptr = std::get_if<std::vector<std::shared_ptr<TestCase>>>(&res);
            if (!ptr) continue;

            combined.insert(combined.end(), ptr->begin(), ptr->end());
        }

        // Finish stage once per entity type
        switch (type) {
            case EntityType::USER:
                finish_seed<EntityType::USER>(combined);
                break;
            case EntityType::GROUP:
                finish_seed<EntityType::GROUP>(combined);
                break;
            case EntityType::ADMIN_ROLE:
                finish_seed<EntityType::ADMIN_ROLE>(combined);
                break;
            case EntityType::VAULT:
                finish_seed<EntityType::VAULT>(combined);
                break;
            case EntityType::VAULT_ROLE:
                finish_seed<EntityType::VAULT_ROLE>(combined);
                break;
            default:
                throw std::runtime_error("Unknown EntityType in seed()");
        }
    }
}

template <EntityType E>
void IntegrationsTestRunner::finish_seed(const std::vector<std::shared_ptr<TestCase>>& res) {
    harvestIdsIntoContext<E>(*ctx_, res, EntityTraits<E>::kIdPrefix, std::cerr);
    stages_.push_back(TestStage(std::string("Seed ") + std::string(EntityTraits<E>::kStage), res));
    validateStage(stages_.back());
}

void IntegrationsTestRunner::readStage() {
    std::vector<std::shared_ptr<TestCase>> tests;

    // INFO for each entity
    {
        auto& C = *ctx_;
        auto append = [&](auto&& vec) {
            tests.insert(tests.end(), vec.begin(), vec.end());
        };
        append(makeInfoTests<EntityType::USER>(C.users));
        append(makeInfoTests<EntityType::VAULT>(C.vaults));
        append(makeInfoTests<EntityType::GROUP>(C.groups));
        append(makeInfoTests<EntityType::ADMIN_ROLE>(C.adminRoles));
        append(makeInfoTests<EntityType::VAULT_ROLE>(C.vaultRoles));
    }

    // LIST per entity type
    tests.push_back(makeListTest<EntityType::USER>());
    tests.push_back(makeListTest<EntityType::VAULT>());
    tests.push_back(makeListTest<EntityType::GROUP>());
    tests.push_back(makeListTest<EntityType::ADMIN_ROLE>());
    tests.push_back(makeListTest<EntityType::VAULT_ROLE>());

    const auto res = router_->route(tests);
    stages_.push_back(TestStage{ "Read", res });
    validateStage(stages_.back());
}

void IntegrationsTestRunner::assign() {
    std::vector<std::shared_ptr<TestCase>> tests;

    for (const auto& user : ctx_->users)
        tests.push_back(std::make_shared<TestCase>(
                TestCase::Generate(EntityType::GROUP, EntityType::USER, ActionType::ADD, ctx_->pickRandomGroup(), user)));

    for (const auto& user : ctx_->users)
        tests.push_back(TestCase::Generate(EntityType::VAULT, EntityType::VAULT_ROLE, EntityType::USER, CommandType::ASSIGN,
                ctx_->pickRandomVault(), ctx_->randomVaultRole(), user));

    for (const auto& group : ctx_->groups)
        tests.push_back(TestCase::Generate(EntityType::VAULT, EntityType::VAULT_ROLE, EntityType::GROUP, CommandType::ASSIGN,
                ctx_->pickRandomVault(), ctx_->randomVaultRole(), group));

    const auto res = router_->route(tests);
    stages_.push_back(TestStage{ "Assign", res });
    validateStage(stages_.back());
}

void IntegrationsTestRunner::updateStage() {
    std::vector<std::shared_ptr<TestCase>> tests;

    const auto& C = *ctx_;
    auto append = [&](auto&& vec) {
        tests.insert(tests.end(), vec.begin(), vec.end());
    };
    append(makeUpdateTests<EntityType::USER>(C.users));
    append(makeUpdateTests<EntityType::VAULT>(C.vaults));
    append(makeUpdateTests<EntityType::GROUP>(C.groups));
    append(makeUpdateTests<EntityType::ADMIN_ROLE>(C.adminRoles));
    append(makeUpdateTests<EntityType::VAULT_ROLE>(C.vaultRoles));

    const auto res = router_->route(tests);
    stages_.push_back(TestStage{ "Update", res });
    validateStage(stages_.back());
}

void IntegrationsTestRunner::teardownStage() {
    std::vector<std::shared_ptr<TestCase>> tests;
    auto& C = *ctx_;

    // Order chosen to avoid fk/rbac headaches
    {
        auto append = [&](auto&& vec) {
            tests.insert(tests.end(), vec.begin(), vec.end());
        };
        append(makeDeleteTests<EntityType::VAULT>(C.vaults));
        append(makeDeleteTests<EntityType::USER>(C.users));
        append(makeDeleteTests<EntityType::GROUP>(C.groups));
        append(makeDeleteTests<EntityType::ADMIN_ROLE>(C.adminRoles));
        append(makeDeleteTests<EntityType::VAULT_ROLE>(C.vaultRoles));
    }

    const auto res = router_->route(tests);
    stages_.push_back(TestStage{ "Teardown", res });
    validateStage(stages_.back());
}

// ---------- Validation

void IntegrationsTestRunner::validateAllTestObjects() const {
    Validator<EntityType::USER,       User>::assert_all_exist(ctx_->users);
    Validator<EntityType::VAULT,      Vault>::assert_all_exist(ctx_->vaults);
    Validator<EntityType::GROUP,      Group>::assert_all_exist(ctx_->groups);
    Validator<EntityType::ADMIN_ROLE,  role::Admin>::assert_all_exist(ctx_->adminRoles);
    Validator<EntityType::VAULT_ROLE, role::Vault>::assert_all_exist(ctx_->vaultRoles);
}

}
