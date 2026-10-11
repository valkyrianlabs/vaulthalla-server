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
#include "seed/Stream.hpp"

#include "identities/User.hpp"
#include "identities/Group.hpp"
#include "vault/model/Vault.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"
#include "db/query/rbac/role/vault/Assignments.hpp"

#include <algorithm>
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

// Every test draws from h64(root, "<stage>:<path>", n), n counting the tests with that path in the stage, so a
// test's random choices don't move when unrelated tests are added or removed.
static void labelStreams(const std::string& stage, const std::vector<std::shared_ptr<TestCase>>& tests) {
    std::unordered_map<std::string, uint64_t> next;
    for (const auto& t : tests) {
        if (!t) continue;
        t->stream = stage + ":" + t->path;
        t->streamIndex = next[t->path]++;
    }
}

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
        auto tc = std::make_shared<TestCase>(TestCase::Generate(E, CommandType::INFO, e));
        // `info` must describe the entity that was asked for, not just print the right headings.
        if constexpr (std::is_same_v<typename EntityTraits<E>::Type, User> ||
                      std::is_same_v<typename EntityTraits<E>::Type, Group>)
            tc->must_contain.push_back(e->name());
        else
            tc->must_contain.push_back(e->name);
        v.push_back(std::move(tc));
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

// A delete test plus the state check that the entity is gone afterwards.
struct TeardownCase {
    std::shared_ptr<TestCase> test;
    std::function<AssertionResult()> gone;
};

template <EntityType E>
static void appendDeleteTests(std::vector<TeardownCase>& out,
                              const std::vector<std::shared_ptr<typename EntityTraits<E>::Type>>& src) {
    using T = EntityTraits<E>::Type;
    for (const auto& e : src) {
        out.push_back({std::make_shared<TestCase>(TestCase::Delete(E, e)),
                       [e] { return Validator<E, T>::assert_not_exists(e); }});
    }
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
            r->fail("Seed: failed to extract ID from output for " + r->name);
        }
    }
}

// ---------- Runner

IntegrationsTestRunner::IntegrationsTestRunner(RunOptions options)
    : options_(std::move(options)),
      config_(options_.config),
      ctx_(std::make_shared<cli::Context>()),
      usage_(std::make_shared<protocols::shell::UsageManager>()),
      router_(std::make_shared<cmd::Router>(ctx_)),
      interruptFlag(std::make_shared<std::atomic<bool>>(false)),
      threadPool_(std::make_shared<concurrency::TestThreadPool>(interruptFlag, options_.seedThreads)),
      startedAt_(std::chrono::system_clock::now()) {
    cmd::Registry::init(usage_, ctx_);
    registerAllContainsAssertions();
    if (options_.negativeControl == NegativeControl::Assertion) {
        // Applies to every `role info admin` output, so it also proves role expectations are matched at all.
        registerStdoutContains("role/info/admin",
                               std::string(kNegativeControlNeedle) + " (negative control: this text is never printed)");
    }
}

// ----- pipeline

void IntegrationsTestRunner::runStage(const std::string& name, const std::function<void()>& fn) {
    try {
        const seed::Scope scope("stage:" + name);
        fn();
    } catch (const std::exception& e) {
        auto tc = std::make_shared<TestCase>();
        tc->name = name + " stage";
        tc->path = "stage/" + name;
        tc->expect_exit = 0;
        tc->result.exit_code = -1;
        tc->result.stderr_text = e.what();
        tc->fail(std::string("stage aborted by a harness exception: ") + e.what());
        stages_.push_back(TestStage{name + " (aborted)", {tc}});
    }
}

int IntegrationsTestRunner::operator()() {
    if (options_.has("seed")) runStage("seed", [&] { seed(); });
    if (options_.has("assign")) runStage("assign", [&] { assign(); });
    if (options_.has("read")) runStage("read", [&] { readStage(); });
    if (options_.has("update")) runStage("update", [&] { updateStage(); });
    if (options_.has("validate")) runStage("validate", [&] { validateAllTestObjects(); });
    if (options_.has("fuse")) runStage("fuse", [&] { runFUSETests(); });
    if (options_.has("teardown")) runStage("teardown", [&] { teardownStage(); });

    const int status = printResults();
    writeReports(status);
    return status;
}

static std::vector<std::vector<std::shared_ptr<TestCase>>> split(const std::vector<std::shared_ptr<TestCase>>& tests, const std::size_t n) {
    std::vector<std::vector<std::shared_ptr<TestCase>>> result;
    if (n == 0) return result;
    result.resize(n);
    for (std::size_t i = 0; i < tests.size(); ++i) result[i % n].push_back(tests[i]);
    return result;
}

void IntegrationsTestRunner::seed() {
    const auto numThreads = std::max(1u, options_.seedThreads);

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
        switch (type) {
            case EntityType::USER: labelStreams("Seed Users", tests); break;
            case EntityType::GROUP: labelStreams("Seed Groups", tests); break;
            case EntityType::ADMIN_ROLE: labelStreams("Seed Admin Roles", tests); break;
            case EntityType::VAULT: labelStreams("Seed Vaults", tests); break;
            case EntityType::VAULT_ROLE: labelStreams("Seed Vault Roles", tests); break;
        }

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

        // Creation order, not thread order: what later stages pick from ctx doesn't depend on the core count.
        std::ranges::sort(combined, {}, [](const auto& t) { return t->streamIndex; });

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

    labelStreams("Read", tests);
    const auto res = router_->route(tests);
    stages_.push_back(TestStage{ "Read", res });
    validateStage(stages_.back());
}

void IntegrationsTestRunner::assign() {
    std::vector<std::shared_ptr<TestCase>> tests;
    // What each assign test must have changed, checked in the identity manager / DB once the command succeeded.
    std::vector<std::function<AssertionResult()>> effects;

    for (const auto& user : ctx_->users) {
        const auto group = ctx_->pickRandomGroup();
        tests.push_back(std::make_shared<TestCase>(
                TestCase::Generate(EntityType::GROUP, EntityType::USER, ActionType::ADD, group, user)));
        effects.emplace_back([group, user] {
            for (const auto& m : vh::identities::manager().members(group->id))
                if (m.user && m.user->id == user->id) return AssertionResult::Pass();
            return AssertionResult::Fail("user " + std::to_string(user->id) + " is not a member of group " +
                                         std::to_string(group->id) + " in the identity manager");
        });
    }

    const auto expectAssignment = [](const std::shared_ptr<Vault>& vault, const std::shared_ptr<role::Vault>& role,
                                     const std::string& subjectType, const uint32_t subjectId) {
        return [vault, role, subjectType, subjectId] {
            const auto held = db::query::rbac::role::vault::Assignments::get(vault->id, subjectType, subjectId);
            const auto who = subjectType + " " + std::to_string(subjectId);
            if (!held) return AssertionResult::Fail(who + " holds no role on vault " + std::to_string(vault->id) + " in the DB");
            if (held->id != role->id)
                return AssertionResult::Fail(who + " holds role " + std::to_string(held->id) + " on vault " +
                                             std::to_string(vault->id) + ", expected " + std::to_string(role->id));
            return AssertionResult::Pass();
        };
    };

    for (const auto& user : ctx_->users) {
        const auto vault = ctx_->pickRandomVault();
        const auto role = ctx_->randomVaultRole();
        tests.push_back(TestCase::Generate(EntityType::VAULT, EntityType::VAULT_ROLE, EntityType::USER, CommandType::ASSIGN,
                vault, role, user));
        effects.emplace_back(expectAssignment(vault, role, "user", user->id));
    }

    for (const auto& group : ctx_->groups) {
        const auto vault = ctx_->pickRandomVault();
        const auto role = ctx_->randomVaultRole();
        tests.push_back(TestCase::Generate(EntityType::VAULT, EntityType::VAULT_ROLE, EntityType::GROUP, CommandType::ASSIGN,
                vault, role, group));
        effects.emplace_back(expectAssignment(vault, role, "group", group->id));
    }

    labelStreams("Assign", tests);
    const auto res = router_->route(tests);
    stages_.push_back(TestStage{ "Assign", res });
    validateStage(stages_.back());

    for (std::size_t i = 0; i < tests.size(); ++i) {
        if (tests[i]->result.exit_code != 0) continue;  // the exit-code check already failed it
        try {
            if (const auto r = effects[i](); !r.ok) tests[i]->fail("Assign: " + r.message);
        } catch (const std::exception& e) {
            tests[i]->fail(std::string("Assign: state check threw: ") + e.what());
        }
    }
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

    labelStreams("Update", tests);
    const auto res = router_->route(tests);
    stages_.push_back(TestStage{ "Update", res });
    validateStage(stages_.back());
}

void IntegrationsTestRunner::teardownStage() {
    std::vector<TeardownCase> cases;
    auto& C = *ctx_;

    // Order chosen to avoid fk/rbac headaches
    appendDeleteTests<EntityType::VAULT>(cases, C.vaults);
    appendDeleteTests<EntityType::USER>(cases, C.users);
    appendDeleteTests<EntityType::GROUP>(cases, C.groups);
    appendDeleteTests<EntityType::ADMIN_ROLE>(cases, C.adminRoles);
    appendDeleteTests<EntityType::VAULT_ROLE>(cases, C.vaultRoles);

    std::vector<std::shared_ptr<TestCase>> tests;
    for (const auto& c : cases) tests.push_back(c.test);

    labelStreams("Teardown", tests);
    const auto res = router_->route(tests);
    stages_.push_back(TestStage{ "Teardown", res });
    validateStage(stages_.back());

    for (const auto& c : cases) {
        if (c.test->result.exit_code != 0) continue;
        try {
            if (const auto r = c.gone(); !r.ok) c.test->fail("Teardown: " + r.message);
        } catch (const std::exception& e) {
            c.test->fail(std::string("Teardown: state check threw: ") + e.what());
        }
    }
}

// ---------- Validation

void IntegrationsTestRunner::validateAllTestObjects() {
    std::vector<std::shared_ptr<TestCase>> tests;
    const auto check = [&](const std::string& name, const std::string& path, const std::function<AssertionResult()>& fn) {
        auto tc = std::make_shared<TestCase>();
        tc->name = name;
        tc->path = path;
        tc->command = "state check: " + name;
        const auto start = std::chrono::steady_clock::now();
        try {
            tc->assertion = fn();
            tc->result.exit_code = 0;
        } catch (const std::exception& e) {
            tc->result.exit_code = -1;
            tc->fail(std::string("state check threw: ") + e.what());
        }
        tc->duration_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
        tests.push_back(tc);
    };

    check("DB and identity manager hold every user as modelled", "validate/user",
          [&] { return Validator<EntityType::USER, User>::assert_all_exist(ctx_->users); });
    check("DB holds every vault as modelled", "validate/vault",
          [&] { return Validator<EntityType::VAULT, Vault>::assert_all_exist(ctx_->vaults); });
    check("DB and identity manager hold every group as modelled", "validate/group",
          [&] { return Validator<EntityType::GROUP, Group>::assert_all_exist(ctx_->groups); });
    check("DB holds every admin role as modelled", "validate/role/admin",
          [&] { return Validator<EntityType::ADMIN_ROLE, role::Admin>::assert_all_exist(ctx_->adminRoles); });
    check("DB holds every vault role as modelled", "validate/role/vault",
          [&] { return Validator<EntityType::VAULT_ROLE, role::Vault>::assert_all_exist(ctx_->vaultRoles); });

    if (options_.negativeControl == NegativeControl::Oracle) {
        // A user the harness never created: the state oracle must report it missing, so this test must fail.
        check("negative control (oracle): a user that was never created exists", "validate/negative_control", [] {
            vh::identities::UserState phantom;
            phantom.name = "vh_negative_control_phantom";
            const auto r = Validator<EntityType::USER, User>::assert_exists(User::detached(0xFFFFFFF0u, std::move(phantom)));
            if (r.ok) return r;
            return AssertionResult::Fail(std::string(kNegativeControlNeedle) + ": " + r.message);
        });
    }

    stages_.push_back(TestStage{"Validate", tests});
    validateStage(stages_.back());
}

}
