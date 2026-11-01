// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// #260: ws push for the change journal. A subscribed session gets one coalesced fs.changed per vault after changes
// commit; vaults the user can't follow are refused; losing access drops the subscription with a last event; a slow
// consumer holds at most one pending event per vault. Events are captured through the notifier's delivery seam (a
// test session has no socket); the default delivery holds them the same way while Session::queuedFrames() is at
// ChangeNotifier::kMaxQueuedFrames.

#include "db/Transactions.hpp"
#include "db/query/fs/ChangeLog.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/FsChanges.hpp"
#include "ops/Roles.hpp"
#include "ops/Users.hpp"
#include "ops/Vaults.hpp"
#include "protocols/http/Access.hpp"
#include "protocols/ws/ChangeNotifier.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/fs/Changes.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "sync/Controller.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace vh::test_fs_change_push {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using EnginePtr = std::shared_ptr<storage::Engine>;
using SessionPtr = std::shared_ptr<protocols::ws::Session>;
using protocols::ws::ChangeNotifier;

std::string cpTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "p" + std::to_string(n.fetch_add(1));
}

class FsChangePushDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static UserPtr superUser;
    inline static std::shared_ptr<sync::Controller> previousController;
    inline static std::filesystem::path root;

    std::shared_ptr<ChangeNotifier> notifier;
    std::map<std::string, std::vector<json>> delivered;  // by session uuid
    bool full = false;                                   // the consumer is not reading

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_fs_change_push] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        root = std::filesystem::temp_directory_path() / ("vh_fs_change_push_" + cpTag());
        paths::backingPath = root / "backing";
        paths::mountPath = root / "mount";
        std::filesystem::create_directories(paths::backingPath);
        std::filesystem::create_directories(paths::mountPath);

        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::seed_database();
        runtime::Deps::init();
        fs::Filesystem::init(runtime::Deps::get().storageManager);
        runtime::Deps::get().fsCache = std::make_shared<fs::cache::Registry>();
        runtime::Deps::get().storageManager->initStorageEngines();
        superUser = vh::identities::manager().userByName("admin");

        previousController = runtime::Deps::get().syncController;
        runtime::Deps::setSyncController(std::make_shared<sync::Controller>());
        protocols::http::access::clearCachesForTesting();
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        runtime::Deps::setSyncController(previousController);
        std::error_code ec;
        std::filesystem::remove_all(root, ec);
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        notifier = std::make_shared<ChangeNotifier>();
        notifier->setDeliveryForTesting([this](const SessionPtr& session, const json& event) {
            if (full) return false;
            delivered[session->uuid].push_back(event);
            return true;
        });
        // Whatever earlier tests left pending is numbered now, not inside this test's first tick.
        (void)db::query::fs::ChangeLog::sequence();
    }

    [[nodiscard]] EnginePtr vault() const {
        const auto v = ops::vaults::create(superUser, {.name = "cp_" + cpTag(), .type = vault::model::VaultType::Local});
        return runtime::Deps::get().storageManager->getEngine(v->id);
    }

    void write(const EnginePtr& engine, const std::string& path, const std::string& content) const {
        ASSERT_TRUE(fs::Filesystem::createFile({.path = path,
                                                .fuse_path = engine->vaultPathToFusePath(path),
                                                .buffer = std::vector<uint8_t>(content.begin(), content.end()),
                                                .engine = engine,
                                                .user = superUser,
                                                .overwrite = true}));
    }

    [[nodiscard]] static SessionPtr sessionAs(const UserPtr& user) {
        auto session = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        session->user = user;
        return session;
    }

    [[nodiscard]] UserPtr userWithVaultRole(const EnginePtr& engine, const std::string& role) const {
        const auto created = ops::users::create(superUser, {.name = "cp_user_" + cpTag(), .role = "unprivileged",
                                                            .password = std::string("Change-Push-Pass-123")});
        (void)ops::roles::assignVaultRole(superUser, {.target = {.vault_id = engine->vault->id,
                                                                 .subject = {.type = "user", .id = created.user->id}},
                                                      .role = role});
        return vh::identities::manager().user(created.user->id);
    }

    [[nodiscard]] std::vector<json> take(const SessionPtr& session) {
        auto out = std::move(delivered[session->uuid]);
        delivered.erase(session->uuid);
        return out;
    }

    [[nodiscard]] static json changed(const uint32_t vaultId, const uint64_t revision) {
        return {{"command", "fs.changed"}, {"data", {{"vault_id", vaultId}, {"revision", revision}}}};
    }
};

TEST_F(FsChangePushDbTest, SubscribedSessionsGetOneCoalescedEventPerVault) {
    const auto a = vault();
    const auto b = vault();
    const auto quiet = vault();
    const auto session = sessionAs(superUser);
    const auto other = sessionAs(superUser);  // follows nothing
    const auto res = notifier->subscribe(session, {a->vault->id, b->vault->id, quiet->vault->id});
    EXPECT_TRUE(res.refused.empty());
    EXPECT_EQ(res.vault_ids.size(), 3u);

    notifier->tick();
    EXPECT_TRUE(take(session).empty()) << "nothing changed since subscribing";

    for (int i = 0; i < 5; ++i) write(a, "/a" + std::to_string(i) + ".txt", "x");
    write(b, "/b.txt", "y");
    notifier->tick();

    // One event per changed vault, at the cursor fs.changes.list answers.
    const auto events = take(session);
    const auto atA = ops::fs_changes::list(superUser, {.vault_id = a->vault->id, .since = 0}).revision;
    const auto lastB = ops::fs_changes::list(superUser, {.vault_id = b->vault->id, .since = 0}).changes.back().revision;
    const auto lastA = ops::fs_changes::list(superUser, {.vault_id = a->vault->id, .since = 0}).changes.back().revision;
    EXPECT_GE(atA, lastA);
    EXPECT_EQ(events, (std::vector<json>{changed(a->vault->id, lastA), changed(b->vault->id, lastB)}));
    EXPECT_TRUE(take(other).empty());

    notifier->tick();
    EXPECT_TRUE(take(session).empty()) << "an event is sent once";

    // Unsubscribing one vault keeps the other.
    EXPECT_EQ(notifier->unsubscribe(session, std::vector<uint32_t>{a->vault->id}),
              (std::vector<uint32_t>{b->vault->id, quiet->vault->id}));
    write(a, "/later.txt", "z");
    notifier->tick();
    EXPECT_TRUE(take(session).empty());
    EXPECT_TRUE(notifier->unsubscribe(session, std::nullopt).empty());
    EXPECT_EQ(notifier->sessionCount(), 0u);
}

TEST_F(FsChangePushDbTest, VaultsTheUserCannotFollowAreRefused) {
    const auto engine = vault();
    const auto outsider = ops::users::create(superUser, {.name = "cp_out_" + cpTag(), .role = "unprivileged",
                                                         .password = std::string("Change-Push-Pass-123")});
    const auto session = sessionAs(vh::identities::manager().user(outsider.user->id));

    const auto res = notifier->subscribe(session, {engine->vault->id, 999999});
    EXPECT_TRUE(res.vault_ids.empty());
    ASSERT_EQ(res.refused.size(), 2u);
    EXPECT_EQ(res.refused[0].vault_id, engine->vault->id);
    EXPECT_EQ(res.refused[0].code, "denied");
    EXPECT_EQ(res.refused[1].code, "not_found");
    EXPECT_EQ(notifier->sessionCount(), 0u);

    // The ws handler answers the same, and refuses a session without a user.
    const auto answer = protocols::ws::handler::fs::Changes::subscribe({{"vault_ids", {engine->vault->id}}}, session);
    EXPECT_EQ(answer.at("vault_ids"), json::array());
    EXPECT_EQ(answer.at("refused")[0].at("code"), "denied");
    EXPECT_THROW((void)notifier->subscribe(sessionAs(nullptr), {engine->vault->id}), ops::Denied);
    EXPECT_THROW((void)protocols::ws::handler::fs::Changes::subscribe({{"vault_ids", "1"}}, session), ops::Invalid);
}

TEST_F(FsChangePushDbTest, LosingAccessDropsTheSubscription) {
    const auto engine = vault();
    const auto user = userWithVaultRole(engine, "power_user");
    const auto session = sessionAs(user);
    ASSERT_TRUE(notifier->subscribe(session, {engine->vault->id}).refused.empty());

    (void)ops::roles::unassignVaultRole(superUser, {.vault_id = engine->vault->id,
                                                    .subject = {.type = "user", .id = user->id}});
    notifier->tick();

    const auto events = take(session);
    ASSERT_EQ(events.size(), 1u);
    EXPECT_EQ(events[0].at("command"), "fs.changed");
    EXPECT_EQ(events[0].at("data").at("vault_id"), engine->vault->id);
    EXPECT_EQ(events[0].at("data").at("subscribed"), false);
    EXPECT_TRUE(notifier->subscriptions(*session).empty());
    EXPECT_EQ(notifier->sessionCount(), 0u);

    write(engine, "/after.txt", "x");
    notifier->tick();
    EXPECT_TRUE(take(session).empty());
}

TEST_F(FsChangePushDbTest, AnAuthorizationChangeIsPushedToo) {
    const auto engine = vault();
    const auto user = userWithVaultRole(engine, "power_user");
    const auto session = sessionAs(user);
    ASSERT_TRUE(notifier->subscribe(session, {engine->vault->id}).refused.empty());
    const auto cursor = ops::fs_changes::list(user, {.vault_id = engine->vault->id}).revision;

    ops::roles::PermissionEdit edit;
    edit.changes.emplace_back("vault.fs.files.preview", false);
    (void)ops::roles::addVaultRoleOverrides(superUser, {
        .target = {.vault_id = engine->vault->id, .subject = {.type = "user", .id = user->id}},
        .permissions = edit,
        .pattern = "/secret/**"});
    notifier->tick();

    // Still followed (List on the root stands); the event sends the client to a cursor that has expired.
    const auto events = take(session);
    ASSERT_EQ(events.size(), 1u);
    EXPECT_FALSE(events[0].at("data").contains("subscribed"));
    EXPECT_TRUE(ops::fs_changes::list(user, {.vault_id = engine->vault->id, .since = cursor}).expired);
}

TEST_F(FsChangePushDbTest, ASlowConsumerHoldsOneEventPerVault) {
    const auto a = vault();
    const auto b = vault();
    const auto session = sessionAs(superUser);
    ASSERT_TRUE(notifier->subscribe(session, {a->vault->id, b->vault->id}).refused.empty());

    full = true;
    for (int round = 0; round < 20; ++round) {
        write(a, "/a" + std::to_string(round) + ".txt", "x");
        write(b, "/b" + std::to_string(round) + ".txt", "y");
        notifier->tick();
    }
    EXPECT_TRUE(take(session).empty());

    full = false;
    notifier->flush();
    const auto events = take(session);
    ASSERT_EQ(events.size(), 2u) << "twenty rounds coalesce into one event per vault";
    const auto last = ops::fs_changes::list(superUser, {.vault_id = b->vault->id, .since = 0}).changes.back().revision;
    EXPECT_EQ(events[1].at("data").at("revision"), last);
}

// The default delivery: a closed session takes nothing and is forgotten.
TEST_F(FsChangePushDbTest, AClosedSessionIsForgotten) {
    const auto engine = vault();
    auto real = std::make_shared<ChangeNotifier>();
    const auto session = sessionAs(superUser);
    ASSERT_TRUE(real->subscribe(session, {engine->vault->id}).refused.empty());
    session->close();
    write(engine, "/x.txt", "x");
    real->tick();
    EXPECT_EQ(real->sessionCount(), 0u);
    EXPECT_EQ(session->queuedFrames(), 0u);
}

TEST_F(FsChangePushDbTest, ARequestNamesAtMostTheCap) {
    const auto session = sessionAs(superUser);
    auto ids = json::array();
    for (std::size_t i = 0; i <= ChangeNotifier::kMaxVaults; ++i) ids.push_back(i + 1);
    EXPECT_THROW((void)protocols::ws::handler::fs::Changes::subscribe({{"vault_ids", ids}}, session), ops::Invalid);
}

}
