// Vaults through both surfaces (Phase 2). Before: CLI `vault update` wrote the DB directly and left the live
// engine (which RBAC reads the owner from) stale; the web silently dropped description/quota on create and reset
// omitted fields on update; key changes needed Consume only on the CLI; owner changes needed only Edit; and sync
// settings were gated by two different permissions. Everything now goes through ops::vaults.

#include "../helpers/identities.hpp"
#include "config/Config.hpp"
#include "config/Registry.hpp"
#include "db/Transactions.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/sync/Policy.hpp"
#include "db/query/vault/APIKey.hpp"
#include "db/query/vault/Deletion.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/Filesystem.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/Roles.hpp"
#include "ops/Vaults.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/vault.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/vault/Vaults.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "sync/model/LocalPolicy.hpp"
#include "sync/model/Policy.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "UsageManager.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/Retention.hpp"
#include "vault/model/Deletion.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <set>
#include <shared_mutex>
#include <string>

namespace vh::test_ops_parity_vaults {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;

std::string vaultTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(n.fetch_add(1));
}

class VaultParityTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<protocols::shell::Router> router;
    inline static UserPtr superUser, alice, bob;

    static UserPtr createUser(const std::string& name, const std::string& roleName) {
        auto user = vh::test::identities::createUser(name, db::query::rbac::role::Admin::get(roleName), name + "@vaulthalla.test", "x", std::nullopt);
        return vh::identities::manager().user(user->id);
    }

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_ops_parity_vaults] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = std::filesystem::temp_directory_path() / ("vh_vault_parity_" + vaultTag());
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

        if (!runtime::Deps::get().shellUsageManager)
            runtime::Deps::get().shellUsageManager = std::make_shared<protocols::shell::UsageManager>();
        router = std::make_shared<protocols::shell::Router>();
        protocols::shell::commands::vault::registerCommands(router);

        superUser = createUser("vp_super_" + vaultTag(), "super_admin");
        alice = createUser("vp_alice_" + vaultTag(), "unprivileged");
        bob = createUser("vp_bob_" + vaultTag(), "unprivileged");
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    }

    static std::pair<int, std::string> cli(const std::string& line, const UserPtr& user) {
        try {
            const auto res = router->executeLine(line, user, nullptr);
            return {res.exit_code, res.stdout_text + res.stderr_text};
        } catch (const std::exception& e) {
            return {1, e.what()};
        }
    }

    static std::shared_ptr<protocols::ws::Session> ws(const UserPtr& user) {
        auto s = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        s->user = user;
        return s;
    }

    static bool wsOk(const std::function<void()>& fn) {
        try {
            fn();
            return true;
        } catch (const std::exception&) {
            return false;
        }
    }

    static json vaultFacts(const unsigned int id) {
        const auto v = db::query::vault::Vault::getVault(id);
        if (!v) return json{{"exists", false}};
        return json{{"exists", true}, {"description", v->description}, {"quota", v->quota}, {"owner", v->owner_id}};
    }

    static unsigned int seedKey(const UserPtr& owner) {
        auto key = std::make_shared<vault::model::APIKey>(owner->id, "vp_key_" + vaultTag(), vault::model::S3Provider::AWS,
                                                          "AKIATESTACCESSKEY000", "secret-value-00000000000000000000000",
                                                          "us-east-1", "https://s3.example.com");
        return runtime::Deps::get().apiKeyManager->addAPIKey(key);
    }
};

TEST_F(VaultParityTest, CreateKeepsTheSameFieldsOnBothSurfaces) {
    const auto cliName = "vp_cli_" + vaultTag(), wsName = "vp_ws_" + vaultTag();
    const auto [code, out] = cli("vault create " + cliName + " --local --desc notes --quota 1G", superUser);
    ASSERT_EQ(code, 0) << out;
    const auto added = protocols::ws::handler::Vaults::add(
        json{{"name", wsName}, {"type", "local"}, {"description", "notes"}, {"quota", 1024ull * 1024 * 1024}}, ws(superUser));

    const auto cliVault = db::query::vault::Vault::getVault(cliName, superUser->id);
    ASSERT_TRUE(cliVault);
    auto a = vaultFacts(cliVault->id), b = vaultFacts(added.at("vault").at("id").get<unsigned int>());
    EXPECT_EQ(a, b) << "the web used to drop description and quota on create";
    EXPECT_EQ(a.at("description"), "notes");
}

TEST_F(VaultParityTest, UpdatesGoThroughTheEngineAndArePatches) {
    const auto name = "vp_upd_" + vaultTag();
    ASSERT_EQ(cli("vault create " + name + " --local --desc before", superUser).first, 0);
    const auto id = db::query::vault::Vault::getVault(name, superUser->id)->id;

    // CLI update: the live engine must see it (it used to keep the old vault until a restart).
    const auto [code, out] = cli("vault update " + std::to_string(id) + " --desc after --interval 10m", superUser);
    ASSERT_EQ(code, 0) << out;
    const auto engine = runtime::Deps::get().storageManager->getEngine(id);
    ASSERT_TRUE(engine);
    EXPECT_EQ(engine->vault->description, "after");
    {
        std::shared_lock lock(engine->mutex);
        EXPECT_EQ(engine->sync->interval, std::chrono::minutes(10));
    }

    // ws update is a patch: a payload with only some fields leaves the rest alone (it used to reset them).
    (void)protocols::ws::handler::Vaults::update(json{{"id", id}, {"description", "web"}}, ws(superUser));
    const auto v = db::query::vault::Vault::getVault(id);
    EXPECT_EQ(v->description, "web");
    EXPECT_EQ(v->name, name);
    EXPECT_EQ(runtime::Deps::get().storageManager->getEngine(id)->vault->description, "web");
}

TEST_F(VaultParityTest, OwnerReassignmentNeedsCreateForTheNewOwner) {
    // A vault editor who may not create vaults for bob cannot hand him one, on either surface.
    const auto editorRole = "vp_editor_" + vaultTag();
    (void)ops::roles::createAdminRole(superUser, {.name = editorRole, .permissions = {.changes = {
        {"admin.vaults.user.view", true}, {"admin.vaults.user.edit", true}}}}, "test");
    const auto editor = createUser("vp_editor_user_" + vaultTag(), editorRole);

    const auto name = "vp_owner_" + vaultTag();
    const auto vault = ops::vaults::create(superUser, {.name = name, .type = vault::model::VaultType::Local, .owner_id = alice->id});

    EXPECT_NE(cli("vault update " + std::to_string(vault->id) + " --owner " + bob->name(), editor).first, 0);
    EXPECT_FALSE(wsOk([&] {
        (void)protocols::ws::handler::Vaults::update(json{{"id", vault->id}, {"owner_id", bob->id}}, ws(editor));
    }));
    EXPECT_EQ(db::query::vault::Vault::getVault(vault->id)->owner_id, alice->id);

    // Edit alone still works for ordinary fields.
    EXPECT_EQ(cli("vault update " + std::to_string(vault->id) + " --desc edited", editor).first, 0);

    // With the right to create for bob, the reassignment lands, and the engine (RBAC's source) follows.
    ASSERT_EQ(cli("vault update " + std::to_string(vault->id) + " --owner " + bob->name(), superUser).first, 0);
    EXPECT_EQ(runtime::Deps::get().storageManager->getEngine(vault->id)->vault->owner_id, bob->id);
}

TEST_F(VaultParityTest, ChangingTheApiKeyNeedsConsumeOnBothSurfaces) {
    const auto keyA = seedKey(superUser), keyB = seedKey(superUser);
    const auto vault = ops::vaults::create(superUser, {
        .name = "vp_s3_" + vaultTag(), .type = vault::model::VaultType::S3, .owner_id = superUser->id,
        .s3 = ops::vaults::S3Spec{.api_key_id = keyA, .bucket = "vp-bucket"}});

    const auto editorRole = "vp_s3editor_" + vaultTag();
    (void)ops::roles::createAdminRole(superUser, {.name = editorRole, .permissions = {.changes = {
        {"admin.vaults.admin.view", true}, {"admin.vaults.admin.edit", true}}}}, "test");
    const auto editor = createUser("vp_s3editor_user_" + vaultTag(), editorRole);

    EXPECT_NE(cli("vault update " + std::to_string(vault->id) + " --api-key " + std::to_string(keyB), editor).first, 0);
    EXPECT_FALSE(wsOk([&] {
        (void)protocols::ws::handler::Vaults::update(json{{"id", vault->id}, {"api_key_id", keyB}}, ws(editor));
    }));
    EXPECT_EQ(std::static_pointer_cast<vault::model::S3Vault>(db::query::vault::Vault::getVault(vault->id))->api_key_id, keyA);

    // Unchanged key: no Consume needed.
    EXPECT_TRUE(wsOk([&] {
        (void)protocols::ws::handler::Vaults::update(json{{"id", vault->id}, {"api_key_id", keyA}, {"description", "x"}}, ws(editor));
    }));
}

// vaults.s3.* (#164): an S3 vault created without a strategy or conflict policy gets the operator's defaults, on
// both surfaces; an explicit setting still wins. (These keys used to sit unread under s3_gateway.)
TEST_F(VaultParityTest, NewS3VaultsTakeTheConfiguredRemoteDefaults) {
    const auto previous = config::Registry::get();
    struct Restore {
        const config::Config& cfg;
        ~Restore() { config::Registry::set(cfg); }
    } restore{previous};
    auto cfg = previous;
    cfg.vaults.s3.default_remote_sync_strategy = "mirror";
    cfg.vaults.s3.default_remote_conflict_policy = "keep_newest";
    config::Registry::set(cfg);

    const auto key = seedKey(superUser);
    const auto cliName = "vp_def_cli_" + vaultTag(), wsName = "vp_def_ws_" + vaultTag();
    const auto [code, out] = cli("vault create " + cliName + " --s3 --api-key " + std::to_string(key) + " --bucket vp-def",
                                 superUser);
    ASSERT_EQ(code, 0) << out;
    const auto added = protocols::ws::handler::Vaults::add(
        json{{"name", wsName}, {"type", "s3"}, {"api_key_id", key}, {"bucket", "vp-def-ws"}}, ws(superUser));

    for (const auto id : {db::query::vault::Vault::getVault(cliName, superUser->id)->id,
                          added.at("vault").at("id").get<unsigned int>()}) {
        const auto policy = std::dynamic_pointer_cast<sync::model::RemotePolicy>(db::query::sync::Policy::getSync(id));
        ASSERT_TRUE(policy) << "vault " << id;
        EXPECT_EQ(policy->strategy, sync::model::RemotePolicy::Strategy::Mirror) << "vault " << id;
        EXPECT_EQ(policy->conflict_policy, sync::model::RemotePolicy::ConflictPolicy::KeepNewest) << "vault " << id;
    }

    // Explicit settings win over the defaults.
    const auto explicitName = "vp_def_explicit_" + vaultTag();
    ASSERT_EQ(cli("vault create " + explicitName + " --s3 --api-key " + std::to_string(key) +
                  " --bucket vp-def-explicit --sync-strategy sync --on-sync-conflict keep_remote", superUser).first, 0);
    const auto explicitPolicy = std::dynamic_pointer_cast<sync::model::RemotePolicy>(
        db::query::sync::Policy::getSync(db::query::vault::Vault::getVault(explicitName, superUser->id)->id));
    ASSERT_TRUE(explicitPolicy);
    EXPECT_EQ(explicitPolicy->strategy, sync::model::RemotePolicy::Strategy::Sync);
    EXPECT_EQ(explicitPolicy->conflict_policy, sync::model::RemotePolicy::ConflictPolicy::KeepRemote);
}

TEST_F(VaultParityTest, SyncSettingsUseOnePermissionOnBothSurfaces) {
    const auto vault = ops::vaults::create(superUser, {.name = "vp_sync_" + vaultTag(), .type = vault::model::VaultType::Local,
                                                       .owner_id = alice->id});
    const auto cliOk = cli("vault sync update " + std::to_string(vault->id) + " --interval 20m", alice).first == 0;
    const auto wsOkay = wsOk([&] {
        (void)protocols::ws::handler::Vaults::update(json{{"id", vault->id}, {"sync", {{"interval", 1200}}}}, ws(alice));
    });
    EXPECT_EQ(cliOk, wsOkay) << "CLI and web disagree on who may change sync settings";

    // Settings that only exist for S3 are refused for local vaults instead of being dropped.
    EXPECT_NE(cli("vault sync update " + std::to_string(vault->id) + " --sync-strategy mirror", superUser).first, 0);
}

TEST_F(VaultParityTest, DeleteAndListAgree) {
    const auto a = ops::vaults::create(superUser, {.name = "vp_del_a_" + vaultTag(), .type = vault::model::VaultType::Local});
    const auto b = ops::vaults::create(superUser, {.name = "vp_del_b_" + vaultTag(), .type = vault::model::VaultType::Local});
    EXPECT_NE(cli("vault delete " + std::to_string(a->id), bob).first, 0);
    EXPECT_FALSE(wsOk([&] { (void)protocols::ws::handler::Vaults::remove(json{{"id", b->id}}, ws(bob)); }));

    ASSERT_EQ(cli("vault delete " + std::to_string(a->id), superUser).first, 0);
    ASSERT_TRUE(wsOk([&] { (void)protocols::ws::handler::Vaults::remove(json{{"id", b->id}}, ws(superUser)); }));
    EXPECT_FALSE(vaultFacts(a->id).at("exists"));
    EXPECT_FALSE(vaultFacts(b->id).at("exists"));
    EXPECT_FALSE(wsOk([&] { (void)protocols::ws::handler::Vaults::remove(json{{"id", b->id}}, ws(superUser)); }));

    const auto listed = protocols::ws::handler::Vaults::list(ws(bob)).at("vaults");
    for (const auto& v : listed) EXPECT_EQ(v.at("owner_id").get<unsigned int>(), bob->id);
}

// Safe deletion (#162): delete, delete now, the deleted list and restore agree on both surfaces, and need vault
// Remove (the owner the deletion recorded decides the scope).
TEST_F(VaultParityTest, DeletionLifecycleAgreesOnBothSurfaces) {
    const auto viaCli = ops::vaults::create(superUser, {.name = "vp_rm_cli_" + vaultTag(), .type = vault::model::VaultType::Local});
    const auto viaWs = ops::vaults::create(superUser, {.name = "vp_rm_ws_" + vaultTag(), .type = vault::model::VaultType::Local});
    const auto cliId = std::to_string(viaCli->id);

    // Without a terminal a delete is the safe default: scheduled, restorable; it says how to undo it.
    const auto [code, out] = cli("vault delete " + cliId, superUser);
    ASSERT_EQ(code, 0) << out;
    EXPECT_NE(out.find("vh vault restore " + cliId), std::string::npos) << out;
    ASSERT_TRUE(wsOk([&] { (void)protocols::ws::handler::Vaults::remove(json{{"id", viaWs->id}}, ws(superUser)); }));
    EXPECT_FALSE(vaultFacts(viaCli->id).at("exists"));
    EXPECT_FALSE(vaultFacts(viaWs->id).at("exists"));

    // Both surfaces list both deletions for the super admin, neither for bob.
    const auto listedIds = [](const json& rows) {
        std::set<unsigned int> ids;
        for (const auto& r : rows) ids.insert(r.at("vault_id").get<unsigned int>());
        return ids;
    };
    const auto [listCode, listOut] = cli("vault deleted --json", superUser);
    ASSERT_EQ(listCode, 0) << listOut;
    const auto cliIds = listedIds(json::parse(listOut));
    const auto wsIds = listedIds(protocols::ws::handler::Vaults::listDeleted(ws(superUser)).at("deleted"));
    EXPECT_EQ(cliIds, wsIds);
    EXPECT_TRUE(cliIds.contains(viaCli->id) && cliIds.contains(viaWs->id));
    EXPECT_TRUE(protocols::ws::handler::Vaults::listDeleted(ws(bob)).at("deleted").empty());
    const auto [bobList, bobOut] = cli("vault deleted --json", bob);
    ASSERT_EQ(bobList, 0) << bobOut;
    EXPECT_TRUE(json::parse(bobOut).empty());

    // Restore and delete now: refused for bob on both surfaces, allowed for the super admin.
    EXPECT_NE(cli("vault restore " + cliId, bob).first, 0);
    EXPECT_FALSE(wsOk([&] { (void)protocols::ws::handler::Vaults::restore(json{{"id", viaWs->id}}, ws(bob)); }));
    EXPECT_NE(cli("vault delete " + cliId + " --now --yes", bob).first, 0);
    EXPECT_FALSE(wsOk([&] {
        (void)protocols::ws::handler::Vaults::remove(json{{"id", viaWs->id}, {"now", true}, {"confirm_now", true}}, ws(bob));
    }));

    ASSERT_EQ(cli("vault restore " + cliId, superUser).first, 0);
    ASSERT_TRUE(wsOk([&] { (void)protocols::ws::handler::Vaults::restore(json{{"id", viaWs->id}}, ws(superUser)); }));
    EXPECT_TRUE(vaultFacts(viaCli->id).at("exists"));
    EXPECT_TRUE(vaultFacts(viaWs->id).at("exists"));

    // Delete now needs a confirmation on both surfaces; without one nothing changes.
    EXPECT_NE(cli("vault delete " + cliId + " --now", superUser).first, 0);
    EXPECT_FALSE(wsOk([&] { (void)protocols::ws::handler::Vaults::remove(json{{"id", viaWs->id}, {"now", true}}, ws(superUser)); }));
    EXPECT_TRUE(vaultFacts(viaCli->id).at("exists"));
    EXPECT_TRUE(vaultFacts(viaWs->id).at("exists"));
    ASSERT_EQ(cli("vault delete " + cliId + " --now --yes", superUser).first, 0);
    ASSERT_TRUE(wsOk([&] {
        (void)protocols::ws::handler::Vaults::remove(json{{"id", viaWs->id}, {"now", true}, {"confirm_now", true}}, ws(superUser));
    }));
    for (const auto id : {viaCli->id, viaWs->id}) {
        const auto d = db::query::vault::Deletion::get(id);
        ASSERT_TRUE(d);
        EXPECT_EQ(d->purge_after, d->deleted_at) << "delete now purges on the next pass";
    }

    // The removal plan the web dialog reads: Remove permission, same windows as the op uses.
    const auto planned = ops::vaults::create(superUser, {.name = "vp_rm_plan_" + vaultTag(), .type = vault::model::VaultType::Local});
    const auto plan = protocols::ws::handler::Vaults::removalPlan(json{{"id", planned->id}}, ws(superUser)).at("plan");
    EXPECT_EQ(plan.at("retention_window_seconds").get<int64_t>(),
              vault::retention::windowsFor(vault::model::VaultType::Local).retention_window.count());
    EXPECT_FALSE(plan.at("key_exported").get<bool>());
    EXPECT_FALSE(wsOk([&] { (void)protocols::ws::handler::Vaults::removalPlan(json{{"id", planned->id}}, ws(bob)); }));
}

// The waiver flow without a real bucket: the CLI asks (or takes the accept flag) and repeats the op accepted.
TEST(VaultWaiverFlow, CliRetriesAcceptedOnlyWhenAccepted) {
    protocols::shell::CommandCall call;
    int calls = 0;
    const auto op = [&](const bool accept) -> ops::vaults::VaultPtr {
        ++calls;
        if (!accept) throw ops::NeedsConfirmation("encryption_waiver", "waiver text");
        auto v = std::make_shared<vault::model::Vault>();
        v->name = "accepted";
        return v;
    };
    const auto fmt = [](const ops::vaults::VaultPtr& v) { return v->name; };

    // No terminal and no flag: refused with the waiver text, nothing retried.
    auto res = protocols::shell::commands::vault::runVaultChange(call, "vault create", op, fmt);
    EXPECT_NE(res.exit_code, 0);
    EXPECT_NE(res.stderr_text.find("waiver text"), std::string::npos);
    EXPECT_EQ(calls, 1);

    // The documented accept flag (it used to be checked under a misspelled key).
    call.options.push_back({"accept-decryption-waiver", std::nullopt});
    calls = 0;
    res = protocols::shell::commands::vault::runVaultChange(call, "vault create", op, fmt);
    EXPECT_EQ(res.exit_code, 0) << res.stderr_text;
    EXPECT_EQ(res.stdout_text, "accepted");
    EXPECT_EQ(calls, 1);
}

}
