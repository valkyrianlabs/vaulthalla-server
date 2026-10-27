// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// The upstream control plane (#237, #96) through both surfaces: `vh upstream …` / `vh vault create --bucket-mode …`
// (shell::Router::executeLine) and the ws upstream.* / storage.vault.add handlers, against the test DB and an
// in-memory provider account. Verdicts are compared with the oracle from the role's admin.upstream bits and the key's
// keys.api bits, and outcomes by database and provider state, never by text.

#include "../helpers/sync_conflict_harness.hpp"
#include "../helpers/upstream_admin_fakes.hpp"

#include "db/query/upstream/Audit.hpp"
#include "db/query/upstream/Bucket.hpp"
#include "db/query/vault/Vault.hpp"
#include "ops/Upstream.hpp"
#include "ops/UpstreamJson.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/all.hpp"
#include "protocols/shell/commands/vault.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/Upstream.hpp"
#include "protocols/ws/handler/vault/Vaults.hpp"
#include "rbac/permission/admin/Upstream.hpp"
#include "rbac/permission/admin/keys/API.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "storage/upstream/Provisioner.hpp"
#include "UsageManager.hpp"

#include <nlohmann/json.hpp>

namespace vh::test_ops_parity_upstream {

using namespace test_support::sync_conflicts;
using test_support::upstream_admin::FakeAdmin;
using test_support::upstream_admin::FakeCloud;
using test_support::upstream_admin::kAccount;
namespace padmin = storage::s3::provider::admin;
namespace up = ops::upstream;
using json = nlohmann::json;
using WsUp = protocols::ws::handler::Upstream;

class UpstreamParityTest : public Harness {
protected:
    inline static std::shared_ptr<protocols::shell::Router> router;
    std::shared_ptr<FakeCloud> cloud;

    static void SetUpTestSuite() {
        Harness::SetUpTestSuite();
        if (skipTests) return;
        if (!runtime::Deps::get().shellUsageManager)
            runtime::Deps::get().shellUsageManager = std::make_shared<protocols::shell::UsageManager>();
        router = std::make_shared<protocols::shell::Router>();
        protocols::shell::commands::registerUpstreamCommands(router);
        protocols::shell::commands::vault::registerCommands(router);
    }

    void SetUp() override {
        Harness::SetUp();
        if (skipTests) return;
        cloud = std::make_shared<FakeCloud>();
        padmin::setFactoryForTesting(padmin::Factory{
            .admin = [c = cloud](const std::shared_ptr<vault::model::APIKey>&) -> std::unique_ptr<padmin::AdminClient> {
                return std::make_unique<FakeAdmin>(c);
            },
            .events = nullptr});
        storage::upstream::provision::setObjectHeadForTesting(
            [c = cloud](const std::shared_ptr<vault::model::APIKey>&, const std::string& bucket, const std::string& key)
                -> std::optional<std::unordered_map<std::string, std::string>> {
                std::scoped_lock lock(c->mutex);
                if (!c->buckets.contains(bucket) || !c->buckets.at(bucket).objects.contains(key)) return std::nullopt;
                return std::unordered_map<std::string, std::string>{{"Content-Length", "1"}};
            });
        storage::upstream::guard::reload();
    }

    void TearDown() override {
        padmin::setFactoryForTesting(std::nullopt);
        storage::upstream::provision::setObjectHeadForTesting({});
    }

    static int cli(const std::string& line, const UserPtr& user) {
        try {
            return router->executeLine(line, user, nullptr).exit_code;
        } catch (const std::exception&) {
            return 1;
        }
    }

    static std::shared_ptr<protocols::ws::Session> ws(const UserPtr& user) {
        auto s = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        s->user = user;
        return s;
    }

    // ws verdict: true = the op ran; false = refused (any ops::Error, NeedsConfirmation included).
    template <class Fn>
    static bool wsOk(Fn&& fn) {
        try {
            fn();
            return true;
        } catch (const ops::Error&) {
            return false;
        }
    }

    static unsigned awsKey() {
        auto key = std::make_shared<vault::model::APIKey>(superUser->id, "upp_key_" + tag(), vault::model::S3Provider::AWS,
                                                          "AKIATESTACCESSKEY000", "secret-value-0000000000000000000000000",
                                                          "us-east-2", "https://s3.us-east-2.amazonaws.com");
        const auto id = runtime::Deps::get().apiKeyManager->addAPIKey(key);
        (void)up::enableAdmin(superUser, id, {});
        return id;
    }

    void seedBucket(const std::string& name, std::map<std::string, uint64_t> objects = {}) {
        std::scoped_lock lock(cloud->mutex);
        cloud->buckets[name].objects = std::move(objects);
    }

    bool cloudHas(const std::string& name) {
        std::scoped_lock lock(cloud->mutex);
        return cloud->buckets.contains(name);
    }

    size_t objectsIn(const std::string& name) {
        std::scoped_lock lock(cloud->mutex);
        return cloud->buckets.at(name).objects.size();
    }

    std::vector<padmin::LifecycleRule> lifecycleOf(const std::string& name) {
        std::scoped_lock lock(cloud->mutex);
        return cloud->buckets.at(name).lifecycle;
    }

    static std::optional<storage::upstream::model::Bucket> rowOf(const std::string& name) {
        return db::query::upstream::Bucket::getByIdentity("aws-s3", kAccount, name);
    }

    static std::string bucketName() { return "vh-par-" + tag(); }
};

// Every read and lock operation, for every seeded admin role: the CLI and the ws handler agree with each other and
// with the oracle from the role's admin.upstream bits and the key's keys.api permission.
TEST_F(UpstreamParityTest, EverySeededRoleGetsTheSameVerdictOnBothSurfaces) {
    using KeyPerm = rbac::permission::admin::keys::APIPermissions;
    const auto keyId = awsKey();
    const auto k = std::to_string(keyId);
    const auto name = bucketName();
    seedBucket(name, {{"a.txt", 3}});

    for (const auto* role : {"unprivileged", "auditor", "support", "identity_admin", "security_admin", "platform_operator",
                             "vault_admin", "admin", "key_custodian", "super_admin"}) {
        const auto user = std::string(role) == "super_admin" ? superUser : createUser(std::string("upp_") + role, role);
        const auto bits = user->upstreamPerms();
        const auto key = [&](const KeyPerm p) {
            return rbac::resolver::Admin::has<KeyPerm>({.user = user, .permission = p, .api_key_id = keyId});
        };
        const auto session = ws(user);
        const auto check = [&](const std::string& what, const bool oracle, const std::string& line, auto&& wsCall) {
            EXPECT_EQ(cli(line, user) == 0, oracle) << role << " cli " << what;
            EXPECT_EQ(wsOk(wsCall), oracle) << role << " ws " << what;
        };

        const bool view = bits.canView() && key(KeyPerm::View);
        check("buckets", view, "upstream buckets " + k,
              [&] { (void)WsUp::bucketList(json{{"api_key_id", keyId}}, session); });
        check("inspect", view, "upstream inspect " + k + " " + name,
              [&] { (void)WsUp::bucketInspect(json{{"api_key_id", keyId}, {"bucket", name}}, session); });
        check("admin status", view, "upstream admin status " + k,
              [&] { (void)WsUp::adminStatus(json{{"api_key_id", keyId}}, session); });
        check("audit", bits.canView(), "upstream audit", [&] { (void)WsUp::auditList(json::object(), session); });
        check("adopt-check", bits.canProvision() && key(KeyPerm::Consume), "upstream adopt-check " + k + " " + name,
              [&] { (void)WsUp::bucketAdoptPreflight(json{{"api_key_id", keyId}, {"bucket", name}}, session); });
        check("cleanup preflight", bits.canDestroy() && key(KeyPerm::Consume),
              "upstream cleanup " + k + " " + name + " --preflight",
              [&] { (void)WsUp::bucketCleanupPreflight(json{{"api_key_id", keyId}, {"bucket", name}}, session); });

        // Locks: the CLI's protect is undone (by the super admin) before the ws one runs, so both start unlocked.
        const bool protect = bits.canProtect() && key(KeyPerm::View);
        EXPECT_EQ(cli("upstream protect " + k + " " + name + " --reason parity", user) == 0, protect) << role;
        EXPECT_EQ(rowOf(name) && rowOf(name)->is_protected, protect) << role << " cli lock state";
        if (protect) {
            const bool unprotect = bits.canUnprotect() && key(KeyPerm::View);
            EXPECT_EQ(cli("upstream unprotect " + k + " " + name + " --yes", user) == 0, unprotect) << role;
            (void)up::unprotect(superUser, keyId, name, true);
        }
        EXPECT_EQ(wsOk([&] { (void)WsUp::bucketProtect(json{{"api_key_id", keyId}, {"bucket", name}, {"reason", "parity"}},
                                                      session); }), protect) << role;
        EXPECT_EQ(rowOf(name) && rowOf(name)->is_protected, protect) << role << " ws lock state";
        if (protect) {
            const bool unprotect = bits.canUnprotect() && key(KeyPerm::View);
            EXPECT_EQ(wsOk([&] { (void)WsUp::bucketUnprotect(json{{"api_key_id", keyId}, {"bucket", name}, {"confirm", true}},
                                                            session); }), unprotect) << role;
            (void)up::unprotect(superUser, keyId, name, true);
        }
    }
}

TEST_F(UpstreamParityTest, LocksNeedTheSameConfirmationAndLeaveTheSameStateAndAudit) {
    const auto keyId = awsKey();
    const auto k = std::to_string(keyId);
    const auto viaCli = bucketName(), viaWs = bucketName();
    seedBucket(viaCli);
    seedBucket(viaWs);
    const auto session = ws(superUser);

    ASSERT_EQ(cli("upstream protect " + k + " " + viaCli + " --reason \"keep out\"", superUser), 0);
    (void)WsUp::bucketProtect(json{{"api_key_id", keyId}, {"bucket", viaWs}, {"reason", "keep out"}}, session);
    for (const auto& name : {viaCli, viaWs}) {
        const auto row = rowOf(name);
        ASSERT_TRUE(row) << name;
        EXPECT_TRUE(row->is_protected);
        EXPECT_EQ(row->protection_reason.value_or(""), "keep out");
        EXPECT_EQ(row->protected_by_name.value_or(""), superUser->name());
    }

    // Unlocking asks first on both surfaces (no terminal and no --yes: refused; ws: NeedsConfirmation).
    EXPECT_NE(cli("upstream unprotect " + k + " " + viaCli, superUser), 0);
    try {
        (void)WsUp::bucketUnprotect(json{{"api_key_id", keyId}, {"bucket", viaWs}}, session);
        ADD_FAILURE() << "ws unprotected without confirmation";
    } catch (const ops::NeedsConfirmation& e) {
        EXPECT_EQ(e.code, up::UNPROTECT_CONFIRM);
    }
    EXPECT_TRUE(rowOf(viaCli)->is_protected);
    EXPECT_TRUE(rowOf(viaWs)->is_protected);

    EXPECT_EQ(cli("upstream unprotect " + k + " " + viaCli + " --yes", superUser), 0);
    (void)WsUp::bucketUnprotect(json{{"api_key_id", keyId}, {"bucket", viaWs}, {"confirm", true}}, session);
    EXPECT_FALSE(rowOf(viaCli)->is_protected);
    EXPECT_FALSE(rowOf(viaWs)->is_protected);

    // The same audit trail: protect + unprotect for each bucket.
    for (const auto& name : {viaCli, viaWs}) {
        std::multiset<std::string> actions;
        for (const auto& e : up::audit(superUser, {.bucket = name, .limit = 50})) actions.insert(e.action);
        EXPECT_EQ(actions.count("protect"), 1u) << name;
        EXPECT_EQ(actions.count("unprotect"), 1u) << name;
    }
}

TEST_F(UpstreamParityTest, VaultCreationProvisionsTheSameManagedBucketOnBothSurfaces) {
    const auto keyId = awsKey();
    const auto k = std::to_string(keyId);
    const auto cliVault = "upp_cli_" + tag(), wsVault = "upp_ws_" + tag();
    const auto cliBucket = bucketName(), wsBucket = bucketName();

    ASSERT_EQ(cli("vault create " + cliVault + " --s3 --api-key " + k + " --bucket " + cliBucket +
                  " --bucket-mode create --region us-east-2 --abort-multipart-days 7", superUser), 0);
    (void)protocols::ws::handler::Vaults::add(json{
        {"name", wsVault}, {"type", "s3"}, {"api_key_id", keyId}, {"bucket", wsBucket},
        {"provision", {{"mode", "create"}, {"region", "us-east-2"}, {"lifecycle", {{"abort_incomplete_multipart_days", 7}}}}}},
        ws(superUser));

    for (const auto& [vaultName, bucket] : {std::pair{cliVault, cliBucket}, std::pair{wsVault, wsBucket}}) {
        EXPECT_TRUE(cloudHas(bucket)) << bucket;
        const auto row = rowOf(bucket);
        ASSERT_TRUE(row) << bucket;
        EXPECT_EQ(storage::upstream::model::to_string(row->ownership), "managed");
        EXPECT_TRUE(row->created_by_vaulthalla);
        const auto vault = db::query::vault::Vault::getVault(vaultName, superUser->id);
        ASSERT_TRUE(vault) << vaultName;
        EXPECT_EQ(row->vault_id.value_or(0), vault->id);
        const auto rules = lifecycleOf(bucket);
        ASSERT_EQ(rules.size(), 1u) << bucket;
        EXPECT_EQ(rules[0].abort_incomplete_multipart_days.value_or(0), 7u);
    }
}

TEST_F(UpstreamParityTest, ANameCollisionIsRefusedAndHarmlessOnBothSurfaces) {
    const auto keyId = awsKey();
    const auto taken = bucketName();
    seedBucket(taken, {{"precious.bin", 42}});

    EXPECT_NE(cli("vault create upp_collide_" + tag() + " --s3 --api-key " + std::to_string(keyId) + " --bucket " + taken +
                  " --bucket-mode create", superUser), 0);
    EXPECT_THROW((void)protocols::ws::handler::Vaults::add(json{
        {"name", "upp_collide_" + tag()}, {"type", "s3"}, {"api_key_id", keyId}, {"bucket", taken},
        {"provision", {{"mode", "create"}}}}, ws(superUser)), ops::Conflict);
    EXPECT_EQ(objectsIn(taken), 1u) << "an existing bucket is never taken over";
    const auto row = rowOf(taken);
    EXPECT_FALSE(row && row->vault_id) << "no vault was bound to it";
}

TEST_F(UpstreamParityTest, AdoptionNeedsTheSameExplicitAcceptanceOnBothSurfaces) {
    const auto keyId = awsKey();
    const auto k = std::to_string(keyId);
    const auto cliBucket = bucketName(), wsBucket = bucketName();
    seedBucket(cliBucket, {{"old/a.jpg", 10}});
    seedBucket(wsBucket, {{"old/a.jpg", 10}});
    const auto cliVault = "upp_adopt_cli_" + tag(), wsVault = "upp_adopt_ws_" + tag();
    const json wsPayload{{"name", wsVault}, {"type", "s3"}, {"api_key_id", keyId}, {"bucket", wsBucket},
                         {"provision", {{"mode", "adopt"}}}};

    // Without acceptance: no terminal and no --yes on the CLI, no accept_adoption on ws.
    EXPECT_NE(cli("vault create " + cliVault + " --s3 --api-key " + k + " --bucket " + cliBucket + " --bucket-mode adopt",
                  superUser), 0);
    try {
        (void)protocols::ws::handler::Vaults::add(wsPayload, ws(superUser));
        ADD_FAILURE() << "ws adopted without acceptance";
    } catch (const ops::NeedsConfirmation& e) {
        EXPECT_EQ(e.code, up::ADOPTION_CONFIRM);
    }
    EXPECT_FALSE(db::query::vault::Vault::getVault(cliVault, superUser->id));
    EXPECT_FALSE(db::query::vault::Vault::getVault(wsVault, superUser->id));

    EXPECT_EQ(cli("vault create " + cliVault + " --s3 --api-key " + k + " --bucket " + cliBucket +
                  " --bucket-mode adopt --yes", superUser), 0);
    auto accepted = wsPayload;
    accepted["provision"]["accept_adoption"] = true;
    (void)protocols::ws::handler::Vaults::add(accepted, ws(superUser));

    for (const auto& [vaultName, bucket] : {std::pair{cliVault, cliBucket}, std::pair{wsVault, wsBucket}}) {
        const auto vault = db::query::vault::Vault::getVault(vaultName, superUser->id);
        ASSERT_TRUE(vault) << vaultName;
        const auto row = rowOf(bucket);
        ASSERT_TRUE(row) << bucket;
        EXPECT_EQ(storage::upstream::model::to_string(row->ownership), "adopted");
        EXPECT_FALSE(row->created_by_vaulthalla);
        EXPECT_EQ(row->vault_id.value_or(0), vault->id);
        EXPECT_EQ(objectsIn(bucket), 1u) << "adoption keeps the data";
    }
}

TEST_F(UpstreamParityTest, DestructiveLifecycleNeedsTheSameConsentOnBothSurfaces) {
    const auto keyId = awsKey();
    const auto k = std::to_string(keyId);
    const auto cliBucket = bucketName(), wsBucket = bucketName();
    for (const auto& b : {cliBucket, wsBucket})
        (void)ops::vaults::create(superUser, {.name = "upp_lc_" + tag(), .type = vault::model::VaultType::S3,
                                              .owner_id = superUser->id,
                                              .s3 = ops::vaults::S3Spec{.api_key_id = keyId, .bucket = b,
                                                                        .provision = up::Provision{.mode = up::BucketMode::Create}}});
    const auto session = ws(superUser);

    EXPECT_NE(cli("upstream lifecycle " + k + " " + cliBucket + " --expire-days 30", superUser), 0);
    try {
        (void)WsUp::bucketLifecycleSet(json{{"api_key_id", keyId}, {"bucket", wsBucket}, {"expire_current_days", 30}}, session);
        ADD_FAILURE() << "ws set a destructive rule without consent";
    } catch (const ops::NeedsConfirmation& e) {
        EXPECT_EQ(e.code, up::DESTRUCTIVE_LIFECYCLE);
    }
    EXPECT_TRUE(lifecycleOf(cliBucket).empty());
    EXPECT_TRUE(lifecycleOf(wsBucket).empty());

    EXPECT_EQ(cli("upstream lifecycle " + k + " " + cliBucket + " --expire-days 30 --yes", superUser), 0);
    (void)WsUp::bucketLifecycleSet(json{{"api_key_id", keyId}, {"bucket", wsBucket}, {"expire_current_days", 30},
                                        {"accept_destructive", true}}, session);
    for (const auto& b : {cliBucket, wsBucket}) {
        const auto rules = lifecycleOf(b);
        ASSERT_EQ(rules.size(), 1u) << b;
        EXPECT_EQ(rules[0].expire_current_days.value_or(0), 30u) << b;
    }
}

TEST_F(UpstreamParityTest, CleanupNeedsAPreflightTokenOnBothSurfaces) {
    const auto keyId = awsKey();
    const auto k = std::to_string(keyId);
    const auto cliBucket = bucketName(), wsBucket = bucketName();
    // Managed buckets no vault uses any more: created with a vault, then detached from it by deleting the vault row.
    for (const auto& b : {cliBucket, wsBucket}) {
        const auto v = ops::vaults::create(superUser, {.name = "upp_cl_" + tag(), .type = vault::model::VaultType::S3,
                                                       .owner_id = superUser->id,
                                                       .s3 = ops::vaults::S3Spec{.api_key_id = keyId, .bucket = b,
                                                                                 .provision = up::Provision{.mode = up::BucketMode::Create}}});
        runtime::Deps::get().storageManager->removeVault(v->id);
        seedBucket(b, {{"x", 1}, {"y", 2}});
    }
    const auto session = ws(superUser);

    // Without a token: the CLI prints the plan and refuses (no terminal); ws refuses with upstream_cleanup.
    EXPECT_NE(cli("upstream cleanup " + k + " " + cliBucket, superUser), 0);
    try {
        (void)WsUp::bucketCleanup(json{{"api_key_id", keyId}, {"bucket", wsBucket}, {"confirm_token", ""}}, session);
        ADD_FAILURE() << "ws cleaned up without a token";
    } catch (const ops::NeedsConfirmation& e) {
        EXPECT_EQ(e.code, up::CLEANUP_CONFIRM);
    }
    EXPECT_TRUE(cloudHas(cliBucket));
    EXPECT_TRUE(cloudHas(wsBucket));

    const auto cliPlan = up::cleanupPreflight(superUser, keyId, cliBucket);
    ASSERT_TRUE(cliPlan.blockers.empty()) << (cliPlan.blockers.empty() ? "" : cliPlan.blockers.front());
    EXPECT_EQ(cli("upstream cleanup " + k + " " + cliBucket + " --confirm-token " + cliPlan.confirm_token, superUser), 0);
    const auto wsPlan = WsUp::bucketCleanupPreflight(json{{"api_key_id", keyId}, {"bucket", wsBucket}}, session).at("plan");
    const auto result = WsUp::bucketCleanup(json{{"api_key_id", keyId}, {"bucket", wsBucket},
                                                 {"confirm_token", wsPlan.at("confirm_token")}}, session).at("result");
    EXPECT_EQ(result.at("outcome"), "deleted");
    EXPECT_FALSE(cloudHas(cliBucket));
    EXPECT_FALSE(cloudHas(wsBucket));
}

TEST_F(UpstreamParityTest, EventStatusReportsTheSameVaultsOnBothSurfaces) {
    const auto keyId = awsKey();
    const auto v = ops::vaults::create(superUser, {.name = "upp_ev_" + tag(), .type = vault::model::VaultType::S3,
                                                   .owner_id = superUser->id,
                                                   .s3 = ops::vaults::S3Spec{.api_key_id = keyId, .bucket = bucketName(),
                                                                             .provision = up::Provision{.mode = up::BucketMode::Create}}});
    EXPECT_EQ(cli("upstream events status " + std::to_string(v->id), superUser), 0);
    EXPECT_EQ(cli("upstream events status", superUser), 0);
    const auto one = WsUp::eventsStatus(json{{"vault_id", v->id}}, ws(superUser)).at("events");
    ASSERT_EQ(one.size(), 1u);
    EXPECT_EQ(one[0].at("vault_id"), v->id);
    EXPECT_EQ(one[0].at("state"), "none");
    const auto all = WsUp::eventsStatus(json(nullptr), ws(superUser)).at("events");
    EXPECT_TRUE(std::ranges::any_of(all, [&](const json& e) { return e.at("vault_id") == v->id; }));

    // Someone without admin.upstream.view sees nothing on either surface.
    const auto nobody = createUser("upp_nobody", "unprivileged");
    EXPECT_NE(cli("upstream events status " + std::to_string(v->id), nobody), 0);
    EXPECT_FALSE(wsOk([&] { (void)WsUp::eventsStatus(json{{"vault_id", v->id}}, ws(nobody)); }));
}

}
