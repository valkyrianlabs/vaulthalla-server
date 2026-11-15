// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// Attaching a remote through both surfaces (design/storage/attach-remote.md): `vh vault remote attach | status | abort`
// and ws vault.remote.attach | vault.remote.status | vault.remote.abort run ops::vault_remote (and the same for
// `vh vault remote detach` / vault.remote.detach on S3 vaults). For every seeded admin
// role, on local vaults owned by an unprivileged account, both surfaces must give the same verdict for each of the
// three operations and leave the same state; a super admin is allowed and an unprivileged account refused. Attach and
// abort are recorded in the audit trail; the same refusals (a missing key or bucket, a wrong confirmation, a bucket
// that is not empty) come back on both.

#include "../helpers/db_suite.hpp"
#include "../helpers/identities.hpp"
#include "../helpers/parity.hpp"
#include "../helpers/versioned_bucket.hpp"
#include "audit/Trail.hpp"
#include "db/Transactions.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/vault/RemoteAttach.hpp"
#include "db/query/vault/RemoteDetach.hpp"
#include "db/query/vault/Vault.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/VaultRemote.hpp"
#include "ops/Vaults.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/vault.hpp"
#include "protocols/ws/handler/vault/Keys.hpp"
#include "rbac/role/Admin.hpp"
#include "runtime/Deps.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/RemoteAttach.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <map>
#include <memory>
#include <optional>
#include <string>

namespace vh::test_ops_parity_vault_remote {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using test_support::versioned::Versioning;
using test_support::versioned::VersionedBucket;
using vh::test::parity::tag;
using Q = db::query::vault::RemoteAttach;
using WsKeys = protocols::ws::handler::VaultKeys;

class VaultRemoteParityTest : public vh::test::db::Suite {
protected:
    inline static std::shared_ptr<protocols::shell::Router> router;
    inline static UserPtr owner;
    inline static unsigned int keyId = 0;
    inline static std::map<std::string, std::shared_ptr<VersionedBucket>> buckets;

    static UserPtr createUser(const std::string& name, const std::string& roleName) {
        auto user = vh::test::identities::createUser(name, db::query::rbac::role::Admin::get(roleName),
                                                     name + "@vaulthalla.test", "x", std::nullopt);
        return vh::identities::manager().user(user->id);
    }

    static void SetUpTestSuite() {
        if (!setUpDbSuite("test_ops_parity_vault_remote")) return;
        router = test::parity::shellRouter();
        protocols::shell::commands::vault::registerCommands(router);
        owner = createUser("vr_owner_" + tag(), "unprivileged");
        auto key = std::make_shared<vault::model::APIKey>(superUser->id, "vr_key_" + tag(), vault::model::S3Provider::AWS,
                                                          "AKIAREMOTEATTACH0000", "remote-attach-secret-00000000000000",
                                                          "us-east-1", "https://s3.example.com");
        keyId = runtime::Deps::get().apiKeyManager->addAPIKey(key);
        vault::remote::setControllerFactoryForTesting(
            [](unsigned int, const std::string& bucket) -> std::shared_ptr<storage::s3::Controller> {
                const auto it = buckets.find(bucket);
                return it == buckets.end() ? nullptr : it->second;
            });
    }
    static void TearDownTestSuite() {
        if (skipTests) return;
        vault::remote::setControllerFactoryForTesting({});
        buckets.clear();
        tearDownDbSuite();
    }

    static std::pair<int, std::string> cli(const std::string& line, const UserPtr& user) {
        return test::parity::cli(*router, line, user);
    }

    struct Target {
        unsigned int vault{};
        std::string name;
        std::string bucket;
    };

    // A local vault of `owner` with its key exported (the recovery material an attach requires) and an empty bucket.
    static Target target() {
        const auto created = ops::vaults::create(superUser, {.name = "vr_" + tag(),
                                                             .type = vault::model::VaultType::Local,
                                                             .owner_id = owner->id});
        db::Transactions::exec("VaultRemoteParityTest::export", [&](pqxx::work& txn) {
            txn.exec("UPDATE vault_keys SET exported_version = version, exported_at = now() WHERE vault_id = $1",
                     pqxx::params{created->id});
        });
        Target t{.vault = created->id, .name = created->name, .bucket = "vr-bucket-" + tag()};
        buckets[t.bucket] = std::make_shared<VersionedBucket>(Versioning::Enabled, t.bucket);
        return t;
    }

    static std::optional<json> wsCall(const std::function<json()>& fn) {
        try {
            return fn();
        } catch (const ops::Error&) {
            return std::nullopt;
        }
    }

    static std::string stateOf(const unsigned int vaultId) {
        const auto row = Q::get(vaultId);
        return row ? std::string(vault::remote::to_string(row->state)) : std::string("none");
    }

    static uint64_t auditEvents(const std::string& action, const unsigned int vaultId) {
        EXPECT_TRUE(audit::Trail::instance()->flushNow());
        return db::Transactions::exec("auditEvents", [&](pqxx::work& txn) {
            return txn.exec("SELECT COUNT(*) FROM audit_event WHERE action = $1 AND vault_id = $2",
                            pqxx::params{action, vaultId}).one_field_ref().as<uint64_t>();
        });
    }
};

TEST_F(VaultRemoteParityTest, AttachStatusAndAbortAgreeOnBothSurfacesForEverySeededAdminRole) {
    unsigned checked = 0, allowedRoles = 0;
    for (const auto& role : db::query::rbac::role::Admin::list()) {
        SCOPED_TRACE(role->name);
        const auto caller = role->name == "super_admin" ? superUser : createUser("vr_" + role->name + tag(), role->name);
        const auto viaCli = target(), viaWs = target();

        // status before anything: both surfaces agree on who may view the vault.
        const auto cliStatus = cli("vault remote status " + std::to_string(viaCli.vault) + " --json", caller);
        const auto wsStatus = wsCall([&] { return WsKeys::remoteStatus(json{{"vault_id", viaWs.vault}}, test::parity::ws(caller)); });
        EXPECT_EQ(cliStatus.first == 0, wsStatus.has_value()) << cliStatus.second;
        if (cliStatus.first == 0 && wsStatus) {
            EXPECT_EQ(json::parse(cliStatus.second).at("vaults").at(0).at("remote"), "none");
            EXPECT_EQ(wsStatus->at("vaults").at(0).at("remote"), "none");
        }

        // attach
        const auto cliAttach = cli("vault remote attach " + std::to_string(viaCli.vault) + " --api-key " +
                                       std::to_string(keyId) + " --bucket " + viaCli.bucket + " --accept-unpriced --json",
                                   caller);
        const auto wsAttach = wsCall([&] {
            return WsKeys::remoteAttach(json{{"vault_id", viaWs.vault}, {"api_key_id", keyId}, {"bucket", viaWs.bucket},
                                             {"accept_unpriced", true}},
                                        test::parity::ws(caller));
        });
        const bool attached = cliAttach.first == 0;
        EXPECT_EQ(attached, wsAttach.has_value()) << cliAttach.second;
        if (role->name == "super_admin") {
            EXPECT_TRUE(attached) << cliAttach.second;
        }
        if (role->name == "unprivileged") {
            EXPECT_FALSE(attached) << cliAttach.second;
        }
        EXPECT_EQ(stateOf(viaCli.vault), attached ? "preparing" : "none");
        EXPECT_EQ(stateOf(viaWs.vault), stateOf(viaCli.vault));
        EXPECT_EQ(auditEvents("vault.remote.attach", viaCli.vault), attached ? 1u : 0u);
        EXPECT_EQ(auditEvents("vault.remote.attach", viaWs.vault), attached ? 1u : 0u);
        if (attached && wsAttach) {
            const auto fromCli = json::parse(cliAttach.second);
            EXPECT_EQ(fromCli.at("remote"), wsAttach->at("remote"));
            EXPECT_EQ(fromCli.at("attach").at("manifest_publish"), wsAttach->at("attach").at("manifest_publish"));
            EXPECT_EQ(fromCli.at("attach").at("state"), "preparing");
            ++allowedRoles;
        }

        // abort: the same callers, the vault's name as confirmation. Started by the super admin where the caller may not.
        if (!attached) {
            ASSERT_EQ(cli("vault remote attach " + std::to_string(viaCli.vault) + " --api-key " + std::to_string(keyId) +
                              " --bucket " + viaCli.bucket + " --accept-unpriced", superUser).first, 0);
            (void)WsKeys::remoteAttach(json{{"vault_id", viaWs.vault}, {"api_key_id", keyId}, {"bucket", viaWs.bucket},
                                            {"accept_unpriced", true}},
                                       test::parity::ws(superUser));
        }
        const auto cliAbort = cli("vault remote abort " + std::to_string(viaCli.vault) + " --confirm " + viaCli.name +
                                      " --json", caller);
        const auto wsAbort = wsCall([&] {
            return WsKeys::remoteAbort(json{{"vault_id", viaWs.vault}, {"confirm", viaWs.name}}, test::parity::ws(caller));
        });
        EXPECT_EQ(cliAbort.first == 0, wsAbort.has_value()) << cliAbort.second;
        EXPECT_EQ(Q::get(viaCli.vault)->abort_requested_at.has_value(), cliAbort.first == 0);
        EXPECT_EQ(Q::get(viaWs.vault)->abort_requested_at.has_value(), wsAbort.has_value());
        EXPECT_EQ(auditEvents("vault.remote.abort", viaCli.vault), cliAbort.first == 0 ? 1u : 0u);
        ++checked;
    }
    EXPECT_GE(checked, 2u) << "expected the seeded admin roles";
    EXPECT_GE(allowedRoles, 1u);
}

TEST_F(VaultRemoteParityTest, DetachAndItsAbortAgreeOnBothSurfacesForEverySeededAdminRole) {
    using DQ = db::query::vault::RemoteDetach;
    unsigned checked = 0, allowedRoles = 0;
    for (const auto& role : db::query::rbac::role::Admin::list()) {
        SCOPED_TRACE(role->name);
        const auto caller = role->name == "super_admin" ? superUser : createUser("vd_" + role->name + tag(), role->name);
        const auto viaCli = test_support::versioned::makeCloudVault(superUser, "vdcli", Versioning::Enabled, true);
        const auto viaWs = test_support::versioned::makeCloudVault(superUser, "vdws", Versioning::Enabled, true);
        const auto cliName = viaCli.engine->vault->name, wsName = viaWs.engine->vault->name;

        const auto cliDetach = cli("vault remote detach " + std::to_string(viaCli.id()) + " --confirm " + cliName + " --json",
                                   caller);
        const auto wsDetach = wsCall([&] {
            return WsKeys::remoteDetach(json{{"vault_id", viaWs.id()}, {"confirm", wsName}}, test::parity::ws(caller));
        });
        const bool started = cliDetach.first == 0;
        EXPECT_EQ(started, wsDetach.has_value()) << cliDetach.second;
        if (role->name == "super_admin") {
            EXPECT_TRUE(started) << cliDetach.second;
        }
        if (role->name == "unprivileged") {
            EXPECT_FALSE(started) << cliDetach.second;
        }
        EXPECT_EQ(DQ::get(viaCli.id()).has_value(), started);
        EXPECT_EQ(DQ::get(viaWs.id()).has_value(), wsDetach.has_value());
        EXPECT_EQ(auditEvents("vault.remote.detach", viaCli.id()), started ? 1u : 0u);
        if (started && wsDetach) {
            const auto fromCli = json::parse(cliDetach.second);
            EXPECT_EQ(fromCli.at("remote"), "detaching:preparing");
            EXPECT_EQ(fromCli.at("remote"), wsDetach->at("remote"));
            EXPECT_EQ(fromCli.at("detach").at("state"), wsDetach->at("detach").at("state"));
            ++allowedRoles;
        }

        if (!started) {
            ASSERT_EQ(cli("vault remote detach " + std::to_string(viaCli.id()) + " --confirm " + cliName, superUser).first, 0);
            (void)WsKeys::remoteDetach(json{{"vault_id", viaWs.id()}, {"confirm", wsName}}, test::parity::ws(superUser));
        }
        const auto cliAbort = cli("vault remote abort " + std::to_string(viaCli.id()) + " --confirm " + cliName + " --json",
                                  caller);
        const auto wsAbort = wsCall([&] {
            return WsKeys::remoteAbort(json{{"vault_id", viaWs.id()}, {"confirm", wsName}}, test::parity::ws(caller));
        });
        EXPECT_EQ(cliAbort.first == 0, wsAbort.has_value()) << cliAbort.second;
        EXPECT_EQ(DQ::get(viaCli.id())->abort_requested_at.has_value(), cliAbort.first == 0);
        EXPECT_EQ(DQ::get(viaWs.id())->abort_requested_at.has_value(), wsAbort.has_value());
        ++checked;
    }
    EXPECT_GE(checked, 2u);
    EXPECT_GE(allowedRoles, 1u);

    // A wrong confirmation, a local vault: refused alike.
    const auto s3 = test_support::versioned::makeCloudVault(superUser, "vdref", Versioning::Enabled, true);
    EXPECT_NE(cli("vault remote detach " + std::to_string(s3.id()) + " --confirm wrong", superUser).first, 0);
    EXPECT_THROW((void)WsKeys::remoteDetach(json{{"vault_id", s3.id()}, {"confirm", "wrong"}}, test::parity::ws(superUser)),
                 ops::Invalid);
    const auto local = target();
    EXPECT_NE(cli("vault remote detach " + std::to_string(local.vault) + " --confirm " + local.name, superUser).first, 0);
    EXPECT_THROW((void)WsKeys::remoteDetach(json{{"vault_id", local.vault}, {"confirm", local.name}},
                                            test::parity::ws(superUser)),
                 ops::Conflict);
    EXPECT_FALSE(DQ::get(s3.id()));
    EXPECT_FALSE(DQ::get(local.vault));
}

TEST_F(VaultRemoteParityTest, TheSameRefusalsOnBothSurfaces) {
    const auto t = target();
    const auto id = std::to_string(t.vault);

    // A key and a bucket are required.
    EXPECT_NE(cli("vault remote attach " + id + " --bucket " + t.bucket, superUser).first, 0);
    EXPECT_THROW((void)WsKeys::remoteAttach(json{{"vault_id", t.vault}, {"bucket", t.bucket}}, test::parity::ws(superUser)),
                 ops::Invalid);
    EXPECT_NE(cli("vault remote attach " + id + " --api-key " + std::to_string(keyId), superUser).first, 0);
    EXPECT_THROW((void)WsKeys::remoteAttach(json{{"vault_id", t.vault}, {"api_key_id", keyId}}, test::parity::ws(superUser)),
                 ops::Invalid);

    // A bucket that is not empty: the same code, nothing recorded.
    buckets[t.bucket]->seed("someone-elses.txt", std::string("x"));
    const auto refusedCli = cli("vault remote attach " + id + " --api-key " + std::to_string(keyId) + " --bucket " + t.bucket,
                                superUser);
    EXPECT_NE(refusedCli.first, 0);
    EXPECT_NE(refusedCli.second.find("not empty"), std::string::npos) << refusedCli.second;
    try {
        (void)WsKeys::remoteAttach(json{{"vault_id", t.vault}, {"api_key_id", keyId}, {"bucket", t.bucket}},
                                   test::parity::ws(superUser));
        ADD_FAILURE() << "the ws attach was not refused";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "bucket_not_empty");
    }
    EXPECT_FALSE(Q::get(t.vault));

    // Nothing to abort; then a wrong confirmation.
    EXPECT_NE(cli("vault remote abort " + id + " --confirm " + t.name, superUser).first, 0);
    EXPECT_THROW((void)WsKeys::remoteAbort(json{{"vault_id", t.vault}, {"confirm", t.name}}, test::parity::ws(superUser)),
                 ops::Conflict);
    const auto started = target();
    ASSERT_EQ(cli("vault remote attach " + std::to_string(started.vault) + " --api-key " + std::to_string(keyId) +
                      " --bucket " + started.bucket + " --accept-unpriced", superUser).first, 0);
    EXPECT_NE(cli("vault remote abort " + std::to_string(started.vault) + " --confirm wrong", superUser).first, 0);
    EXPECT_NE(cli("vault remote abort " + std::to_string(started.vault), superUser).first, 0);
    EXPECT_THROW((void)WsKeys::remoteAbort(json{{"vault_id", started.vault}, {"confirm", "wrong"}}, test::parity::ws(superUser)),
                 ops::Invalid);
    EXPECT_THROW((void)WsKeys::remoteAbort(json{{"vault_id", started.vault}}, test::parity::ws(superUser)), ops::Invalid);
    EXPECT_FALSE(Q::get(started.vault)->abort_requested_at);

    // status all: every vault with an attach the caller may view, on both surfaces.
    const auto all = cli("vault remote status all --json", superUser);
    ASSERT_EQ(all.first, 0) << all.second;
    const auto wsAll = WsKeys::remoteStatus(json::object(), test::parity::ws(superUser));
    EXPECT_EQ(json::parse(all.second).at("vaults").size(), wsAll.at("vaults").size());
    EXPECT_GE(wsAll.at("vaults").size(), 1u);
    // Whoever may not view a vault is refused its status on both surfaces alike.
    EXPECT_EQ(cli("vault remote status " + id, owner).first == 0,
              wsCall([&] { return WsKeys::remoteStatus(json{{"vault_id", t.vault}}, test::parity::ws(owner)); })
                  .has_value());
}

}
