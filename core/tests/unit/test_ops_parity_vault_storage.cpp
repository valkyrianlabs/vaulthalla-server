// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// The bucket capability probe through both surfaces (design/encryption/06-publish-without-preconditions.md §7):
// `vh vault storage probe` and ws vault.storage.probe run ops::vault_storage::probe. For every seeded admin role, on
// an S3 vault owned by an unprivileged account (admins reach it through admin.vaults.user), both surfaces must agree
// on the verdict, which must match the role's bits (admin.vaults.user.edit), and leave the same stored capability.
// The probe is recorded in the audit trail; a protected bucket and a local vault are refused.

#include "../helpers/db_suite.hpp"
#include "../helpers/identities.hpp"
#include "../helpers/parity.hpp"
#include "../helpers/versioned_bucket.hpp"
#include "audit/Trail.hpp"
#include "db/Transactions.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/vault/BucketCapability.hpp"
#include "db/query/vault/Vault.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/VaultStorage.hpp"
#include "ops/Vaults.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/vault.hpp"
#include "protocols/ws/handler/vault/Keys.hpp"
#include "rbac/role/Admin.hpp"
#include "runtime/Deps.hpp"
#include "storage/BucketCapability.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <memory>
#include <optional>
#include <string>

namespace vh::test_ops_parity_vault_storage {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using storage::s3::WriteCapability;
using test_support::versioned::Versioning;
using test_support::versioned::VersionedBucket;
using vh::test::parity::tag;

class VaultStorageParityTest : public vh::test::db::Suite {
protected:
    inline static std::shared_ptr<protocols::shell::Router> router;
    inline static UserPtr owner;
    inline static std::shared_ptr<VersionedBucket> bucket;

    static UserPtr createUser(const std::string& name, const std::string& roleName) {
        auto user = vh::test::identities::createUser(name, db::query::rbac::role::Admin::get(roleName),
                                                     name + "@vaulthalla.test", "x", std::nullopt);
        return vh::identities::manager().user(user->id);
    }

    static void SetUpTestSuite() {
        // Fresh engines: a vault id an earlier suite used must not resolve to that suite's engine and controller.
        if (!setUpDbSuite("test_ops_parity_vault_storage")) return;
        router = test::parity::shellRouter();
        protocols::shell::commands::vault::registerCommands(router);
        owner = createUser("vs_owner_" + tag(), "unprivileged");
        bucket = std::make_shared<VersionedBucket>(Versioning::Enabled);
        bucket->conditionalPuts = VersionedBucket::ConditionalPuts::Reject501;
        storage::bucket_capability::setControllerFactoryForTesting(
            [](unsigned int, const std::string&) -> std::shared_ptr<storage::s3::Controller> { return bucket; });
    }
    static void TearDownTestSuite() {
        if (skipTests) return;
        storage::bucket_capability::setControllerFactoryForTesting({});
        tearDownDbSuite();
    }

    static std::pair<int, std::string> cli(const std::string& line, const UserPtr& user) {
        return test::parity::cli(*router, line, user);
    }

    // An S3 vault row of `owner` without a running engine (the op then probes the vault's binding).
    static unsigned int s3Vault() {
        auto key = std::make_shared<vault::model::APIKey>(owner->id, "vs_key_" + tag(),
                                                          vault::model::S3Provider::BackblazeB2, "AKIASTORAGEPROBE0000",
                                                          "storage-probe-secret-000000000000000", "us-west-004",
                                                          "https://s3.us-west-004.backblazeb2.com");
        const auto keyId = runtime::Deps::get().apiKeyManager->addAPIKey(key);
        const auto name = "vs_" + tag();
        auto s3 = std::make_shared<vault::model::S3Vault>(name, keyId, "vs-bucket-" + tag());
        s3->owner_id = owner->id;
        s3->mount_point = name;
        s3->encrypt_upstream = true;
        s3->storage_layout = vault::model::StorageLayout::OpaqueV1;
        return db::query::vault::Vault::upsertVault(s3, std::make_shared<sync::model::RemotePolicy>());
    }

    static bool oracle(const UserPtr& user) {
        if (user->isSuperAdmin()) return true;
        const auto& admin = user->state()->roles.admin;
        return admin && admin->vaults.user.canEdit();
    }

    static uint64_t auditEvents(const unsigned int vaultId) {
        EXPECT_TRUE(audit::Trail::instance()->flushNow());
        return db::Transactions::exec("auditEvents", [&](pqxx::work& txn) {
            return txn.exec("SELECT COUNT(*) FROM audit_event WHERE action = 'vault.storage.probe' AND vault_id = $1",
                            pqxx::params{vaultId}).one_field_ref().as<uint64_t>();
        });
    }
};

TEST_F(VaultStorageParityTest, ProbeAgreesOnBothSurfacesForEverySeededAdminRole) {
    unsigned checked = 0;
    for (const auto& role : db::query::rbac::role::Admin::list()) {
        SCOPED_TRACE(role->name);
        const auto caller = role->name == "super_admin" ? superUser : createUser("vs_" + role->name + tag(), role->name);
        const auto viaCli = s3Vault();
        const auto viaWs = s3Vault();
        const bool allowed = oracle(caller);

        const auto [code, out] = cli("vault storage probe " + std::to_string(viaCli) + " --json", caller);
        std::optional<json> wsAnswer;
        try {
            wsAnswer = protocols::ws::handler::VaultKeys::storageProbe(json{{"vault_id", viaWs}},
                                                                       test::parity::ws(caller));
        } catch (const ops::Denied&) {
        }
        EXPECT_EQ(code == 0, wsAnswer.has_value()) << out;
        EXPECT_EQ(code == 0, allowed) << "oracle: admin.vaults.user.edit\n" << out;
        if (code == 0 && wsAnswer) {
            const auto cliAnswer = json::parse(out);
            EXPECT_EQ(cliAnswer.at("probe").at("capability"), wsAnswer->at("probe").at("capability"));
            EXPECT_EQ(cliAnswer.at("probe").at("capability"), "version_log");
            EXPECT_EQ(cliAnswer.at("manifest_publishable"), false);
        }
        const auto expected = allowed ? WriteCapability::VersionLog : WriteCapability::Unknown;
        EXPECT_EQ(db::query::vault::BucketCapability::get(viaCli).capability, expected);
        EXPECT_EQ(db::query::vault::BucketCapability::get(viaWs).capability, expected);
        EXPECT_EQ(auditEvents(viaCli), allowed ? 1u : 0u);
        ++checked;
    }
    EXPECT_GE(checked, 2u) << "expected the seeded admin roles";
}

TEST_F(VaultStorageParityTest, ALocalVaultHasNoBucketToProbe) {
    const auto local = ops::vaults::create(superUser, {.name = "vs_local_" + tag(), .type = vault::model::VaultType::Local});
    EXPECT_THROW((void)ops::vault_storage::probe(superUser, local->id), ops::Invalid);
    EXPECT_NE(cli("vault storage probe " + std::to_string(local->id), superUser).first, 0);
    EXPECT_THROW((void)ops::vault_storage::probe(superUser, 999'999), ops::NotFound);
}

}
