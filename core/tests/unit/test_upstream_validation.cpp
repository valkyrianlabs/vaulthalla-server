// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// Input validation and bucket identity at the ops boundary (#237 security review, FX-2), against the test DB:
//  - bucket names that could change what a provider URL addresses are refused by vault create/update and by every
//    upstream op that calls a provider; legacy names already stored keep working, and can still be locked;
//  - provisioning regions must be real region codes / R2 hints;
//  - a key whose provider label contradicts its endpoint is refused, and an existing mislabelled key's buckets are
//    still covered by the lock on the real (endpoint-derived) identity.

#include "../helpers/sync_conflict_harness.hpp"
#include "../helpers/upstream_admin_fakes.hpp"

#include "db/query/upstream/Bucket.hpp"
#include "ops/APIKeys.hpp"
#include "ops/Upstream.hpp"
#include "ops/UpstreamJson.hpp"
#include "ops/Vaults.hpp"
#include "storage/s3/provider/admin/Admin.hpp"
#include "storage/upstream/Guard.hpp"
#include "storage/upstream/Provisioner.hpp"

#include <nlohmann/json.hpp>

namespace vh::test_upstream_validation {

using namespace test_support::sync_conflicts;
using namespace test_support::upstream_admin;
namespace padmin = storage::s3::provider::admin;
namespace up = ops::upstream;

class UpstreamValidationTest : public Harness {
protected:
    std::shared_ptr<FakeCloud> cloud;

    void SetUp() override {
        Harness::SetUp();
        if (skipTests) return;
        cloud = std::make_shared<FakeCloud>();
        padmin::setFactoryForTesting(padmin::Factory{
            .admin = [c = cloud](const std::shared_ptr<vault::model::APIKey>&) -> std::unique_ptr<padmin::AdminClient> {
                return std::make_unique<FakeAdmin>(c);
            },
            .events = nullptr});
        storage::upstream::guard::reload();
    }

    void TearDown() override { padmin::setFactoryForTesting(std::nullopt); }

    static unsigned allCallsOf(const std::shared_ptr<FakeCloud>& c) {
        std::scoped_lock lock(c->mutex);
        return c->calls;
    }

    static unsigned awsKey(const bool enable = true) {
        auto key = std::make_shared<vault::model::APIKey>(superUser->id, "val_key_" + tag(), vault::model::S3Provider::AWS,
                                                          "AKIATESTACCESSKEY000", "secret-value-0000000000000000000000000",
                                                          "us-east-2", "https://s3.us-east-2.amazonaws.com");
        const auto id = runtime::Deps::get().apiKeyManager->addAPIKey(key);
        if (enable) (void)up::enableAdmin(superUser, id, {});
        return id;
    }

    static ops::vaults::VaultPtr s3Vault(const unsigned keyId, const std::string& bucket,
                                         std::optional<up::Provision> provision = std::nullopt) {
        return ops::vaults::create(superUser, {.name = "val_vault_" + tag(), .type = vault::model::VaultType::S3,
                                               .owner_id = superUser->id,
                                               .s3 = ops::vaults::S3Spec{.api_key_id = keyId, .bucket = bucket,
                                                                         .provision = std::move(provision)}});
    }
};

TEST_F(UpstreamValidationTest, VaultCreateAndUpdateRefuseBucketNamesThatAreNotBucketNames) {
    const auto key = awsKey(false);
    for (const std::string bad : {"x/../prod", "prod/configuration?", "Prod", "a b", "../prod", "prod%2F"})
        EXPECT_THROW((void)s3Vault(key, bad), ops::Invalid) << bad;

    const auto vault = s3Vault(key, "vh-valid-" + tag());
    EXPECT_THROW((void)ops::vaults::update(superUser, {.id = vault->id, .bucket = std::string("x/../prod")}), ops::Invalid);

    // A legacy name already stored keeps working: an unrelated edit doesn't re-validate it.
    db::Transactions::exec("UpstreamValidation::legacy", [&](pqxx::work& txn) {
        txn.exec("UPDATE s3 SET bucket = $2 WHERE vault_id = $1", pqxx::params{vault->id, std::string("Legacy_Upper")});
    });
    runtime::Deps::get().storageManager->reloadEngine(vault->id);
    EXPECT_NO_THROW((void)ops::vaults::update(superUser, {.id = vault->id, .description = std::string("still fine")}));
}

TEST_F(UpstreamValidationTest, UpstreamOpsRefuseBadNamesButLegacyNamesCanStillBeLocked) {
    const auto key = awsKey();
    const auto before = allCallsOf(cloud);   // enabling admin probed the account
    EXPECT_THROW((void)up::inspect(superUser, key, "x/../prod"), ops::Invalid);
    EXPECT_THROW((void)up::adoptPreflight(superUser, key, "prod/configuration?"), ops::Invalid);
    EXPECT_THROW((void)up::inspect(superUser, key, "Legacy_Upper"), ops::Invalid) << "provider ops need a valid name";
    EXPECT_EQ(allCallsOf(cloud), before) << "refused names never reach the provider";

    // A lock is DB-only: legacy names AWS once allowed can be protected, URL-active characters can't.
    const auto row = up::protect(superUser, key, "Legacy_Upper", "old bucket, keep out");
    EXPECT_TRUE(row.is_protected);
    EXPECT_THROW((void)up::protect(superUser, key, "x/../prod", "nope"), ops::Invalid);
    EXPECT_THROW((void)up::protect(superUser, key, "prod?x", "nope"), ops::Invalid);
    (void)up::unprotect(superUser, key, "Legacy_Upper", true);
}

TEST_F(UpstreamValidationTest, ProvisioningRegionsMustBeRealRegions) {
    const auto key = awsKey();
    const auto before = allCallsOf(cloud);
    for (const std::string bad : {"evil.example/#", "us-east-1.evil.com", "US-EAST-1"}) {
        EXPECT_THROW((void)s3Vault(key, "vh-region-" + tag(),
                                   up::Provision{.mode = up::BucketMode::Create, .region = bad}),
                     ops::Invalid) << bad;
        EXPECT_THROW((void)up::provisionFromJson({{"mode", "create"}, {"region", bad}}), ops::Invalid) << bad;
    }
    EXPECT_EQ(allCallsOf(cloud), before) << "a bad region costs no provider request";
    EXPECT_NO_THROW((void)up::provisionFromJson({{"mode", "create"}, {"region", "eu-central-1"}}));
    EXPECT_NO_THROW((void)up::provisionFromJson({{"mode", "create"}, {"region", "wnam"}}));
}

TEST_F(UpstreamValidationTest, ProviderLabelsMustMatchTheEndpointAndLocksFollowTheEndpoint) {
    const auto r2Endpoint = std::string("https://") + std::string(32, 'a') + ".r2.cloudflarestorage.com";
    EXPECT_THROW((void)ops::api_keys::create(superUser, {.name = "mislabel_" + tag(), .provider = vault::model::S3Provider::Other,
                                                         .access_key = "0123456789abcdef0123456789abcdef",
                                                         .secret_access_key = "secret-value-0000000000000000000000000",
                                                         .endpoint = r2Endpoint, .region = "auto"}),
                 ops::Invalid);
    const auto r2Key = ops::api_keys::create(superUser, {.name = "r2_" + tag(), .provider = vault::model::S3Provider::CloudflareR2,
                                                          .access_key = "0123456789abcdef0123456789abcdef",
                                                          .secret_access_key = "secret-value-0000000000000000000000000",
                                                          .endpoint = r2Endpoint, .region = "auto"});
    EXPECT_THROW((void)ops::api_keys::update(superUser, r2Key->id, {.provider = vault::model::S3Provider::MinIO}), ops::Invalid);

    // A key saved before this check, labelled "Other" on an R2 endpoint: the lock on the real bucket still applies.
    auto legacy = std::make_shared<vault::model::APIKey>(superUser->id, "legacy_other_" + tag(), vault::model::S3Provider::Other,
                                                         "0123456789abcdef0123456789abcdef",
                                                         "secret-value-0000000000000000000000000", "auto", r2Endpoint);
    const auto legacyId = runtime::Deps::get().apiKeyManager->addAPIKey(legacy);
    const auto bucket = "vh-locked-" + tag();
    (void)up::protect(superUser, r2Key->id, bucket, "the real R2 bucket");
    EXPECT_THROW((void)s3Vault(legacyId, bucket), ops::Denied) << "the label must not dodge the lock";
    (void)up::unprotect(superUser, r2Key->id, bucket, true);
}

}
