// Upstream control plane ops (#237), against the test DB and an in-memory provider account (a fake AdminClient
// installed through the admin factory test seam):
//  - RBAC: admin.upstream.* bits plus the key's own keys.api permission, for every seeded admin role;
//  - hard protection: every bucket operation refused, binding a vault refused, sync requests refused, unlock needs
//    confirmation and is audited, the lock survives deleting and re-creating the key;
//  - provisioning: a managed bucket + vault, generated names, collisions never take over or delete anything, concurrent
//    attempts, compensation deletes only an empty bucket the attempt created; adoption needs confirmation;
//  - cleanup refuses protected, unmanaged, adopted, bound and changed buckets, reports partial failures;
//  - backward compatibility: existing-mode vault creation and vault deletion make no admin calls.

#include "../helpers/sync_conflict_harness.hpp"
#include "../helpers/upstream_admin_fakes.hpp"

#include "db/query/upstream/Audit.hpp"
#include "db/query/upstream/Bucket.hpp"
#include "db/query/upstream/Channel.hpp"
#include "db/query/upstream/Subscription.hpp"
#include "ops/APIKeys.hpp"
#include "ops/Roles.hpp"
#include "ops/Upstream.hpp"
#include "ops/UpstreamJson.hpp"
#include "ops/Vaults.hpp"
#include "rbac/permission/admin/Upstream.hpp"
#include "rbac/permission/admin/keys/API.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "storage/s3/provider/admin/Admin.hpp"
#include "storage/s3/provider/admin/Internal.hpp"
#include "storage/upstream/Guard.hpp"
#include "storage/upstream/Lifecycle.hpp"
#include "storage/upstream/Provisioner.hpp"

#include <nlohmann/json.hpp>

#include <set>
#include <thread>

namespace vh::test_upstream_ops {

using namespace test_support::sync_conflicts;
using namespace test_support::upstream_admin;
namespace padmin = storage::s3::provider::admin;
namespace up = ops::upstream;

class UpstreamOpsTest : public Harness {
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
        storage::upstream::provision::setObjectHeadForTesting(
            [c = cloud](const std::shared_ptr<vault::model::APIKey>&, const std::string& bucket, const std::string& key)
                -> std::optional<std::unordered_map<std::string, std::string>> {
                std::scoped_lock lock(c->mutex);
                c->touch(bucket);
                if (!c->buckets.contains(bucket) || !c->buckets.at(bucket).objects.contains(key)) return std::nullopt;
                if (key.starts_with("enc/")) return std::unordered_map<std::string, std::string>{{"x-amz-meta-vh-encrypted", "true"}};
                return std::unordered_map<std::string, std::string>{{"Content-Length", "1"}};
            });
        storage::upstream::guard::reload();
    }

    void TearDown() override {
        padmin::setFactoryForTesting(std::nullopt);
        storage::upstream::provision::setObjectHeadForTesting({});
    }

    static unsigned awsKey(const UserPtr& owner, const bool enable = true) {
        auto key = std::make_shared<vault::model::APIKey>(owner->id, "up_key_" + tag(), vault::model::S3Provider::AWS,
                                                          "AKIATESTACCESSKEY000", "secret-value-0000000000000000000000000",
                                                          "us-east-2", "https://s3.us-east-2.amazonaws.com");
        const auto id = runtime::Deps::get().apiKeyManager->addAPIKey(key);
        if (enable) (void)up::enableAdmin(superUser, id, {});
        return id;
    }

    static std::string bucketName() { return "vh-test-" + tag(); }

    void seedBucket(const std::string& name, std::map<std::string, uint64_t> objects = {}) {
        std::scoped_lock lock(cloud->mutex);
        cloud->buckets[name].objects = std::move(objects);
    }

    bool exists(const std::string& name) {
        std::scoped_lock lock(cloud->mutex);
        return cloud->buckets.contains(name);
    }

    size_t objectCount(const std::string& name) {
        std::scoped_lock lock(cloud->mutex);
        return cloud->buckets.at(name).objects.size();
    }

    unsigned callsOn(const std::string& name) {
        std::scoped_lock lock(cloud->mutex);
        return cloud->bucketCalls[name];
    }

    unsigned allCalls() {
        std::scoped_lock lock(cloud->mutex);
        return cloud->calls;
    }

    static std::optional<storage::upstream::model::Bucket> rowOf(const std::string& name) {
        return db::query::upstream::Bucket::getByIdentity("aws-s3", kAccount, name);
    }

    static ops::vaults::VaultPtr s3Vault(const unsigned keyId, const std::string& bucket,
                                         std::optional<up::Provision> provision = std::nullopt) {
        return ops::vaults::create(superUser, {.name = "up_vault_" + tag(), .type = vault::model::VaultType::S3,
                                               .owner_id = superUser->id,
                                               .s3 = ops::vaults::S3Spec{.api_key_id = keyId, .bucket = bucket,
                                                                         .provision = std::move(provision)}});
    }
};

// ---- DB-free ---------------------------------------------------------------------------------------------------------

TEST(UpstreamBucketNames, FollowS3Rules) {
    std::string why;
    EXPECT_TRUE(storage::upstream::provision::validBucketName("vh-photos-a1b2c3d4", why));
    EXPECT_TRUE(storage::upstream::provision::validBucketName("my.bucket.name", why));
    for (const auto* bad : {"ab", "Upper-Case", "-leading", "trailing-", "two..dots", "192.168.1.1", "xn--punycode",
                            "name-s3alias", "under_score"})
        EXPECT_FALSE(storage::upstream::provision::validBucketName(bad, why)) << bad;
}

TEST(UpstreamLifecycleMerge, KeepsForeignRulesAndFlagsDestructiveChanges) {
    using storage::upstream::lifecycle::mergeOwnedRule;
    padmin::LifecycleRule foreign;
    foreign.id = "someone-elses-rule";
    foreign.foreign = true;
    foreign.expire_current_days = 30;
    foreign.raw_xml = "<Rule>…</Rule>";

    auto merged = mergeOwnedRule({foreign}, {.abort_incomplete_multipart_days = 7}, true);
    ASSERT_EQ(merged.rules.size(), 2u);
    EXPECT_EQ(merged.rules[0].id, "someone-elses-rule");
    EXPECT_EQ(merged.rules[0].raw_xml, "<Rule>…</Rule>");
    EXPECT_FALSE(merged.destructive) << "aborting incomplete uploads deletes no object";
    EXPECT_TRUE(merged.changed);

    auto withExpiry = mergeOwnedRule(merged.rules, {.expire_current_days = 90}, true);
    EXPECT_TRUE(withExpiry.destructive);
    auto longer = mergeOwnedRule(withExpiry.rules, {.expire_current_days = 120}, true);
    EXPECT_FALSE(longer.destructive) << "keeping objects longer deletes nothing new";
    auto cleared = mergeOwnedRule(longer.rules, {.clear = true}, true);
    ASSERT_EQ(cleared.rules.size(), 1u);
    EXPECT_EQ(cleared.rules[0].id, "someone-elses-rule");

    EXPECT_THROW((void)mergeOwnedRule({}, {.expire_noncurrent_days = 5}, false), std::invalid_argument);
}

// ---- backward compatibility ----------------------------------------------------------------------------------------

TEST_F(UpstreamOpsTest, ExistingModeVaultCreationMakesNoAdminCalls) {
    const auto keyId = awsKey(superUser, false);
    const auto before = allCalls();
    const auto vault = s3Vault(keyId, bucketName());
    ASSERT_TRUE(vault);
    EXPECT_EQ(allCalls(), before) << "a vault on a named bucket never calls provider administration";

    const auto withMode = s3Vault(keyId, bucketName(), up::Provision{.mode = up::BucketMode::Existing});
    ASSERT_TRUE(withMode);
    EXPECT_EQ(allCalls(), before);
}

// ---- provisioning --------------------------------------------------------------------------------------------------

TEST_F(UpstreamOpsTest, CreatesAManagedBucketWithItsVault) {
    const auto keyId = awsKey(superUser);
    const auto name = bucketName();
    const auto vault = s3Vault(keyId, name, up::Provision{.mode = up::BucketMode::Create,
                                                          .lifecycle = up::LifecyclePatch{.abort_incomplete_multipart_days = 7}});
    ASSERT_TRUE(vault);
    EXPECT_TRUE(exists(name));
    const auto row = rowOf(name);
    ASSERT_TRUE(row);
    EXPECT_EQ(row->ownership, storage::upstream::model::Ownership::Managed);
    EXPECT_EQ(row->provisioning_state, storage::upstream::model::ProvisioningState::Ready);
    EXPECT_TRUE(row->created_by_vaulthalla);
    EXPECT_EQ(row->vault_id.value_or(0), vault->id);
    {
        std::scoped_lock lock(cloud->mutex);
        ASSERT_EQ(cloud->buckets.at(name).lifecycle.size(), 1u);
        EXPECT_EQ(cloud->buckets.at(name).lifecycle[0].id, storage::upstream::lifecycle::kOwnedRuleId);
    }

    const auto inv = up::inventory(superUser, keyId);
    const auto it = std::ranges::find(inv.buckets, name, &up::BucketRow::name);
    ASSERT_NE(it, inv.buckets.end());
    EXPECT_EQ(it->state, up::BucketState::Managed);
    EXPECT_EQ(it->vault_id.value_or(0), vault->id);
}

TEST_F(UpstreamOpsTest, GeneratesAnAvailableName) {
    const auto keyId = awsKey(superUser);
    const auto vault = s3Vault(keyId, "", up::Provision{.mode = up::BucketMode::Create, .generate_name = true});
    const auto s3 = std::static_pointer_cast<vault::model::S3Vault>(runtime::Deps::get().storageManager->getVault(vault->id));
    ASSERT_TRUE(s3);
    EXPECT_TRUE(s3->bucket.starts_with("vh-up-vault-")) << s3->bucket;
    EXPECT_TRUE(exists(s3->bucket));
}

TEST_F(UpstreamOpsTest, CreatingOverAnExistingBucketNeverTakesItOver) {
    const auto keyId = awsKey(superUser);

    // HeadBucket sees it.
    const auto taken = bucketName();
    seedBucket(taken, {{"precious.txt", 5}});
    EXPECT_THROW((void)s3Vault(keyId, taken, up::Provision{.mode = up::BucketMode::Create}), ops::Conflict);
    EXPECT_EQ(objectCount(taken), 1u);
    EXPECT_FALSE(rowOf(taken)) << "the failed claim is released, not left as 'managed'";

    // HeadBucket doesn't see it, CreateBucket refuses.
    const auto racing = bucketName();
    seedBucket(racing, {{"a", 1}});
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->hiddenFromHead.insert(racing);
    }
    EXPECT_THROW((void)s3Vault(keyId, racing, up::Provision{.mode = up::BucketMode::Create}), ops::Conflict);
    EXPECT_EQ(objectCount(racing), 1u);

    // us-east-1: CreateBucket answers 200 on a bucket the account owns; it lists objects, so it existed before.
    const auto silent = bucketName();
    seedBucket(silent, {{"b", 1}});
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->hiddenFromHead.insert(silent);
        cloud->silentCreate = true;
    }
    EXPECT_THROW((void)s3Vault(keyId, silent, up::Provision{.mode = up::BucketMode::Create}), ops::Conflict);
    EXPECT_EQ(objectCount(silent), 1u);
    const auto row = rowOf(silent);
    ASSERT_TRUE(row);
    EXPECT_EQ(row->ownership, storage::upstream::model::Ownership::Unmanaged);

    // Another account's bucket.
    const auto foreign = bucketName();
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->otherAccount.insert(foreign);
    }
    EXPECT_THROW((void)s3Vault(keyId, foreign, up::Provision{.mode = up::BucketMode::Create}), ops::Conflict);

    std::scoped_lock lock(cloud->mutex);
    EXPECT_EQ(cloud->deleteBucketCalls, 0u) << "no collision path deletes anything";
}

TEST_F(UpstreamOpsTest, ConcurrentCreatesOfOneNameHaveOneWinner) {
    const auto keyId = awsKey(superUser);
    const auto name = bucketName();
    std::atomic<int> won{0}, conflicted{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < 4; ++i)
        threads.emplace_back([&] {
            try {
                (void)up::beginProvision(superUser, keyId, "race", name, {.mode = up::BucketMode::Create});
                ++won;
            } catch (const ops::Conflict&) {
                ++conflicted;
            }
        });
    for (auto& t : threads) t.join();
    EXPECT_EQ(won.load(), 1);
    EXPECT_EQ(conflicted.load(), 3);
}

TEST_F(UpstreamOpsTest, RollbackDeletesOnlyAnEmptyBucketThisAttemptCreated) {
    const auto keyId = awsKey(superUser);
    const auto empty = bucketName();
    const auto ticket = up::beginProvision(superUser, keyId, "v", empty, {.mode = up::BucketMode::Create});
    ASSERT_TRUE(exists(empty));
    up::abortProvision(ticket, "vault creation failed");
    EXPECT_FALSE(exists(empty));
    EXPECT_EQ(rowOf(empty)->provisioning_state, storage::upstream::model::ProvisioningState::Deleted);

    const auto used = bucketName();
    const auto t2 = up::beginProvision(superUser, keyId, "v", used, {.mode = up::BucketMode::Create});
    seedBucket(used, {{"someone-wrote-this", 3}});
    up::abortProvision(t2, "vault creation failed");
    EXPECT_TRUE(exists(used)) << "a bucket with data is never deleted by a rollback";
    EXPECT_EQ(objectCount(used), 1u);
    EXPECT_EQ(rowOf(used)->provisioning_state, storage::upstream::model::ProvisioningState::Failed);
}

TEST_F(UpstreamOpsTest, AdoptionNeedsConfirmationAndKeepsTheData) {
    const auto keyId = awsKey(superUser);
    const auto name = bucketName();
    seedBucket(name, {{"photo.jpg", 100}, {"enc/sealed.bin", 116}});

    const auto report = up::adoptPreflight(superUser, keyId, name);
    EXPECT_EQ(report.objects_scanned, 2u);
    EXPECT_EQ(report.sampled, 2u);
    EXPECT_EQ(report.sampled_vaulthalla_encrypted, 1u);
    EXPECT_EQ(report.sampled_plaintext, 1u);
    EXPECT_TRUE(report.blockers.empty());

    try {
        (void)s3Vault(keyId, name, up::Provision{.mode = up::BucketMode::Adopt});
        FAIL() << "adoption without acceptance";
    } catch (const ops::NeedsConfirmation& e) {
        EXPECT_EQ(e.code, up::ADOPTION_CONFIRM);
    }
    const auto vault = s3Vault(keyId, name, up::Provision{.mode = up::BucketMode::Adopt, .accept_adoption = true});
    ASSERT_TRUE(vault);
    EXPECT_EQ(objectCount(name), 2u);
    const auto row = rowOf(name);
    ASSERT_TRUE(row);
    EXPECT_EQ(row->ownership, storage::upstream::model::Ownership::Adopted);
    EXPECT_EQ(row->vault_id.value_or(0), vault->id);

    // Bound now: neither another adoption nor a cleanup.
    EXPECT_FALSE(up::adoptPreflight(superUser, keyId, name).blockers.empty());
    EXPECT_THROW((void)s3Vault(keyId, name, up::Provision{.mode = up::BucketMode::Adopt, .accept_adoption = true}),
                 ops::Conflict);
    EXPECT_FALSE(up::cleanupPreflight(superUser, keyId, name).blockers.empty());
}

// ---- protection ----------------------------------------------------------------------------------------------------

TEST_F(UpstreamOpsTest, AProtectedBucketRefusesEveryOperation) {
    const auto keyId = awsKey(superUser);
    const auto name = bucketName();
    seedBucket(name, {{"keep.txt", 1}});
    (void)up::protect(superUser, keyId, name, "production backups");
    const auto before = callsOn(name);

    EXPECT_THROW((void)up::inspect(superUser, keyId, name), ops::Denied);
    EXPECT_THROW((void)up::setLifecycle(superUser, keyId, name, {.abort_incomplete_multipart_days = 3}), ops::Denied);
    EXPECT_THROW((void)up::adoptPreflight(superUser, keyId, name), ops::Denied);
    EXPECT_THROW((void)up::detach(superUser, keyId, name), ops::Denied);
    EXPECT_THROW((void)up::cleanupPreflight(superUser, keyId, name), ops::Denied);
    EXPECT_THROW((void)up::cleanup(superUser, keyId, name, "token"), ops::Denied);
    EXPECT_THROW((void)s3Vault(keyId, name), ops::Denied) << "never vault storage";
    EXPECT_THROW((void)s3Vault(keyId, name, up::Provision{.mode = up::BucketMode::Adopt, .accept_adoption = true}),
                 ops::Denied);
    EXPECT_THROW((void)s3Vault(keyId, name, up::Provision{.mode = up::BucketMode::Create}), ops::Denied);
    EXPECT_EQ(callsOn(name), before) << "not one bucket-level request";

    // An existing vault repointed at it.
    const auto other = s3Vault(keyId, bucketName());
    EXPECT_THROW((void)ops::vaults::update(superUser, {.id = other->id, .bucket = name}), ops::Denied);

    // Listed in the account inventory, as protected.
    const auto inv = up::inventory(superUser, keyId);
    const auto it = std::ranges::find(inv.buckets, name, &up::BucketRow::name);
    ASSERT_NE(it, inv.buckets.end());
    EXPECT_EQ(it->state, up::BucketState::Protected);
    EXPECT_EQ(it->protection_reason.value_or(""), "production backups");
    const auto unmanagedOnly = up::inventory(superUser, keyId, {.state = up::BucketState::Unmanaged});
    EXPECT_EQ(std::ranges::find(unmanagedOnly.buckets, name, &up::BucketRow::name), unmanagedOnly.buckets.end());

    // Unlocking is explicit and audited.
    try {
        (void)up::unprotect(superUser, keyId, name, false);
        FAIL() << "unprotect without confirmation";
    } catch (const ops::NeedsConfirmation& e) {
        EXPECT_EQ(e.code, up::UNPROTECT_CONFIRM);
    }
    EXPECT_TRUE(storage::upstream::guard::isProtected({.provider = "aws-s3", .account_ref = kAccount, .bucket = name}));
    (void)up::unprotect(superUser, keyId, name, true);
    EXPECT_FALSE(storage::upstream::guard::isProtected({.provider = "aws-s3", .account_ref = kAccount, .bucket = name}));
    EXPECT_NO_THROW((void)up::inspect(superUser, keyId, name));

    const auto entries = up::audit(superUser, {.bucket = name});
    std::set<std::string> actions;
    for (const auto& e : entries) actions.insert(e.action + ":" + e.outcome);
    EXPECT_TRUE(actions.contains("protect:ok"));
    EXPECT_TRUE(actions.contains("unprotect:ok"));
    EXPECT_TRUE(actions.contains("inspect:refused"));
}

TEST_F(UpstreamOpsTest, TheLockBelongsToTheBucketNotTheKey) {
    const auto key1 = awsKey(superUser);
    const auto name = bucketName();
    seedBucket(name);
    (void)up::protect(superUser, key1, name, "not ours");
    (void)ops::api_keys::remove(superUser, key1);

    const auto key2 = awsKey(superUser);
    EXPECT_THROW((void)s3Vault(key2, name), ops::Denied);
    EXPECT_THROW((void)up::inspect(superUser, key2, name), ops::Denied);

    // A key whose account was never resolved (not admin-enabled, nothing cached) still can't bind it: fail closed.
    const auto plain = awsKey(superUser, false);
    EXPECT_THROW((void)s3Vault(plain, name), ops::Denied);
}

TEST_F(UpstreamOpsTest, ProtectingABoundBucketStopsItsUpstreamRequests) {
    const auto keyId = awsKey(superUser);
    const auto f = remoteVault(superUser);   // FakeBucket "fake-bucket" behind an AWS key with no resolved account
    EXPECT_NO_THROW((void)f.bucket->getHeadObject("x"));
    (void)up::protect(superUser, keyId, "fake-bucket", "lab");
    EXPECT_THROW((void)f.bucket->getHeadObject("x"), storage::upstream::BucketProtected)
        << "every metered request of the vault's controller is refused, sync passes and retries included";
    (void)up::unprotect(superUser, keyId, "fake-bucket", true);
    EXPECT_NO_THROW((void)f.bucket->getHeadObject("x"));
}

// ---- lifecycle -----------------------------------------------------------------------------------------------------

TEST_F(UpstreamOpsTest, LifecycleIsManagedOnlyOnOurBucketsAndDestructiveRulesNeedConsent) {
    const auto keyId = awsKey(superUser);
    const auto unmanaged = bucketName();
    seedBucket(unmanaged);
    EXPECT_THROW((void)up::setLifecycle(superUser, keyId, unmanaged, {.abort_incomplete_multipart_days = 3}), ops::Invalid);

    const auto name = bucketName();
    (void)s3Vault(keyId, name, up::Provision{.mode = up::BucketMode::Create});
    {
        padmin::LifecycleRule foreign;
        foreign.id = "other-app";
        foreign.foreign = true;
        foreign.abort_incomplete_multipart_days = 1;
        std::scoped_lock lock(cloud->mutex);
        cloud->buckets.at(name).lifecycle.push_back(foreign);
    }
    try {
        (void)up::setLifecycle(superUser, keyId, name, {.expire_current_days = 30});
        FAIL() << "expiring objects without consent";
    } catch (const ops::NeedsConfirmation& e) {
        EXPECT_EQ(e.code, up::DESTRUCTIVE_LIFECYCLE);
    }
    const auto inspection = up::setLifecycle(superUser, keyId, name, {.expire_current_days = 30, .accept_destructive = true});
    ASSERT_EQ(inspection.config.lifecycle.size(), 2u);
    EXPECT_TRUE(std::ranges::any_of(inspection.config.lifecycle, [](const auto& r) { return r.id == "other-app"; }));
}

// ---- cleanup -------------------------------------------------------------------------------------------------------

TEST_F(UpstreamOpsTest, CleanupRefusesBucketsVaulthallaDoesNotOwnOrStillUses) {
    const auto keyId = awsKey(superUser);
    const auto unmanaged = bucketName();
    seedBucket(unmanaged, {{"x", 1}});
    const auto plan = up::cleanupPreflight(superUser, keyId, unmanaged);
    EXPECT_FALSE(plan.blockers.empty());
    EXPECT_TRUE(plan.confirm_token.empty());
    EXPECT_EQ(callsOn(unmanaged), 0u) << "nothing is listed for a bucket that may not be deleted";

    const auto bound = bucketName();
    const auto vault = s3Vault(keyId, bound, up::Provision{.mode = up::BucketMode::Create});
    EXPECT_FALSE(up::cleanupPreflight(superUser, keyId, bound).blockers.empty());

    // Deleting the vault keeps the bucket and its binding until the purge: still refused, and no admin call happened.
    const auto calls = allCalls();
    (void)ops::vaults::remove(superUser, {.id = vault->id, .accept_key_loss = true});
    EXPECT_EQ(allCalls(), calls) << "vault deletion leaves upstream data alone by default";
    EXPECT_TRUE(exists(bound));
    EXPECT_FALSE(up::cleanupPreflight(superUser, keyId, bound).blockers.empty());

    EXPECT_THROW((void)up::cleanup(superUser, keyId, unmanaged, "made-up-token"), ops::NeedsConfirmation);
}

TEST_F(UpstreamOpsTest, CleanupDeletesAManagedBucketAfterAFreshConfirmation) {
    const auto keyId = awsKey(superUser);
    const auto name = bucketName();
    const auto ticket = up::beginProvision(superUser, keyId, "v", name, {.mode = up::BucketMode::Create});
    ASSERT_TRUE(db::query::upstream::Bucket::setProvisioningState(ticket.upstream_bucket_id,
                                                                 storage::upstream::model::ProvisioningState::Ready,
                                                                 ticket.operation_token));
    seedBucket(name, {{"a", 1}, {"b", 2}});

    const auto plan = up::cleanupPreflight(superUser, keyId, name);
    ASSERT_TRUE(plan.blockers.empty()) << plan.blockers.front();
    EXPECT_EQ(plan.objects, 2u);
    EXPECT_EQ(plan.bytes, 3u);
    ASSERT_FALSE(plan.confirm_token.empty());

    // Another person can't use the confirmation; the bucket changing invalidates it.
    const auto other = createUser("up_other", "admin");
    EXPECT_THROW((void)up::cleanup(other, keyId, name, plan.confirm_token), ops::Error);
    const auto again = up::cleanupPreflight(superUser, keyId, name);
    seedBucket(name, {{"a", 1}, {"b", 2}, {"late", 9}});
    EXPECT_THROW((void)up::cleanup(superUser, keyId, name, again.confirm_token), ops::NeedsConfirmation);
    EXPECT_EQ(objectCount(name), 3u);

    const auto fresh = up::cleanupPreflight(superUser, keyId, name);
    const auto result = up::cleanup(superUser, keyId, name, fresh.confirm_token);
    EXPECT_EQ(result.outcome, "deleted");
    EXPECT_EQ(result.deleted, 3u);
    EXPECT_TRUE(result.bucket_deleted);
    EXPECT_FALSE(exists(name));
    EXPECT_THROW((void)up::cleanup(superUser, keyId, name, fresh.confirm_token), ops::NeedsConfirmation) << "single use";
}

TEST_F(UpstreamOpsTest, CleanupReportsPartialFailuresHonestly) {
    const auto keyId = awsKey(superUser);
    const auto name = bucketName();
    const auto ticket = up::beginProvision(superUser, keyId, "v", name, {.mode = up::BucketMode::Create});
    (void)db::query::upstream::Bucket::setProvisioningState(ticket.upstream_bucket_id,
                                                            storage::upstream::model::ProvisioningState::Ready,
                                                            ticket.operation_token);
    seedBucket(name, {{"free", 1}, {"locked", 1}});
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->buckets.at(name).locked.insert("locked");
    }
    const auto plan = up::cleanupPreflight(superUser, keyId, name);
    const auto result = up::cleanup(superUser, keyId, name, plan.confirm_token);
    EXPECT_EQ(result.outcome, "partial");
    EXPECT_EQ(result.failed, 1u);
    EXPECT_FALSE(result.bucket_deleted);
    EXPECT_TRUE(exists(name));
    EXPECT_EQ(rowOf(name)->provisioning_state, storage::upstream::model::ProvisioningState::Failed);
}

TEST_F(UpstreamOpsTest, DetachRelinquishesOnlyUnusedBucketsAndKeepsTheData) {
    const auto keyId = awsKey(superUser);
    const auto name = bucketName();
    const auto ticket = up::beginProvision(superUser, keyId, "v", name, {.mode = up::BucketMode::Create,
                                           .lifecycle = up::LifecyclePatch{.abort_incomplete_multipart_days = 2}});
    (void)db::query::upstream::Bucket::setProvisioningState(ticket.upstream_bucket_id,
                                                            storage::upstream::model::ProvisioningState::Ready,
                                                            ticket.operation_token);
    seedBucket(name, {{"kept", 4}});
    {
        padmin::LifecycleRule ours;
        ours.id = storage::upstream::lifecycle::kOwnedRuleId;
        ours.abort_incomplete_multipart_days = 2;
        std::scoped_lock lock(cloud->mutex);
        cloud->buckets.at(name).lifecycle.push_back(ours);
    }
    const auto row = up::detach(superUser, keyId, name);
    EXPECT_EQ(row.state, up::BucketState::Unmanaged);
    EXPECT_EQ(objectCount(name), 1u);
    std::scoped_lock lock(cloud->mutex);
    EXPECT_TRUE(cloud->buckets.at(name).lifecycle.empty()) << "our rule is gone, the data is not";
}

// File recovery adds a second Vaulthalla rule (vaulthalla-manifest-versions): detach relinquishes every vaulthalla-*
// rule, never another application's.
TEST_F(UpstreamOpsTest, DetachRemovesEveryVaulthallaLifecycleRuleAndKeepsForeignOnes) {
    const auto keyId = awsKey(superUser);
    const auto name = bucketName();
    const auto ticket = up::beginProvision(superUser, keyId, "v", name, {.mode = up::BucketMode::Create,
                                           .lifecycle = up::LifecyclePatch{.abort_incomplete_multipart_days = 2}});
    (void)db::query::upstream::Bucket::setProvisioningState(ticket.upstream_bucket_id,
                                                            storage::upstream::model::ProvisioningState::Ready,
                                                            ticket.operation_token);
    seedBucket(name, {{"kept", 4}});
    {
        std::scoped_lock lock(cloud->mutex);
        auto& rules = cloud->buckets.at(name).lifecycle;
        rules.clear();
        padmin::LifecycleRule ours;
        ours.id = storage::upstream::lifecycle::kOwnedRuleId;
        ours.foreign = false;
        ours.expire_noncurrent_days = 30;
        rules.push_back(ours);
        const auto manifest = storage::upstream::lifecycle::mergeManifestRule(rules, true, true);
        rules = manifest.rules;
        padmin::LifecycleRule foreign;
        foreign.id = "backup-team-rule";
        foreign.foreign = true;
        foreign.abort_incomplete_multipart_days = 7;
        rules.push_back(foreign);
        ASSERT_EQ(rules.size(), 3u);
    }
    (void)up::detach(superUser, keyId, name);
    std::scoped_lock lock(cloud->mutex);
    const auto& left = cloud->buckets.at(name).lifecycle;
    ASSERT_EQ(left.size(), 1u) << "vaulthalla-managed and vaulthalla-manifest-versions are gone";
    EXPECT_EQ(left.front().id, "backup-team-rule");
}

// ---- admin credentials, keys ---------------------------------------------------------------------------------------

TEST_F(UpstreamOpsTest, AdminEnableResolvesTheAccountAndKeysInUseByEventsCannotBeRemoved) {
    const auto keyId = awsKey(superUser, false);
    const auto status = up::enableAdmin(superUser, keyId, {});
    EXPECT_TRUE(status.enabled);
    EXPECT_EQ(status.account_ref.value_or(""), kAccount);
    ASSERT_TRUE(status.capabilities);
    EXPECT_FALSE(status.capabilities->has("events.queues"));
    EXPECT_THROW((void)up::enableAdmin(superUser, keyId, {.provider_token = std::string("cf-token")}), ops::Invalid)
        << "a provider token is a Cloudflare thing";

    const auto bucket = db::query::upstream::Bucket::protect({.provider = "aws-s3", .account_ref = kAccount, .bucket = bucketName()},
                                                             std::nullopt, std::nullopt, std::nullopt, "fixture");
    (void)db::query::upstream::Bucket::unprotect(bucket.identity());
    storage::upstream::guard::reload();
    const auto channel = db::query::upstream::Channel::getOrCreate("aws-s3", kAccount, "us-east-2",
                                                                   "vaulthalla-events-us-east-2-" + tag(), keyId);
    const auto vault = s3Vault(keyId, bucketName());
    const auto sub = db::query::upstream::Subscription::create(channel.id, bucket.id, vault->id, "",
                                                               storage::upstream::model::ForeignObjects::Import,
                                                               storage::upstream::model::BaselineState::None);
    ASSERT_TRUE(sub);
    db::query::upstream::Subscription::setState(sub->id, storage::upstream::model::SubscriptionState::Active, std::nullopt);
    EXPECT_THROW((void)up::disableAdmin(superUser, keyId), ops::Conflict);
    EXPECT_THROW((void)ops::api_keys::remove(superUser, keyId), ops::Invalid) << "bound to a vault, too";
    db::query::upstream::Subscription::setState(sub->id, storage::upstream::model::SubscriptionState::Removed, std::nullopt);
    EXPECT_NO_THROW((void)up::disableAdmin(superUser, keyId));
}

TEST_F(UpstreamOpsTest, ChangingAKeysEndpointForgetsItsAccount) {
    const auto keyId = awsKey(superUser);
    ASSERT_TRUE(db::query::vault::APIKey::getAPIKey(keyId)->provider_account_id);
    (void)ops::api_keys::update(superUser, keyId, {.endpoint = std::string("https://s3.eu-west-1.amazonaws.com")});
    EXPECT_FALSE(db::query::vault::APIKey::getAPIKey(keyId)->provider_account_id);
}

// ---- RBAC ----------------------------------------------------------------------------------------------------------

TEST_F(UpstreamOpsTest, EveryOperationFollowsTheUpstreamBitsAndTheKeysPermission) {
    using UpPerm = rbac::permission::admin::UpstreamPermissions;
    using KeyPerm = rbac::permission::admin::keys::APIPermissions;
    const auto keyId = awsKey(superUser);
    const auto name = bucketName();
    seedBucket(name);

    for (const auto* role : {"unprivileged", "auditor", "support", "identity_admin", "security_admin", "platform_operator",
                             "vault_admin", "admin", "key_custodian", "super_admin"}) {
        // super_admin can't be assigned: the seeded super administrator holds it.
        const auto user = std::string(role) == "super_admin" ? superUser : createUser(std::string("up_rbac_") + role, role);
        const auto bits = user->upstreamPerms();
        const auto key = [&](const KeyPerm p) {
            return rbac::resolver::Admin::has<KeyPerm>({.user = user, .permission = p, .api_key_id = keyId});
        };
        const auto allowed = [&](auto&& fn) {
            try {
                fn();
                return true;
            } catch (const ops::Denied&) {
                return false;
            } catch (const ops::Error&) {
                return true;   // authorized, refused for another reason
            }
        };
        EXPECT_EQ(allowed([&] { (void)up::inventory(user, keyId); }), bits.canView() && key(KeyPerm::View)) << role;
        EXPECT_EQ(allowed([&] { (void)up::inspect(user, keyId, name); }), bits.canView() && key(KeyPerm::View)) << role;
        EXPECT_EQ(allowed([&] { (void)up::audit(user); }), bits.canView()) << role;
        EXPECT_EQ(allowed([&] { (void)up::adminStatus(user, keyId, false); }), bits.canView() && key(KeyPerm::View)) << role;
        EXPECT_EQ(allowed([&] { (void)up::adoptPreflight(user, keyId, name); }),
                  bits.canProvision() && key(KeyPerm::Consume)) << role;
        EXPECT_EQ(allowed([&] { (void)up::cleanupPreflight(user, keyId, name); }),
                  bits.canDestroy() && key(KeyPerm::Consume)) << role;
        const bool canProtect = bits.canProtect() && key(KeyPerm::View);
        EXPECT_EQ(allowed([&] { (void)up::protect(user, keyId, name, "rbac"); }), canProtect) << role;
        if (canProtect) {
            EXPECT_EQ(allowed([&] { (void)up::unprotect(user, keyId, name, true); }),
                      bits.canUnprotect() && key(KeyPerm::Consume)) << role;
            (void)up::unprotect(superUser, keyId, name, true);
        }
        EXPECT_EQ(allowed([&] { (void)up::enableAdmin(user, keyId, {}); }), bits.canConfigure() && key(KeyPerm::Edit))
            << role;
    }
    (void)sizeof(UpPerm);
}

// ---- JSON ----------------------------------------------------------------------------------------------------------

TEST_F(UpstreamOpsTest, JsonUsesTheDocumentedShapes) {
    const auto keyId = awsKey(superUser);
    const auto name = bucketName();
    seedBucket(name);
    (void)up::protect(superUser, keyId, name, "json");
    const nlohmann::json inv = up::inventory(superUser, keyId);
    ASSERT_TRUE(inv.contains("buckets"));
    const auto it = std::ranges::find_if(inv["buckets"], [&](const auto& b) { return b["name"] == name; });
    ASSERT_NE(it, inv["buckets"].end());
    EXPECT_EQ((*it)["state"], "protected");
    EXPECT_EQ((*it)["is_protected"], true);
    EXPECT_TRUE((*it)["protected_at"].is_string());
    EXPECT_TRUE((*it)["vault_id"].is_null());
    const nlohmann::json status = up::adminStatus(superUser, keyId, false);
    EXPECT_EQ(status["enabled"], true);
    EXPECT_FALSE(status["api_key"].contains("secret_access_key"));
    EXPECT_FALSE(status.dump().contains("secret-value"));
}

// ---- review fixes (FX-1): ownership claims, cleanup lease, lifecycle fidelity, deletion, RBAC ----------------------

namespace {

std::map<std::string, uint64_t> manyObjects(const size_t n) {
    std::map<std::string, uint64_t> out;
    for (size_t i = 0; i < n; ++i) out["obj-" + std::to_string(100000 + i)] = 1;
    return out;
}

unsigned auditCount(const std::string& bucket, const std::string& action, const std::string& outcome) {
    unsigned n = 0;
    for (const auto& r : db::query::upstream::Audit::list(bucket, 1000))
        if (r.action == action && storage::upstream::model::to_string(r.outcome) == outcome) ++n;
    return n;
}

}

TEST_F(UpstreamOpsTest, ATransientFailureBeforeCreatingNeverLeavesAnOwnershipClaim) {
    // Data-safety review #1: a create that failed on HeadBucket (503) used to leave a row saying
    // managed / created_by_vaulthalla, which a later cleanup trusted.
    const auto keyId = awsKey(superUser);
    const auto name = bucketName();
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->headFails.insert(name);
    }
    EXPECT_ANY_THROW((void)up::beginProvision(superUser, keyId, "v", name, {.mode = up::BucketMode::Create}));
    if (const auto row = rowOf(name)) {
        EXPECT_NE(row->ownership, storage::upstream::model::Ownership::Managed);
        EXPECT_FALSE(row->created_by_vaulthalla);
    }

    // The name turns out to be another application's bucket: it is never "ours" to clean up.
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->headFails.clear();
    }
    seedBucket(name, {{"their-data", 7}});
    const auto plan = up::cleanupPreflight(superUser, keyId, name);
    EXPECT_FALSE(plan.blockers.empty());
    EXPECT_TRUE(plan.confirm_token.empty());
    EXPECT_EQ(objectCount(name), 1u);
}

TEST_F(UpstreamOpsTest, ARetryResumesOnlyABucketThisRecordReallyCreated) {
    namespace m = storage::upstream::model;
    using BQ = db::query::upstream::Bucket;
    const auto keyId = awsKey(superUser);

    // An attempt that never created anything, then someone else creates an empty bucket with that name.
    const auto attempted = bucketName();
    const storage::upstream::BucketIdentity attemptedId{.provider = "aws-s3", .account_ref = kAccount, .bucket = attempted};
    const auto claim = BQ::claimForCreate(attemptedId, std::nullopt, keyId, "old-attempt");
    ASSERT_TRUE(claim);
    ASSERT_TRUE(BQ::setProvisioningState(claim->bucket.id, m::ProvisioningState::Failed, "old-attempt", "boom"));
    seedBucket(attempted);
    EXPECT_THROW((void)up::beginProvision(superUser, keyId, "v", attempted, {.mode = up::BucketMode::Create}), ops::Conflict);
    EXPECT_TRUE(exists(attempted));
    if (const auto row = rowOf(attempted)) {
        EXPECT_FALSE(row->created_by_vaulthalla);
    }

    // Our bucket, rolled back (deleted); someone re-creates the name, empty: not ours either.
    const auto recreated = bucketName();
    const auto t = up::beginProvision(superUser, keyId, "v", recreated, {.mode = up::BucketMode::Create});
    up::abortProvision(t, "vault creation failed");
    ASSERT_FALSE(exists(recreated));
    seedBucket(recreated);
    EXPECT_THROW((void)up::beginProvision(superUser, keyId, "v", recreated, {.mode = up::BucketMode::Create}), ops::Conflict);
    EXPECT_TRUE(exists(recreated));
    if (const auto row = rowOf(recreated)) {
        EXPECT_FALSE(row->created_by_vaulthalla);
    }

    // Our own bucket from a failed attempt, still there and empty: resumed.
    const auto ours = bucketName();
    const auto first = up::beginProvision(superUser, keyId, "v", ours, {.mode = up::BucketMode::Create});
    ASSERT_TRUE(BQ::setProvisioningState(first.upstream_bucket_id, m::ProvisioningState::Failed, first.operation_token, "x"));
    const auto resumed = up::beginProvision(superUser, keyId, "v", ours, {.mode = up::BucketMode::Create});
    EXPECT_TRUE(resumed.created);
    EXPECT_EQ(resumed.upstream_bucket_id, first.upstream_bucket_id);

    std::scoped_lock lock(cloud->mutex);
    EXPECT_EQ(cloud->deleteBucketCalls, 1u) << "only the rollback of the bucket this attempt itself created";
}

TEST_F(UpstreamOpsTest, CleanupHoldsALeaseAgainstAdoptionAndProvisioning) {
    namespace m = storage::upstream::model;
    const auto keyId = awsKey(superUser);
    const auto name = bucketName();
    const auto ticket = up::beginProvision(superUser, keyId, "v", name, {.mode = up::BucketMode::Create});

    // Still configuring (no vault yet): cleanup refused.
    seedBucket(name, {{"a", 1}});
    EXPECT_FALSE(up::cleanupPreflight(superUser, keyId, name).blockers.empty());

    ASSERT_TRUE(db::query::upstream::Bucket::setProvisioningState(ticket.upstream_bucket_id, m::ProvisioningState::Ready,
                                                                 ticket.operation_token));
    seedBucket(name, manyObjects(1500));
    std::optional<std::string> adoptionOutcome;
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->beforeDeleteObjects = [&](const std::string&) {
            if (adoptionOutcome) return;
            try {
                (void)up::beginProvision(superUser, keyId, "late", name, {.mode = up::BucketMode::Adopt, .accept_adoption = true});
                adoptionOutcome = "adopted";
            } catch (const ops::Conflict& e) {
                adoptionOutcome = std::string("conflict: ") + e.what();
            } catch (const std::exception& e) {
                adoptionOutcome = std::string("other: ") + e.what();
            }
        };
    }
    const auto plan = up::cleanupPreflight(superUser, keyId, name);
    ASSERT_TRUE(plan.blockers.empty()) << plan.blockers.front();
    const auto result = up::cleanup(superUser, keyId, name, plan.confirm_token);
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->beforeDeleteObjects = nullptr;
    }
    ASSERT_TRUE(adoptionOutcome);
    EXPECT_TRUE(adoptionOutcome->starts_with("conflict")) << *adoptionOutcome;
    EXPECT_EQ(result.outcome, "deleted");
    EXPECT_EQ(rowOf(name)->provisioning_state, m::ProvisioningState::Deleted);
    EXPECT_FALSE(rowOf(name)->vault_id);
}

TEST_F(UpstreamOpsTest, ALockSetDuringACleanupStopsItAsPartial) {
    namespace m = storage::upstream::model;
    const auto keyId = awsKey(superUser);
    const auto name = bucketName();
    const auto ticket = up::beginProvision(superUser, keyId, "v", name, {.mode = up::BucketMode::Create});
    ASSERT_TRUE(db::query::upstream::Bucket::setProvisioningState(ticket.upstream_bucket_id, m::ProvisioningState::Ready,
                                                                 ticket.operation_token));
    seedBucket(name, manyObjects(2500));
    const auto plan = up::cleanupPreflight(superUser, keyId, name);
    bool locked = false;
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->beforeDeleteObjects = [&](const std::string&) {
            if (locked) return;
            locked = true;
            (void)up::protect(superUser, keyId, name, "stop that");
        };
    }
    const auto result = up::cleanup(superUser, keyId, name, plan.confirm_token);
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->beforeDeleteObjects = nullptr;
    }
    EXPECT_EQ(result.outcome, "partial");
    EXPECT_FALSE(result.bucket_deleted);
    EXPECT_TRUE(exists(name));
    EXPECT_GT(objectCount(name), 0u) << "nothing past the lock is deleted";
    EXPECT_GE(auditCount(name, "cleanup", "partial"), 1u);
    (void)up::unprotect(superUser, keyId, name, true);
}

TEST_F(UpstreamOpsTest, AProviderErrorMidCleanupIsRecordedAsPartialAndCanBeResumed) {
    namespace m = storage::upstream::model;
    const auto keyId = awsKey(superUser);
    const auto name = bucketName();
    const auto ticket = up::beginProvision(superUser, keyId, "v", name, {.mode = up::BucketMode::Create});
    ASSERT_TRUE(db::query::upstream::Bucket::setProvisioningState(ticket.upstream_bucket_id, m::ProvisioningState::Ready,
                                                                 ticket.operation_token));
    seedBucket(name, manyObjects(1500));
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->deleteObjectsFailAfter = 1;   // the first batch goes through, the second fails
    }
    const auto plan = up::cleanupPreflight(superUser, keyId, name);
    const auto result = up::cleanup(superUser, keyId, name, plan.confirm_token);
    EXPECT_EQ(result.outcome, "partial");
    EXPECT_EQ(result.deleted, 1000u);
    ASSERT_FALSE(result.errors.empty());
    EXPECT_EQ(objectCount(name), 500u);
    const auto row = rowOf(name);
    EXPECT_EQ(row->provisioning_state, m::ProvisioningState::Failed) << "recoverable, not stuck in deleting";
    EXPECT_TRUE(row->last_error && row->last_error->contains("1000 deleted"));
    EXPECT_EQ(auditCount(name, "cleanup", "partial"), 1u) << "what was already deleted is on the record";

    {
        std::scoped_lock lock(cloud->mutex);
        cloud->deleteObjectsFailAfter = -1;
    }
    const auto again = up::cleanupPreflight(superUser, keyId, name);
    ASSERT_TRUE(again.blockers.empty()) << again.blockers.front();
    EXPECT_EQ(up::cleanup(superUser, keyId, name, again.confirm_token).outcome, "deleted");
    EXPECT_FALSE(exists(name));
}

TEST(UpstreamLifecycleFidelity, OnlyOurManagedRuleIsRebuiltAndUnmodeledVersionsOfItAreRefused) {
    namespace detail = storage::s3::provider::admin::detail;
    using storage::upstream::lifecycle::mergeOwnedRule;
    const std::string xml =
        R"(<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">)"
        R"(<Rule><ID>vaulthalla-tmp</ID><Filter><And><Prefix>tmp/</Prefix><Tag><Key>tmp</Key><Value>true</Value></Tag></And></Filter>)"
        R"(<Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>)"
        R"(<Rule><ID>vaulthalla-managed</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status>)"
        R"(<AbortIncompleteMultipartUpload><DaysAfterInitiation>3</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule>)"
        R"(</LifecycleConfiguration>)";
    const auto rules = detail::parseLifecycle(xml);
    ASSERT_EQ(rules.size(), 2u);
    EXPECT_TRUE(rules[0].foreign) << "another vaulthalla-* id is not ours to rebuild";
    EXPECT_TRUE(rules[0].unmodeled);
    EXPECT_FALSE(rules[1].foreign);
    EXPECT_FALSE(rules[1].unmodeled);

    const auto merged = mergeOwnedRule(rules, {.abort_incomplete_multipart_days = 7}, true);
    const auto written = detail::buildLifecycle(merged.rules, true);
    EXPECT_TRUE(written.contains("<Tag>")) << "the tag filter survives byte for byte: " << written;
    EXPECT_TRUE(written.contains("vaulthalla-tmp"));

    // Our rule changed outside Vaulthalla into something the model can't carry: refused, not silently widened.
    const std::string customized =
        R"(<LifecycleConfiguration><Rule><ID>vaulthalla-managed</ID><Filter><Tag><Key>k</Key><Value>v</Value></Tag></Filter>)"
        R"(<Status>Enabled</Status><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>)";
    const auto custom = detail::parseLifecycle(customized);
    ASSERT_EQ(custom.size(), 1u);
    EXPECT_TRUE(custom[0].unmodeled);
    EXPECT_THROW((void)mergeOwnedRule(custom, {.abort_incomplete_multipart_days = 7}, true),
                 storage::upstream::lifecycle::UnmodeledOwnedRule);
    EXPECT_NO_THROW((void)mergeOwnedRule(custom, {.clear = true}, true)) << "removing it is still allowed";
}

TEST(UpstreamLifecycleFidelity, ReEnablingADisabledExpirationIsDestructive) {
    using storage::upstream::lifecycle::mergeOwnedRule;
    padmin::LifecycleRule disabled;
    disabled.id = storage::upstream::lifecycle::kOwnedRuleId;
    disabled.enabled = false;
    disabled.expire_current_days = 30;
    const auto merged = mergeOwnedRule({disabled}, {.abort_incomplete_multipart_days = 7}, true);
    EXPECT_TRUE(merged.destructive) << "an unrelated patch turns the expiration back on";
}

TEST_F(UpstreamOpsTest, DeletingAnAdoptedVaultNeverDeletesTheBucketsData) {
    const auto keyId = awsKey(superUser);
    const auto name = bucketName();
    seedBucket(name, {{"other-app.txt", 3}});
    const auto vault = s3Vault(keyId, name, up::Provision{.mode = up::BucketMode::Adopt, .accept_adoption = true});
    ASSERT_TRUE(vault);
    EXPECT_THROW((void)ops::vaults::remove(superUser, {.id = vault->id, .delete_upstream = true, .accept_key_loss = true}),
                 ops::Invalid);
    EXPECT_NO_THROW((void)ops::vaults::remove(superUser, {.id = vault->id, .accept_key_loss = true}));
    EXPECT_THROW((void)ops::vaults::remove(superUser, {.id = vault->id, .now = true, .delete_upstream = true,
                                                       .confirm_now = true, .accept_key_loss = true}),
                 ops::Invalid) << "not by switching it on later either";
    EXPECT_EQ(objectCount(name), 1u);
}

TEST_F(UpstreamOpsTest, OwnershipWritesFollowTheOperationToken) {
    namespace m = storage::upstream::model;
    using BQ = db::query::upstream::Bucket;
    const auto keyId = awsKey(superUser);
    const auto name = bucketName();
    const auto ticket = up::beginProvision(superUser, keyId, "v", name, {.mode = up::BucketMode::Create});
    EXPECT_FALSE(BQ::setOwnership(ticket.upstream_bucket_id, m::Ownership::Unmanaged, m::ProvisioningState::Failed,
                                  std::string("stale-token")));
    EXPECT_EQ(rowOf(name)->ownership, m::Ownership::Managed);
    EXPECT_TRUE(BQ::setOwnership(ticket.upstream_bucket_id, m::Ownership::Managed, m::ProvisioningState::Ready,
                                 ticket.operation_token));
}

TEST_F(UpstreamOpsTest, ProvisioningWithLifecycleOrEventsNeedsConfigure) {
    const auto keyId = awsKey(superUser);
    const auto roleName = "up_provisioner_" + tag();
    (void)ops::roles::createAdminRole(superUser, {.name = roleName, .permissions = {.changes = {
        {"admin.upstream.view", true}, {"admin.upstream.provision", true},
        {"admin.keys.api.admin.view", true}, {"admin.keys.api.admin.consume", true}}}}, "test");
    const auto provisioner = createUser("up_provisioner", roleName);

    EXPECT_THROW((void)up::beginProvision(provisioner, keyId, "v", bucketName(),
                                          {.mode = up::BucketMode::Create,
                                           .lifecycle = up::LifecyclePatch{.abort_incomplete_multipart_days = 3}}),
                 ops::Denied);
    EXPECT_THROW((void)up::beginProvision(provisioner, keyId, "v", bucketName(), {.mode = up::BucketMode::Create, .events = true}),
                 ops::Denied);
    EXPECT_NO_THROW((void)up::beginProvision(provisioner, keyId, "v", bucketName(), {.mode = up::BucketMode::Create}));
}

TEST_F(UpstreamOpsTest, RepointingAnAdministrativeKeyTurnsAdministrationOff) {
    const auto keyId = awsKey(superUser);
    ASSERT_TRUE(db::query::vault::APIKey::getAPIKey(keyId)->admin_enabled);
    (void)ops::api_keys::update(superUser, keyId, {.endpoint = std::string("https://s3.eu-west-1.amazonaws.com")});
    const auto key = db::query::vault::APIKey::getAPIKey(keyId);
    EXPECT_FALSE(key->admin_enabled);
    EXPECT_FALSE(key->provider_account_id);
    EXPECT_FALSE(key->admin_capabilities_json);
    EXPECT_FALSE(key->hasProviderToken());

    // While it operates an event channel, it can't be repointed at all.
    const auto busyKey = awsKey(superUser);
    const auto bucket = db::query::upstream::Bucket::protect({.provider = "aws-s3", .account_ref = kAccount, .bucket = bucketName()},
                                                             std::nullopt, std::nullopt, std::nullopt, "fixture");
    (void)db::query::upstream::Bucket::unprotect(bucket.identity());
    storage::upstream::guard::reload();
    const auto channel = db::query::upstream::Channel::getOrCreate("aws-s3", kAccount, "us-east-2",
                                                                   "vaulthalla-events-us-east-2-" + tag(), busyKey);
    const auto vault = s3Vault(busyKey, bucketName());
    const auto sub = db::query::upstream::Subscription::create(channel.id, bucket.id, vault->id, "",
                                                               storage::upstream::model::ForeignObjects::Import,
                                                               storage::upstream::model::BaselineState::None);
    ASSERT_TRUE(sub);
    db::query::upstream::Subscription::setState(sub->id, storage::upstream::model::SubscriptionState::Active, std::nullopt);
    EXPECT_THROW((void)ops::api_keys::update(superUser, busyKey, {.access_key = std::string("AKIAOTHERACCESSKEY01")}),
                 ops::Conflict);
    EXPECT_TRUE(db::query::vault::APIKey::getAPIKey(busyKey)->admin_enabled);
    EXPECT_NO_THROW((void)ops::api_keys::update(superUser, busyKey, {.name = std::string("renamed-" + tag())}))
        << "a rename doesn't move the key anywhere";
    db::query::upstream::Subscription::setState(sub->id, storage::upstream::model::SubscriptionState::Removed, std::nullopt);
}

TEST_F(UpstreamOpsTest, TheAuditLogShowsOnlyKeysTheReaderMayView) {
    const auto keyId = awsKey(superUser);
    const auto name = bucketName();
    seedBucket(name);
    (void)up::protect(superUser, keyId, name, "audit fixture");
    (void)up::unprotect(superUser, keyId, name, true);
    EXPECT_GE(up::audit(superUser, {.bucket = name}).size(), 2u);

    const auto roleName = "up_auditor_" + tag();
    (void)ops::roles::createAdminRole(superUser, {.name = roleName, .permissions = {.changes = {
        {"admin.upstream.view", true}}}}, "test");
    const auto reader = createUser("up_reader", roleName);
    EXPECT_TRUE(up::audit(reader, {.bucket = name}).empty())
        << "admin.upstream.view alone doesn't reveal the buckets and accounts of keys the reader can't see";
}

}
