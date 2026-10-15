// Upstream control plane persistence (#237, #96): upstream_bucket identity, the create/adopt leases, hard protection
// keyed to (provider, account, bucket), the audit log, event channels/subscriptions, the durable inbox and write
// intents, and the admin columns on API keys. DB-backed; skipped without the VH_TEST_DB_* environment.

#include "../helpers/identities.hpp"
#include "db/Transactions.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/upstream/Audit.hpp"
#include "db/query/upstream/Bucket.hpp"
#include "db/query/upstream/Channel.hpp"
#include "db/query/upstream/Inbox.hpp"
#include "db/query/upstream/Subscription.hpp"
#include "db/query/upstream/WriteIntent.hpp"
#include "db/query/vault/APIKey.hpp"
#include "fs/Filesystem.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Vaults.hpp"
#include "rbac/role/Admin.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Manager.hpp"
#include "storage/upstream/Guard.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <future>
#include <iostream>
#include <memory>
#include <string>

namespace vh::test_upstream_store {

namespace q = db::query::upstream;
namespace m = storage::upstream::model;
using storage::upstream::BucketIdentity;
using UserPtr = std::shared_ptr<identities::User>;

std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(n.fetch_add(1));
}

// A 32-hex R2 account id and the endpoint that encodes it.
constexpr const char* kR2Account = "0123456789abcdef0123456789abcdef";
const std::string kR2Endpoint = std::string("https://") + kR2Account + ".r2.cloudflarestorage.com";

class UpstreamStoreTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static UserPtr superUser;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_upstream_store] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = std::filesystem::temp_directory_path() / ("vh_upstream_store_" + tag());
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

        auto user = vh::test::identities::createUser("us_super_" + tag(), db::query::rbac::role::Admin::get("super_admin"),
                                                     "us_super@vaulthalla.test", "x", std::nullopt);
        superUser = vh::identities::manager().user(user->id);
    }

    // The protection set is process-wide: leave it unloaded for the suites that run after this one.
    static void TearDownTestSuite() { storage::upstream::guard::clearForTesting(); }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        storage::upstream::guard::clearForTesting();
    }

    static std::shared_ptr<vault::model::APIKey> addKey(const vault::model::S3Provider provider, const std::string& endpoint,
                                                        const std::optional<std::string>& accountRef = std::nullopt) {
        auto key = std::make_shared<vault::model::APIKey>(superUser->id, "us_key_" + tag(), provider,
                                                          "AKIAEXAMPLE" + tag(), "secret-value-" + tag(), "auto", endpoint);
        const auto id = runtime::Deps::get().apiKeyManager->addAPIKey(key);
        if (accountRef) runtime::Deps::get().apiKeyManager->setAccountRef(id, accountRef);
        return runtime::Deps::get().apiKeyManager->getAPIKey(id);
    }

    static uint32_t addVault() {
        return ops::vaults::create(superUser, {.name = "us_vault_" + tag(), .type = vault::model::VaultType::Local})->id;
    }

    static BucketIdentity r2(const std::string& bucket) {
        return {.provider = "cloudflare-r2", .account_ref = kR2Account, .bucket = bucket};
    }

    static m::InboxEvent event(const uint32_t vaultId, const std::string& key, const std::string& dedupe,
                               const std::optional<std::string>& sequencer = std::nullopt, const std::time_t at = 1000) {
        m::InboxEvent e;
        e.vault_id = vaultId;
        e.provider = "aws-s3";
        e.account_ref = "123456789012";
        e.bucket = "inbox-bucket";
        e.object_key = key;
        e.event_name = "ObjectCreated:Put";
        e.dedupe_key = dedupe;
        e.sequencer = sequencer;
        e.event_time = at;
        e.origin = m::InboxOrigin::External;
        return e;
    }
};

// ---- buckets -------------------------------------------------------------------------------------------------------

TEST_F(UpstreamStoreTest, IdentityIsUniqueAndListingNeverChangesOwnershipOrLocks) {
    const auto name = "seen-" + tag();
    q::Bucket::recordSeen("cloudflare-r2", kR2Account, std::nullopt, {{.bucket = name, .region = "wnam"}});
    q::Bucket::recordSeen("cloudflare-r2", kR2Account, std::nullopt, {{.bucket = name, .region = std::nullopt}});
    const auto row = q::Bucket::getByIdentity("cloudflare-r2", kR2Account, name);
    ASSERT_TRUE(row);
    EXPECT_EQ(row->ownership, m::Ownership::Unmanaged);
    EXPECT_EQ(row->region, std::optional<std::string>("wnam")) << "a listing without a region keeps the known one";
    EXPECT_TRUE(row->discovered_at && row->last_seen_at);

    (void)q::Bucket::protect(r2(name), std::nullopt, superUser->id, superUser->name(), "prod data");
    q::Bucket::recordSeen("cloudflare-r2", kR2Account, std::nullopt, {{.bucket = name}});
    const auto after = q::Bucket::getByIdentity("cloudflare-r2", kR2Account, name);
    ASSERT_TRUE(after);
    EXPECT_EQ(after->id, row->id);
    EXPECT_TRUE(after->is_protected);
    EXPECT_EQ(after->ownership, m::Ownership::Unmanaged);

    // Same name in another account is another bucket.
    q::Bucket::recordSeen("cloudflare-r2", "ffffffffffffffffffffffffffffffff", std::nullopt, {{.bucket = name}});
    const auto mine = q::Bucket::listForAccount("cloudflare-r2", kR2Account);
    EXPECT_EQ(std::ranges::count_if(mine, [&](const auto& b) { return b.bucket == name; }), 1);
    EXPECT_NE(q::Bucket::getByIdentity("cloudflare-r2", "ffffffffffffffffffffffffffffffff", name)->id, row->id);
}

TEST_F(UpstreamStoreTest, WritesRefuseAnIdentityWithoutAccount) {
    const BucketIdentity unresolved{.provider = "aws-s3", .account_ref = std::nullopt, .bucket = "x-" + tag()};
    EXPECT_THROW((void)q::Bucket::claimForCreate(unresolved, std::nullopt, std::nullopt, "t"), std::invalid_argument);
    EXPECT_THROW((void)q::Bucket::protect(unresolved, std::nullopt, std::nullopt, std::nullopt, "r"), std::invalid_argument);
}

TEST_F(UpstreamStoreTest, CreateClaimHasExactlyOneWinnerUnderARace) {
    const auto id = r2("race-" + tag());
    auto a = std::async(std::launch::async, [&] { return q::Bucket::claimForCreate(id, std::nullopt, std::nullopt, "token-a"); });
    auto b = std::async(std::launch::async, [&] { return q::Bucket::claimForCreate(id, std::nullopt, std::nullopt, "token-b"); });
    const auto ra = a.get(), rb = b.get();
    EXPECT_NE(ra.has_value(), rb.has_value()) << "exactly one creator may hold the lease";
    const auto& winner = ra ? *ra : *rb;
    EXPECT_FALSE(winner.reclaimed);
    // A claim claims nothing about the bucket (data-safety review #1): unmanaged and not created by Vaulthalla until
    // CreateBucket succeeded and the bucket listed empty.
    EXPECT_EQ(winner.bucket.ownership, m::Ownership::Unmanaged);
    EXPECT_EQ(winner.bucket.provisioning_state, m::ProvisioningState::Creating);
    EXPECT_FALSE(winner.bucket.created_by_vaulthalla);
    EXPECT_TRUE(winner.bucket.provision_attempted);
    EXPECT_FALSE(q::Bucket::confirmCreated(winner.bucket.id, "not-the-token"));
    ASSERT_TRUE(q::Bucket::confirmCreated(winner.bucket.id, *winner.bucket.operation_token));
    const auto confirmed = q::Bucket::get(winner.bucket.id);
    EXPECT_EQ(confirmed->ownership, m::Ownership::Managed);
    EXPECT_TRUE(confirmed->created_by_vaulthalla);

    // A third attempt while the winner is live loses too.
    EXPECT_FALSE(q::Bucket::claimForCreate(id, std::nullopt, std::nullopt, "token-c"));
}

TEST_F(UpstreamStoreTest, OurOwnFailedAttemptIsReclaimedButKnownBucketsAreNot) {
    const auto id = r2("retry-" + tag());
    const auto first = q::Bucket::claimForCreate(id, "wnam", std::nullopt, "t1");
    ASSERT_TRUE(first);
    EXPECT_FALSE(q::Bucket::setProvisioningState(first->bucket.id, m::ProvisioningState::Failed, "wrong-token", "boom"))
        << "the CAS refuses a stale token";
    ASSERT_TRUE(q::Bucket::setProvisioningState(first->bucket.id, m::ProvisioningState::Failed, "t1", "boom"));

    const auto retry = q::Bucket::claimForCreate(id, std::nullopt, std::nullopt, "t2");
    ASSERT_TRUE(retry);
    EXPECT_TRUE(retry->reclaimed);
    EXPECT_EQ(retry->bucket.id, first->bucket.id);
    EXPECT_EQ(retry->bucket.operation_token, std::optional<std::string>("t2"));
    EXPECT_FALSE(retry->bucket.last_error);
    EXPECT_EQ(retry->bucket.region, std::optional<std::string>("wnam"));

    // A bucket a listing found (existing, not ours) is never claimable through the create path.
    const auto seen = "known-" + tag();
    q::Bucket::recordSeen("cloudflare-r2", kR2Account, std::nullopt, {{.bucket = seen}});
    EXPECT_FALSE(q::Bucket::claimForCreate(r2(seen), std::nullopt, std::nullopt, "t3"));

    // Ours but bound to a vault, or locked: not claimable either.
    const auto boundId = r2("bound-" + tag());
    const auto bound = q::Bucket::claimForCreate(boundId, std::nullopt, std::nullopt, "t4");
    ASSERT_TRUE(bound);
    ASSERT_TRUE(q::Bucket::setProvisioningState(bound->bucket.id, m::ProvisioningState::Failed, "t4"));
    q::Bucket::bindVault(bound->bucket.id, addVault(), m::Ownership::Managed);
    EXPECT_FALSE(q::Bucket::claimForCreate(boundId, std::nullopt, std::nullopt, "t5"));

    const auto lockedId = r2("locked-" + tag());
    const auto locked = q::Bucket::claimForCreate(lockedId, std::nullopt, std::nullopt, "t6");
    ASSERT_TRUE(locked);
    ASSERT_TRUE(q::Bucket::setProvisioningState(locked->bucket.id, m::ProvisioningState::Failed, "t6"));
    (void)q::Bucket::protect(lockedId, std::nullopt, superUser->id, superUser->name(), "hands off");
    EXPECT_FALSE(q::Bucket::claimForCreate(lockedId, std::nullopt, std::nullopt, "t7"));
}

TEST_F(UpstreamStoreTest, AdoptionRefusesLockedBoundAndBusyBuckets) {
    const auto fresh = r2("adopt-" + tag());
    const auto adopted = q::Bucket::upsertAdopted(fresh, "enam", std::nullopt, "a1");
    ASSERT_EQ(adopted.result, q::AdoptResult::Adopted);
    ASSERT_TRUE(adopted.bucket);
    EXPECT_EQ(adopted.bucket->ownership, m::Ownership::Adopted);
    EXPECT_EQ(adopted.bucket->provisioning_state, m::ProvisioningState::Configuring);
    EXPECT_FALSE(adopted.bucket->created_by_vaulthalla);

    // Another attempt while ours is configuring: busy. Ours again: fine (idempotent retry).
    EXPECT_EQ(q::Bucket::upsertAdopted(fresh, std::nullopt, std::nullopt, "a2").result, q::AdoptResult::Busy);
    EXPECT_EQ(q::Bucket::upsertAdopted(fresh, std::nullopt, std::nullopt, "a1").result, q::AdoptResult::Adopted);

    q::Bucket::bindVault(adopted.bucket->id, addVault(), m::Ownership::Adopted);
    EXPECT_EQ(q::Bucket::upsertAdopted(fresh, std::nullopt, std::nullopt, "a3").result, q::AdoptResult::BoundElsewhere);

    const auto locked = r2("adopt-locked-" + tag());
    (void)q::Bucket::protect(locked, std::nullopt, superUser->id, superUser->name(), "no");
    const auto refused = q::Bucket::upsertAdopted(locked, std::nullopt, std::nullopt, "a4");
    EXPECT_EQ(refused.result, q::AdoptResult::Protected);
    ASSERT_TRUE(refused.bucket);
    EXPECT_EQ(refused.bucket->provisioning_state, m::ProvisioningState::None) << "a refusal changes nothing";

    // Adopting a managed bucket of ours (unbound) keeps it managed.
    const auto mine = r2("adopt-mine-" + tag());
    const auto claim = q::Bucket::claimForCreate(mine, std::nullopt, std::nullopt, "c1");
    ASSERT_TRUE(claim);
    ASSERT_TRUE(q::Bucket::confirmCreated(claim->bucket.id, "c1"));
    ASSERT_TRUE(q::Bucket::setProvisioningState(claim->bucket.id, m::ProvisioningState::Ready, "c1"));
    const auto again = q::Bucket::upsertAdopted(mine, std::nullopt, std::nullopt, "a5");
    ASSERT_EQ(again.result, q::AdoptResult::Adopted);
    EXPECT_EQ(again.bucket->ownership, m::Ownership::Managed);
}

TEST_F(UpstreamStoreTest, ProtectIsIdempotentAndUnprotectClearsTheLock) {
    const auto id = r2("lock-" + tag());
    const auto first = q::Bucket::protect(id, std::nullopt, superUser->id, superUser->name(), "reason one");
    EXPECT_TRUE(first.is_protected);
    EXPECT_EQ(first.protection_reason, std::optional<std::string>("reason one"));
    const auto second = q::Bucket::protect(id, std::nullopt, superUser->id, superUser->name(), "reason two");
    EXPECT_EQ(second.id, first.id);
    EXPECT_EQ(second.protected_at, first.protected_at) << "re-protecting keeps the original lock time";
    EXPECT_EQ(second.protection_reason, std::optional<std::string>("reason two"));
    EXPECT_EQ(q::Bucket::findProtectedByName("cloudflare-r2", id.bucket).size(), 1u);

    const auto cleared = q::Bucket::unprotect(id);
    ASSERT_TRUE(cleared);
    EXPECT_FALSE(cleared->is_protected);
    EXPECT_FALSE(cleared->protection_reason);
    EXPECT_TRUE(q::Bucket::findProtectedByName("cloudflare-r2", id.bucket).empty());
    EXPECT_FALSE(q::Bucket::unprotect(r2("never-known-" + tag())));
}

TEST_F(UpstreamStoreTest, ProtectionFollowsTheBucketIdentityNotTheApiKey) {
    const auto bucket = "keyed-" + tag();
    auto key = addKey(vault::model::S3Provider::CloudflareR2, kR2Endpoint);
    const auto id = storage::upstream::identityFor(*key, bucket);
    ASSERT_EQ(id.account_ref, std::optional<std::string>(kR2Account)) << "R2 accounts come from the endpoint";

    (void)q::Bucket::protect(id, std::nullopt, superUser->id, superUser->name(), "survives keys");
    storage::upstream::guard::reload();
    EXPECT_TRUE(storage::upstream::guard::isProtected(id));

    // Delete the key and register a new one for the same account: the lock still applies.
    runtime::Deps::get().apiKeyManager->removeAPIKey(key->id);
    const auto replacement = addKey(vault::model::S3Provider::CloudflareR2, kR2Endpoint);
    storage::upstream::guard::reload();
    EXPECT_TRUE(storage::upstream::guard::isProtected(storage::upstream::identityFor(*replacement, bucket)));
    EXPECT_THROW(storage::upstream::guard::require(*replacement, bucket), storage::upstream::BucketProtected);
    EXPECT_FALSE(storage::upstream::guard::isProtected(storage::upstream::identityFor(*replacement, bucket + "-other")));

    // AWS: a key whose account is not resolved yet fails closed on any lock with that name; a key known to belong
    // to another account is not blocked.
    const auto awsBucket = "aws-keyed-" + tag();
    (void)q::Bucket::protect({.provider = "aws-s3", .account_ref = "111111111111", .bucket = awsBucket}, "us-east-2",
                             superUser->id, superUser->name(), "aws lock");
    storage::upstream::guard::reload();
    const auto unresolved = addKey(vault::model::S3Provider::AWS, "https://s3.us-east-2.amazonaws.com");
    EXPECT_TRUE(storage::upstream::guard::isProtected(storage::upstream::identityFor(*unresolved, awsBucket)));
    const auto otherAccount = addKey(vault::model::S3Provider::AWS, "https://s3.us-east-2.amazonaws.com", "222222222222");
    EXPECT_FALSE(storage::upstream::guard::isProtected(storage::upstream::identityFor(*otherAccount, awsBucket)));
    const auto sameAccount = addKey(vault::model::S3Provider::AWS, "https://s3.us-east-2.amazonaws.com", "111111111111");
    EXPECT_TRUE(storage::upstream::guard::isProtected(storage::upstream::identityFor(*sameAccount, awsBucket)));

    (void)q::Bucket::unprotect(id);
    storage::upstream::guard::reload();
    EXPECT_FALSE(storage::upstream::guard::isProtected(id));
}

TEST_F(UpstreamStoreTest, StaleProvisioningIsListedForRecovery) {
    const auto id = r2("stale-" + tag());
    const auto claim = q::Bucket::claimForCreate(id, std::nullopt, std::nullopt, "s1");
    ASSERT_TRUE(claim);
    db::Transactions::exec("test::age", [&](pqxx::work& txn) {
        txn.exec("UPDATE upstream_bucket SET updated_at = CURRENT_TIMESTAMP - INTERVAL '1 hour' WHERE id = $1",
                 pqxx::params{claim->bucket.id});
    });
    const auto stale = q::Bucket::listStaleProvisioning(std::chrono::minutes(15));
    EXPECT_TRUE(std::ranges::any_of(stale, [&](const auto& b) { return b.id == claim->bucket.id; }));
    // An abandoned creating row of ours can be re-claimed.
    const auto retry = q::Bucket::claimForCreate(id, std::nullopt, std::nullopt, "s2");
    ASSERT_TRUE(retry);
    EXPECT_TRUE(retry->reclaimed);
}

// ---- audit ---------------------------------------------------------------------------------------------------------

TEST_F(UpstreamStoreTest, AuditIsAppendOnlyNewestFirstAndFilterable) {
    const auto bucket = "audited-" + tag();
    m::AuditRecord r;
    r.user_id = superUser->id;
    r.user_name = superUser->name();
    r.action = "protect";
    r.provider = "cloudflare-r2";
    r.account_ref = kR2Account;
    r.bucket = bucket;
    r.detail_json = R"({"reason":"x"})";
    const auto first = q::Audit::append(r);
    r.action = "unprotect";
    r.outcome = m::AuditOutcome::Refused;
    r.detail_json = "not json";    // wrapped, never lost
    const auto second = q::Audit::append(r);
    EXPECT_GT(second, first);

    const auto rows = q::Audit::list(bucket, 10);
    ASSERT_EQ(rows.size(), 2u);
    EXPECT_EQ(rows[0].action, "unprotect");
    EXPECT_EQ(rows[0].outcome, m::AuditOutcome::Refused);
    EXPECT_EQ(nlohmann::json::parse(rows[0].detail_json).at("detail"), "not json");
    EXPECT_EQ(nlohmann::json::parse(rows[1].detail_json).at("reason"), "x");
    EXPECT_EQ(rows[1].user_name, std::optional<std::string>(superUser->name()));

    // A best-effort write to a vault that doesn't exist (FK) is swallowed.
    r.vault_id = 999999;
    EXPECT_NO_THROW(q::Audit::appendNoThrow(r));
    EXPECT_EQ(q::Audit::list(bucket, 10).size(), 2u);
}

// ---- inbox ---------------------------------------------------------------------------------------------------------

TEST_F(UpstreamStoreTest, InboxDeduplicatesAndOrdersByKeyThenNumericSequencer) {
    const auto vaultId = addVault();
    const auto p = "inbox-" + tag() + "/";
    EXPECT_EQ(q::Inbox::insertMany({event(vaultId, p + "b", p + "d1", "A"), event(vaultId, p + "b", p + "d2", "9"),
                                    event(vaultId, p + "b", p + "d3", "10"), event(vaultId, p + "a", p + "d4")}),
              4u);
    EXPECT_EQ(q::Inbox::insertMany({event(vaultId, p + "b", p + "d1", "A")}), 0u) << "redelivery is a no-op";

    const auto claimed = q::Inbox::claimForVault(vaultId, 100);
    ASSERT_EQ(claimed.size(), 4u);
    EXPECT_EQ(claimed[0].object_key, p + "a");
    EXPECT_EQ(claimed[1].sequencer, std::optional<std::string>("9"));
    EXPECT_EQ(claimed[2].sequencer, std::optional<std::string>("A"));
    EXPECT_EQ(claimed[3].sequencer, std::optional<std::string>("10")) << "hex 0x10 sorts after 0xA";

    const auto latest = q::Inbox::latestForKey(vaultId, p + "b");
    ASSERT_TRUE(latest);
    EXPECT_EQ(latest->dedupe_key, p + "d3");
}

TEST_F(UpstreamStoreTest, InboxTransitionsCountsRetriesAndSweep) {
    const auto vaultId = addVault();
    const auto p = "states-" + tag() + "/";
    ASSERT_EQ(q::Inbox::insertMany({event(vaultId, p + "1", p + "a"), event(vaultId, p + "2", p + "b"),
                                    event(vaultId, p + "3", p + "c"), event(vaultId, p + "4", p + "d")}),
              4u);
    auto rows = q::Inbox::claimForVault(vaultId, 10);
    ASSERT_EQ(rows.size(), 4u);

    q::Inbox::markApplied({rows[0].id, rows[1].id});
    q::Inbox::markSkipped({rows[2].id}, "own write", m::InboxOrigin::Self);
    q::Inbox::markFailed(rows[3].id, "transient", std::time(nullptr) + 3600);   // retried later: not due now

    EXPECT_TRUE(q::Inbox::claimForVault(vaultId, 10).empty()) << "a backed-off retry is not due";
    auto counts = q::Inbox::counts(vaultId);
    EXPECT_EQ(counts.pending, 1u);
    EXPECT_EQ(counts.applied, 2u);
    EXPECT_EQ(counts.self_24h, 1u);
    EXPECT_EQ(counts.last_event_at, std::optional<std::time_t>(1000));

    EXPECT_EQ(q::Inbox::listApplied(vaultId, 10).size(), 2u);
    q::Inbox::requeueApplied(vaultId, {rows[0].id}, std::time(nullptr) + 3600, "pass failed");
    const auto due = q::Inbox::listApplied(vaultId, 10);
    ASSERT_EQ(due.size(), 1u);
    EXPECT_EQ(due[0].id, rows[1].id);
    q::Inbox::markDone({rows[1].id});

    q::Inbox::markFailed(rows[3].id, "permanent", std::nullopt);
    counts = q::Inbox::counts(vaultId);
    EXPECT_EQ(counts.failed, 1u);
    EXPECT_EQ(counts.pending, 0u);
    EXPECT_EQ(counts.done_24h, 1u);

    EXPECT_EQ(std::ranges::count(q::Inbox::listVaultsWithWork(), vaultId), 0) << "only backed-off work is left";

    EXPECT_GE(q::Inbox::sweepFinished(std::chrono::seconds(0)), 2u);   // the done and the skipped row
    counts = q::Inbox::counts(vaultId);
    EXPECT_EQ(counts.done_24h, 0u);
    EXPECT_EQ(counts.applied, 1u) << "unfinished work is never swept";
}

TEST_F(UpstreamStoreTest, EventsReceivedBeforeRoutingAreAssignedLater) {
    const auto vaultId = addVault();
    auto e = event(vaultId, "early/key", "early-" + tag());
    e.vault_id.reset();
    e.bucket = "routing-" + tag();
    ASSERT_EQ(q::Inbox::insertMany({e}), 1u);
    EXPECT_TRUE(q::Inbox::claimForVault(vaultId, 10).empty());

    const auto bucket = q::Bucket::upsertAdopted({.provider = e.provider, .account_ref = e.account_ref, .bucket = e.bucket},
                                                 std::nullopt, std::nullopt, "r1");
    ASSERT_TRUE(bucket.bucket);
    const auto sub = q::Subscription::create(std::nullopt, bucket.bucket->id, vaultId, "", m::ForeignObjects::Import,
                                             m::BaselineState::Pending);
    ASSERT_TRUE(sub);
    EXPECT_EQ(q::Inbox::routeUnassigned(e.provider, e.account_ref, e.bucket, vaultId, sub->id), 1u);
    const auto routed = q::Inbox::claimForVault(vaultId, 10);
    ASSERT_EQ(routed.size(), 1u);
    EXPECT_EQ(routed[0].subscription_id, std::optional<int64_t>(sub->id));
}

// ---- write intents -------------------------------------------------------------------------------------------------

TEST_F(UpstreamStoreTest, WriteIntentsMatchOnceByKeyOpSizeAndTime) {
    const auto vaultId = addVault();
    const auto key = "intent/" + tag();
    const auto now = std::time(nullptr);
    (void)q::WriteIntent::record(vaultId, key, m::WriteOp::Put, 100);

    EXPECT_FALSE(q::WriteIntent::consumeMatching(vaultId, key, m::WriteOp::Delete, std::nullopt, now)) << "wrong op";
    EXPECT_FALSE(q::WriteIntent::consumeMatching(vaultId, key, m::WriteOp::Put, 101, now)) << "wrong size";
    EXPECT_FALSE(q::WriteIntent::consumeMatching(vaultId, key, m::WriteOp::Put, 100, now - 3600))
        << "an event older than the intent is not the write it announced";
    EXPECT_FALSE(q::WriteIntent::consumeMatching(vaultId, key + "x", m::WriteOp::Put, 100, now)) << "wrong key";
    EXPECT_TRUE(q::WriteIntent::consumeMatching(vaultId, key, m::WriteOp::Put, 100, now));
    EXPECT_FALSE(q::WriteIntent::consumeMatching(vaultId, key, m::WriteOp::Put, 100, now)) << "consumed exactly once";

    // Unknown sizes match; deletes carry none.
    (void)q::WriteIntent::record(vaultId, key, m::WriteOp::Delete, std::nullopt);
    EXPECT_TRUE(q::WriteIntent::consumeMatching(vaultId, key, m::WriteOp::Delete, std::nullopt, now + 1));

    // Expired intents never match and are swept.
    (void)q::WriteIntent::record(vaultId, key, m::WriteOp::Put, 5, std::chrono::seconds(0));
    EXPECT_FALSE(q::WriteIntent::consumeMatching(vaultId, key, m::WriteOp::Put, 5, std::time(nullptr)));
    EXPECT_GE(q::WriteIntent::sweepExpired(), 1u);
}

// ---- channels and subscriptions -------------------------------------------------------------------------------------

TEST_F(UpstreamStoreTest, ChannelBookkeepingDegradesAfterRepeatedFailuresAndRecovers) {
    auto key = addKey(vault::model::S3Provider::AWS, "https://s3.us-east-2.amazonaws.com", "123456789012");
    const auto queue = "vaulthalla-test-" + tag();
    const auto c = q::Channel::getOrCreate("aws-s3", "123456789012", "us-east-2", queue, key->id);
    EXPECT_EQ(c.state, m::ChannelState::Provisioning);
    EXPECT_EQ(q::Channel::getOrCreate("aws-s3", "123456789012", "us-east-2", queue, std::nullopt).id, c.id);
    q::Channel::updateRefs(c.id, "https://sqs.example/q", "arn:aws:sqs:us-east-2:123456789012:" + queue, "dlq", "dlq-arn",
                           true, m::ChannelState::Active);

    // Pollable only while a subscription wants it.
    EXPECT_FALSE(std::ranges::any_of(q::Channel::listPollable(), [&](const auto& x) { return x.id == c.id; }));
    const auto bucket = q::Bucket::upsertAdopted({.provider = "aws-s3", .account_ref = "123456789012", .bucket = "ch-" + tag()},
                                                 "us-east-2", key->id, "ch");
    const auto vaultId = addVault();
    const auto sub = q::Subscription::create(c.id, bucket.bucket->id, vaultId, "", m::ForeignObjects::Import,
                                             m::BaselineState::None);
    ASSERT_TRUE(sub);
    EXPECT_TRUE(std::ranges::any_of(q::Channel::listPollable(), [&](const auto& x) { return x.id == c.id; }));
    EXPECT_EQ(q::Channel::countSubscriptions(c.id, {m::SubscriptionState::Pending, m::SubscriptionState::Active}), 1u);
    EXPECT_EQ(q::Subscription::countActiveUsingKey(key->id), 1u);

    for (int i = 0; i < 3; ++i) q::Channel::recordPoll(c.id, false, 0, std::nullopt, "AccessDenied", std::nullopt);
    auto now = q::Channel::get(c.id);
    ASSERT_TRUE(now);
    EXPECT_EQ(now->state, m::ChannelState::Degraded);
    EXPECT_EQ(now->consecutive_failures, 3u);
    EXPECT_EQ(now->last_error, std::optional<std::string>("AccessDenied"));

    q::Channel::recordPoll(c.id, true, 4, 12, std::nullopt, std::time(nullptr) + 20);
    now = q::Channel::get(c.id);
    EXPECT_EQ(now->state, m::ChannelState::Active);
    EXPECT_EQ(now->consecutive_failures, 0u);
    EXPECT_EQ(now->backlog_estimate, std::optional<uint64_t>(12));
    EXPECT_TRUE(now->last_message_at && now->last_success_at && now->next_poll_at);

    q::Channel::setState(c.id, m::ChannelState::Failed, "");
    EXPECT_FALSE(q::Channel::get(c.id)->last_error) << "\"\" clears the error";
    EXPECT_FALSE(q::Channel::find("aws-s3", "123456789012", "eu-west-1"));
    EXPECT_EQ(q::Channel::find("aws-s3", "123456789012", "us-east-2")->id, c.id);
}

TEST_F(UpstreamStoreTest, OneLiveSubscriptionPerVault) {
    const auto vaultId = addVault();
    const auto bucket = q::Bucket::upsertAdopted(r2("sub-" + tag()), std::nullopt, std::nullopt, "s");
    ASSERT_TRUE(bucket.bucket);
    const auto first = q::Subscription::create(std::nullopt, bucket.bucket->id, vaultId, "photos/",
                                               m::ForeignObjects::Ignore, m::BaselineState::Pending);
    ASSERT_TRUE(first);
    EXPECT_EQ(first->foreign_objects, m::ForeignObjects::Ignore);
    EXPECT_FALSE(q::Subscription::create(std::nullopt, bucket.bucket->id, vaultId, "", m::ForeignObjects::Import,
                                         m::BaselineState::None))
        << "a second live subscription for the vault is refused";

    q::Subscription::setRuleIds(first->id, {"vaulthalla-1", "vaulthalla-1b"});
    q::Subscription::setState(first->id, m::SubscriptionState::Active, "");
    q::Subscription::setBaseline(first->id, m::BaselineState::Running, 1700000000);
    q::Subscription::setForeignRules(first->id, 2);
    const auto live = q::Subscription::getLiveForVault(vaultId);
    ASSERT_TRUE(live);
    EXPECT_EQ(live->rule_ids, (std::vector<std::string>{"vaulthalla-1", "vaulthalla-1b"}));
    EXPECT_TRUE(live->activated_at);
    EXPECT_EQ(live->baseline_state, m::BaselineState::Running);
    EXPECT_EQ(live->baseline_started_at, std::optional<std::time_t>(1700000000));
    EXPECT_EQ(live->foreign_rules, 2u);
    EXPECT_EQ(std::ranges::count(q::Subscription::listActiveVaultIds(), vaultId), 1);
    EXPECT_EQ(q::Subscription::listLiveForBucket("cloudflare-r2", kR2Account, bucket.bucket->bucket).size(), 1u);

    q::Subscription::setState(first->id, m::SubscriptionState::Removed);
    EXPECT_FALSE(q::Subscription::getLiveForVault(vaultId));
    EXPECT_TRUE(q::Subscription::create(std::nullopt, bucket.bucket->id, vaultId, "", m::ForeignObjects::Import,
                                        m::BaselineState::None))
        << "removed rows are history; a new live one may follow";
}

// ---- the admin.upstream permission module (no DB) -------------------------------------------------------------------

TEST(UpstreamPermission, IsExportedAtStableBitsWithFlags) {
    using rbac::role::Admin;
    const std::vector<std::string> names{"view", "configure", "provision", "protect", "unprotect", "destroy"};
    std::size_t found = 0;
    for (const auto& p : Admin::None().toPermissions()) {
        if (!p.qualified_name.starts_with("admin.upstream.")) continue;
        ++found;
        const auto leaf = p.qualified_name.substr(std::string("admin.upstream.").size());
        const auto it = std::ranges::find(names, leaf);
        ASSERT_NE(it, names.end()) << p.qualified_name;
        // Persisted in admin_role.upstream_permissions (migration 110): never renumber.
        EXPECT_EQ(p.bit_position, static_cast<uint32_t>(it - names.begin())) << p.qualified_name;
        EXPECT_FALSE(p.value.value_or(false));
        EXPECT_NE(std::ranges::find(p.flags, "--allow-upstream-" + leaf), p.flags.end()) << p.qualified_name;
    }
    EXPECT_EQ(found, names.size());
}

TEST(UpstreamPermission, BuiltInGrantsMatchMigration110) {
    using rbac::role::Admin;
    // The same grants migration 110 writes on upgraded databases (MSB-first bit strings, bit 0 = view).
    EXPECT_EQ(Admin::SuperAdmin().upstream.toBitString(), "00111111");
    EXPECT_EQ(Admin::OrgAdmin().upstream.toBitString(), "00001111");
    EXPECT_EQ(Admin::PlatformOperator().upstream.toBitString(), "00001111");
    EXPECT_EQ(Admin::SecurityAdmin().upstream.toBitString(), "00001001");
    EXPECT_EQ(Admin::Auditor().upstream.toBitString(), "00000001");
    EXPECT_EQ(Admin::VaultAdmin().upstream.toBitString(), "00000001");
    for (const auto& role : {Admin::None(), Admin::Support(), Admin::IdentityAdmin(), Admin::KeyCustodian()})
        EXPECT_EQ(role.upstream.toBitString(), "00000000") << role.name;
    EXPECT_FALSE(Admin::OrgAdmin().upstream.canUnprotect());
    EXPECT_FALSE(Admin::OrgAdmin().upstream.canDestroy());
    EXPECT_TRUE(Admin::SuperAdmin().upstream.canDestroy());
}

// ---- API key admin columns -----------------------------------------------------------------------------------------

TEST_F(UpstreamStoreTest, ProviderTokenIsSealedAndNeverSerialized) {
    auto key = addKey(vault::model::S3Provider::CloudflareR2, kR2Endpoint);
    EXPECT_FALSE(key->admin_enabled);
    EXPECT_FALSE(key->hasProviderToken());

    const std::string token = "cf-token-" + tag();
    runtime::Deps::get().apiKeyManager->setProviderToken(key->id, token);
    runtime::Deps::get().apiKeyManager->setAdmin(key->id, true, kR2Account, R"({"items":[]})", 1700000000);

    const auto stored = db::query::vault::APIKey::getAPIKey(key->id);
    ASSERT_TRUE(stored);
    EXPECT_TRUE(stored->admin_enabled);
    EXPECT_EQ(stored->provider_account_id, std::optional<std::string>(kR2Account));
    EXPECT_EQ(stored->admin_validated_at, std::optional<std::time_t>(1700000000));
    ASSERT_FALSE(stored->encrypted_provider_token.empty());
    EXPECT_EQ(std::string(stored->encrypted_provider_token.begin(), stored->encrypted_provider_token.end()).find(token),
              std::string::npos)
        << "the token is never stored in plaintext";
    EXPECT_TRUE(stored->provider_token.empty()) << "a plain DB read never decrypts";

    const auto decrypted = runtime::Deps::get().apiKeyManager->getAPIKey(key->id);
    EXPECT_EQ(decrypted->provider_token, token);
    const auto json = nlohmann::json(*decrypted).dump();
    EXPECT_EQ(json.find(token), std::string::npos);
    EXPECT_TRUE(nlohmann::json::parse(json).at("has_provider_token").get<bool>());

    // Absent values keep what is stored.
    runtime::Deps::get().apiKeyManager->setAdmin(key->id, false, std::nullopt, std::nullopt, std::nullopt);
    const auto disabled = db::query::vault::APIKey::getAPIKey(key->id);
    EXPECT_FALSE(disabled->admin_enabled);
    EXPECT_EQ(disabled->provider_account_id, std::optional<std::string>(kR2Account));

    runtime::Deps::get().apiKeyManager->setProviderToken(key->id, std::nullopt);
    EXPECT_FALSE(runtime::Deps::get().apiKeyManager->getAPIKey(key->id)->hasProviderToken());
    runtime::Deps::get().apiKeyManager->setAccountRef(key->id, std::nullopt);
    EXPECT_FALSE(db::query::vault::APIKey::getAPIKey(key->id)->provider_account_id);
}

}
