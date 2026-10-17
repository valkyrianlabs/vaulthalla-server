// Provider versioning policy (ops::recovery status / update / versioningDisclosure / suspendVersioning / costs), against
// the test DB, an in-memory provider account (FakeAdmin) and the signed price-bot fixture catalog:
//  - capability: R2 (and any provider without versions) refused before anything is sent;
//  - protection: a locked bucket is refused before any provider request;
//  - ownership: an unmanaged bucket needs accept_adoption, then the admission preflight, then it is adopted;
//  - disclosure tokens bound to vault + bucket + retention + actor + catalog (missing / other retention / other actor /
//    other vault / expired refused), unpriced needs accept_unpriced, retention shortening needs its own acceptance;
//  - enabling: no PutBucketVersioning when already Enabled, bounded re-read under eventual consistency, the 15-minute
//    propagation window, Vaulthalla's retention rule + the manifest-versions rule with foreign rules kept byte for byte,
//    a shorter foreign rule reported as effective;
//  - mode away never suspends; suspension is confirmed and deletes nothing; provisioning never enables versioning;
//  - RBAC: vault sync.config.edit, admin.upstream.configure and key Consume.

#include "../helpers/recovery_pricing.hpp"
#include "../helpers/sync_conflict_harness.hpp"
#include "../helpers/upstream_admin_fakes.hpp"

#include "db/query/recovery/Policy.hpp"
#include "db/query/recovery/Usage.hpp"
#include "db/query/upstream/Audit.hpp"
#include "db/query/upstream/Bucket.hpp"
#include "ops/Recovery.hpp"
#include "ops/RecoveryJson.hpp"
#include "ops/Roles.hpp"
#include "ops/Stats.hpp"
#include "ops/Upstream.hpp"
#include "rbac/permission/admin/Upstream.hpp"
#include "rbac/permission/admin/keys/API.hpp"
#include "rbac/permission/vault/sync/Config.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "recovery/cost/Alerts.hpp"
#include "recovery/cost/Report.hpp"
#include "recovery/provider/Policy.hpp"
#include "recovery/usage/Ledger.hpp"
#include "storage/s3/provider/admin/Admin.hpp"
#include "storage/upstream/Guard.hpp"
#include "storage/upstream/Lifecycle.hpp"
#include "storage/upstream/Provisioner.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>

namespace vh::test_recovery_policy {

using namespace test_support::sync_conflicts;
using namespace test_support::upstream_admin;
namespace padmin = storage::s3::provider::admin;
namespace up = ops::upstream;
namespace rec = ops::recovery;
namespace pol = vh::recovery::provider::policy;
namespace lifecycle = storage::upstream::lifecycle;
using vh::recovery::Mode;
using vh::recovery::ProviderRetention;

const ProviderRetention k30d{.indefinite = false, .days = 30};
const ProviderRetention k60d{.indefinite = false, .days = 60};
const ProviderRetention k90d{.indefinite = false, .days = 90};
const ProviderRetention kForever{.indefinite = true, .days = 0};

// The NeedsConfirmation code fn throws ("" when it returns; other errors propagate).
template <typename Fn>
std::string confirmationCode(Fn&& fn) {
    try {
        fn();
    } catch (const ops::NeedsConfirmation& e) {
        return e.code;
    }
    return {};
}

// ---- DB-free --------------------------------------------------------------------------------------------------------

TEST(RecoveryDisclosureToken, BindsEveryFieldAndExpires) {
    const pol::TokenBinding b{.vault_id = 3, .bucket = {.provider = "aws-s3", .account_ref = "123456789012", .bucket = "b"},
                              .retention = "30d", .actor_id = 9, .estimate_digest = "abc"};
    const std::time_t now = 1792065600;
    const auto token = pol::issueToken(b, now + 600);
    EXPECT_TRUE(pol::verifyToken(token, b, now));
    EXPECT_FALSE(pol::verifyToken(token, b, now + 600)) << "expired at expires_at";
    auto other = b;
    other.retention = "90d";
    EXPECT_FALSE(pol::verifyToken(token, other, now));
    other = b;
    other.actor_id = 10;
    EXPECT_FALSE(pol::verifyToken(token, other, now));
    other = b;
    other.vault_id = 4;
    EXPECT_FALSE(pol::verifyToken(token, other, now));
    other = b;
    other.bucket.bucket = "c";
    EXPECT_FALSE(pol::verifyToken(token, other, now));
    other = b;
    other.estimate_digest = "abd";
    EXPECT_FALSE(pol::verifyToken(token, other, now));
    // A forged expiry doesn't verify (it is under the MAC).
    auto forged = token;
    forged.replace(3, std::to_string(now + 600).size(), std::to_string(now + 99999));
    EXPECT_FALSE(pol::verifyToken(forged, b, now));
    for (const auto* bad : {"", "v1.", "v1.x.y", "v2.1.abc", "garbage"}) EXPECT_FALSE(pol::verifyToken(bad, b, now)) << bad;
}

TEST(RecoveryManifestRule, AddsOnceAndKeepsEveryOtherRule) {
    padmin::LifecycleRule foreign;
    foreign.id = "other-app";
    foreign.foreign = true;
    foreign.raw_xml = "<Rule><ID>other-app</ID></Rule>";
    const auto added = lifecycle::mergeManifestRule({foreign}, true, true);
    ASSERT_EQ(added.rules.size(), 2u);
    EXPECT_TRUE(added.changed);
    EXPECT_FALSE(added.destructive) << "it only expires Vaulthalla's own index copies";
    EXPECT_EQ(added.rules[0].raw_xml, foreign.raw_xml);
    EXPECT_EQ(added.rules[1].id, lifecycle::kManifestRuleId);
    EXPECT_EQ(added.rules[1].prefix, lifecycle::kManifestRulePrefix);
    EXPECT_EQ(added.rules[1].expire_noncurrent_days.value_or(0), 1u);
    EXPECT_FALSE(lifecycle::mergeManifestRule(added.rules, true, true).changed);
    const auto removed = lifecycle::mergeManifestRule(added.rules, false, true);
    EXPECT_TRUE(removed.changed);
    ASSERT_EQ(removed.rules.size(), 1u);
    EXPECT_THROW((void)lifecycle::mergeManifestRule({}, true, false), std::invalid_argument);
}

// ---- DB-backed ------------------------------------------------------------------------------------------------------

class RecoveryPolicyTest : public Harness {
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
                if (!c->buckets.contains(bucket) || !c->buckets.at(bucket).objects.contains(key)) return std::nullopt;
                return std::unordered_map<std::string, std::string>{{"x-amz-meta-vh-encrypted", "true"}};
            });
        storage::upstream::guard::reload();
        vh::recovery::cost::setCatalogStoreForTesting(test_support::recovery_pricing::catalogStore());
        pol::setReadBackForTesting(6, std::chrono::milliseconds(0));
    }

    void TearDown() override {
        padmin::setFactoryForTesting(std::nullopt);
        storage::upstream::provision::setObjectHeadForTesting({});
        vh::recovery::cost::setCatalogStoreForTesting(nullptr);
        pol::setReadBackForTesting(6, std::chrono::milliseconds(250));
    }

    static unsigned awsKey(const UserPtr& owner = nullptr) {
        auto key = std::make_shared<vault::model::APIKey>((owner ? owner : superUser)->id, "rp_key_" + tag(),
                                                          vault::model::S3Provider::AWS, "AKIATESTACCESSKEY000",
                                                          "secret-value-0000000000000000000000000", "us-east-2",
                                                          "https://s3.us-east-2.amazonaws.com");
        const auto id = runtime::Deps::get().apiKeyManager->addAPIKey(key);
        (void)up::enableAdmin(superUser, id, {});
        return id;
    }

    static std::string bucketName() { return "vh-rp-" + tag(); }

    void seedBucket(const std::string& name, std::map<std::string, uint64_t> objects = {}) {
        std::scoped_lock lock(cloud->mutex);
        cloud->buckets[name].objects = std::move(objects);
    }

    struct V {
        uint32_t id = 0;
        unsigned keyId = 0;
        std::string bucket;
    };

    // A vault on a bucket Vaulthalla created (managed, bound).
    V managedVault(const UserPtr& owner = nullptr) {
        V v;
        v.keyId = awsKey();
        v.bucket = bucketName();
        const auto vault = ops::vaults::create(superUser, {.name = "rp_vault_" + tag(), .type = vault::model::VaultType::S3,
                                                           .owner_id = (owner ? owner : superUser)->id,
                                                           .s3 = ops::vaults::S3Spec{.api_key_id = v.keyId, .bucket = v.bucket,
                                                                                     .provision = up::Provision{.mode = up::BucketMode::Create}}});
        v.id = vault->id;
        return v;
    }

    // A vault on an existing bucket Vaulthalla doesn't manage.
    V unmanagedVault() {
        V v;
        v.keyId = awsKey();
        v.bucket = bucketName();
        seedBucket(v.bucket, {{"enc/a.txt", 5}, {"enc/b.txt", 7}});
        const auto vault = ops::vaults::create(superUser, {.name = "rp_vault_" + tag(), .type = vault::model::VaultType::S3,
                                                           .owner_id = superUser->id,
                                                           .s3 = ops::vaults::S3Spec{.api_key_id = v.keyId, .bucket = v.bucket}});
        v.id = vault->id;
        return v;
    }

    static rec::Update enableRequest(const ProviderRetention& r, const std::string& token) {
        rec::Update u;
        u.mode = Mode::ProviderVersioning;
        u.provider_retention = r;
        u.disclosure_token = token;
        return u;
    }

    static vh::recovery::Status enable(const V& v, const ProviderRetention& r, const UserPtr& actor = nullptr,
                                       const std::function<void(rec::Update&)>& tweak = {}) {
        const auto a = actor ? actor : superUser;
        const auto d = rec::versioningDisclosure(a, v.id, r);
        auto u = enableRequest(r, d.token);
        if (tweak) tweak(u);
        return rec::update(a, v.id, u);
    }

    std::vector<std::pair<std::string, padmin::Versioning>> puts() {
        std::scoped_lock lock(cloud->mutex);
        return cloud->putVersioningCalls;
    }

    unsigned versioningReads() {
        std::scoped_lock lock(cloud->mutex);
        return cloud->getVersioningCalls;
    }

    unsigned callsOn(const std::string& bucket) {
        std::scoped_lock lock(cloud->mutex);
        return cloud->bucketCalls[bucket];
    }

    std::vector<padmin::LifecycleRule> rules(const std::string& bucket) {
        std::scoped_lock lock(cloud->mutex);
        return cloud->buckets.at(bucket).lifecycle;
    }

    std::optional<unsigned int> ruleDays(const std::string& bucket, const std::string& id) {
        for (const auto& e : lifecycle::noncurrentExpirations(rules(bucket)))
            if (e.rule_id == id) return e.days;
        return std::nullopt;
    }

    static bool audited(const std::string& bucket, const std::string& action) {
        return std::ranges::any_of(db::query::upstream::Audit::list(bucket, 200),
                                   [&](const auto& r) { return r.action == action; });
    }
};

TEST_F(RecoveryPolicyTest, EnablingNeedsTheDisclosureAndRecordsThePropagationWindow) {
    const auto v = managedVault();
    EXPECT_EQ(confirmationCode([&] { (void)rec::update(superUser, v.id, enableRequest(k30d, "")); }),
              rec::VERSIONING_DISCLOSURE);
    EXPECT_EQ(confirmationCode([&] { (void)rec::update(superUser, v.id, enableRequest(k30d, "v1.1.00")); }),
              rec::VERSIONING_DISCLOSURE);
    EXPECT_TRUE(puts().empty()) << "nothing is enabled without the disclosure";

    const auto d = rec::versioningDisclosure(superUser, v.id, k30d);
    EXPECT_EQ(d.report.phase, "pre_activation");
    EXPECT_TRUE(d.report.priced) << d.report.unpriced_reason.value_or("");
    EXPECT_TRUE(d.report.catalog.verified);
    EXPECT_EQ(d.report.retention.value_or(""), "30d");
    EXPECT_EQ(d.required_acknowledgements, std::vector<std::string>{rec::VERSIONING_DISCLOSURE});
    EXPECT_GE(d.consequences.size(), 5u);
    EXPECT_GT(d.expires_at, std::time(nullptr));
    EXPECT_TRUE(puts().empty()) << "the disclosure is read-only";

    const auto before = std::time(nullptr);
    const auto st = rec::update(superUser, v.id, enableRequest(k30d, d.token));
    EXPECT_EQ(st.mode, Mode::ProviderVersioning);
    EXPECT_EQ(st.provider.status, "enabled");
    EXPECT_TRUE(st.provider.enabled_by_vaulthalla);
    EXPECT_EQ(st.provider.bucket_state, "managed");
    ASSERT_TRUE(st.provider.settles_at);
    EXPECT_GE(*st.provider.settles_at, before + 15 * 60);
    EXPECT_LE(*st.provider.settles_at, std::time(nullptr) + 15 * 60);
    EXPECT_FALSE(st.provider.settled) << "AWS asks for 15 minutes before relying on versioned writes";
    EXPECT_EQ(st.provider.retention_mode, "days");
    EXPECT_EQ(st.provider.retention_days.value_or(0), 30u);

    ASSERT_EQ(puts().size(), 1u);
    EXPECT_EQ(puts()[0].second, padmin::Versioning::Enabled);
    EXPECT_EQ(ruleDays(v.bucket, lifecycle::kOwnedRuleId).value_or(0), 30u);
    EXPECT_EQ(ruleDays(v.bucket, lifecycle::kManifestRuleId).value_or(0), 1u) << "the manifest's old versions expire";
    EXPECT_TRUE(audited(v.bucket, "recovery.versioning.enable"));
    EXPECT_TRUE(audited(v.bucket, "recovery.retention.set"));
    EXPECT_TRUE(audited(v.bucket, "recovery.disclosure"));
    EXPECT_EQ(db::query::recovery::Policy::get(v.id).mode, Mode::ProviderVersioning);

    // The same token again changes nothing new (idempotent), and status reads it back.
    (void)rec::update(superUser, v.id, enableRequest(k30d, d.token));
    EXPECT_EQ(puts().size(), 1u) << "never a second PutBucketVersioning";
    const nlohmann::json j = rec::status(superUser, v.id);
    EXPECT_EQ(j.at("provider").at("status"), "enabled");
}

TEST_F(RecoveryPolicyTest, TokensAreBoundToRetentionActorAndVault) {
    const auto a = managedVault();
    const auto b = managedVault();
    const auto d = rec::versioningDisclosure(superUser, a.id, k30d);
    EXPECT_EQ(confirmationCode([&] { (void)rec::update(superUser, a.id, enableRequest(k90d, d.token)); }),
              rec::VERSIONING_DISCLOSURE) << "another retention";
    EXPECT_EQ(confirmationCode([&] { (void)rec::update(superUser, b.id, enableRequest(k30d, d.token)); }),
              rec::VERSIONING_DISCLOSURE) << "another vault and bucket";
    // Another person who may enable it themselves still needs their own disclosure.
    using KeyPerm = rbac::permission::admin::keys::APIPermissions;
    using SyncPerm = rbac::permission::vault::sync::SyncConfigPermissions;
    for (const auto* role : {"admin", "platform_operator", "vault_admin"}) {
        const auto other = createUser(std::string("rp_other_") + role, role);
        if (!rbac::resolver::Vault::has<SyncPerm>({.user = other, .permission = SyncPerm::Edit, .vault_id = a.id}) ||
            !other->upstreamPerms().canConfigure() ||
            !rbac::resolver::Admin::has<KeyPerm>({.user = other, .permission = KeyPerm::Consume, .api_key_id = a.keyId}))
            continue;
        EXPECT_EQ(confirmationCode([&] { (void)rec::update(other, a.id, enableRequest(k30d, d.token)); }),
                  rec::VERSIONING_DISCLOSURE) << "another person (" << role << ")";
        break;
    }
    EXPECT_TRUE(puts().empty());
    EXPECT_EQ(rec::update(superUser, a.id, enableRequest(k30d, d.token)).provider.status, "enabled");
}

TEST_F(RecoveryPolicyTest, RetentionIsNeverAHiddenDefault) {
    const auto v = managedVault();
    rec::Update u;
    u.mode = Mode::ProviderVersioning;
    EXPECT_THROW((void)rec::update(superUser, v.id, u), ops::Invalid);
    u.mode = Mode::LocalSnapshots;
    u.provider_retention = k30d;
    EXPECT_THROW((void)rec::update(superUser, v.id, u), ops::Invalid) << "retention belongs to provider versioning";
}

TEST_F(RecoveryPolicyTest, ProvidersWithoutVersionsAreRefusedBeforeAnythingIsSent) {
    const auto v = managedVault();
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->versioningSupported = false;
    }
    const auto calls = callsOn(v.bucket);
    EXPECT_THROW((void)rec::versioningDisclosure(superUser, v.id, k30d), ops::Invalid);
    EXPECT_THROW((void)rec::update(superUser, v.id, enableRequest(k30d, "x")), ops::Invalid);
    EXPECT_THROW((void)rec::suspendVersioning(superUser, v.id, true), ops::Invalid);
    EXPECT_TRUE(puts().empty());
    EXPECT_EQ(versioningReads(), 0u);
    EXPECT_EQ(callsOn(v.bucket), calls);

    // A real Cloudflare R2 key: the documented reason, no client involved at all.
    auto key = std::make_shared<vault::model::APIKey>(superUser->id, "rp_r2_" + tag(), vault::model::S3Provider::CloudflareR2,
                                                      "r2accesskey000000000000000000000", "r2-secret-0000000000000000000000000000",
                                                      "auto", "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com");
    const auto keyId = runtime::Deps::get().apiKeyManager->addAPIKey(key);
    const auto r2 = ops::vaults::create(superUser, {.name = "rp_r2_vault_" + tag(), .type = vault::model::VaultType::S3,
                                                    .owner_id = superUser->id,
                                                    .s3 = ops::vaults::S3Spec{.api_key_id = keyId, .bucket = bucketName()}});
    const auto st = rec::status(superUser, r2->id);
    EXPECT_FALSE(st.provider.supported);
    EXPECT_EQ(st.provider.unsupported_reason, padmin::kR2VersioningUnsupported);
    try {
        (void)rec::update(superUser, r2->id, enableRequest(k30d, "x"));
        ADD_FAILURE() << "R2 enabled";
    } catch (const ops::Invalid& e) {
        EXPECT_EQ(std::string(e.what()), padmin::kR2VersioningUnsupported);
    }
    EXPECT_TRUE(puts().empty());
}

TEST_F(RecoveryPolicyTest, AProtectedBucketIsRefusedBeforeAnyRequest) {
    const auto v = managedVault();
    (void)up::protect(superUser, v.keyId, v.bucket, "recovery test lock");
    const auto calls = callsOn(v.bucket);
    EXPECT_THROW((void)rec::versioningDisclosure(superUser, v.id, k30d), ops::Denied);
    EXPECT_THROW((void)rec::update(superUser, v.id, enableRequest(k30d, "x")), ops::Denied);
    EXPECT_THROW((void)rec::suspendVersioning(superUser, v.id, true), ops::Denied);
    EXPECT_EQ(callsOn(v.bucket), calls);
    EXPECT_TRUE(puts().empty());
    EXPECT_EQ(rec::status(superUser, v.id).provider.bucket_state, "protected");
    (void)up::unprotect(superUser, v.keyId, v.bucket, true);
}

TEST_F(RecoveryPolicyTest, AnUnmanagedBucketIsAdoptedThroughTheAdmissionPreflight) {
    const auto v = unmanagedVault();
    EXPECT_EQ(rec::status(superUser, v.id).provider.bucket_state, "unmanaged");
    const auto d = rec::versioningDisclosure(superUser, v.id, k30d);
    EXPECT_NE(std::ranges::find(d.required_acknowledgements, rec::BUCKET_ADOPTION), d.required_acknowledgements.end());

    EXPECT_EQ(confirmationCode([&] { (void)rec::update(superUser, v.id, enableRequest(k30d, d.token)); }),
              rec::BUCKET_ADOPTION);
    EXPECT_TRUE(puts().empty());

    auto u = enableRequest(k30d, d.token);
    u.accept_adoption = true;
    const auto st = rec::update(superUser, v.id, u);
    EXPECT_EQ(st.provider.bucket_state, "adopted");
    EXPECT_EQ(st.provider.status, "enabled");
    const auto row = db::query::upstream::Bucket::getByIdentity("aws-s3", kAccount, v.bucket);
    ASSERT_TRUE(row);
    EXPECT_EQ(row->ownership, storage::upstream::model::Ownership::Adopted);
    EXPECT_EQ(row->vault_id.value_or(0), v.id);
    EXPECT_TRUE(audited(v.bucket, "bucket.adopt"));
    std::scoped_lock lock(cloud->mutex);
    EXPECT_EQ(cloud->buckets.at(v.bucket).objects.size(), 2u) << "adoption touches no object";
}

TEST_F(RecoveryPolicyTest, UnpricedEnablingNeedsItsOwnAcceptance) {
    const auto v = managedVault();
    vh::recovery::cost::setCatalogStoreForTesting(test_support::recovery_pricing::emptyCatalogStore());
    const auto d = rec::versioningDisclosure(superUser, v.id, k30d);
    EXPECT_FALSE(d.report.priced);
    EXPECT_TRUE(d.report.unpriced_reason);
    EXPECT_FALSE(d.report.pre_activation_monthly.expected) << "never $0.00";
    EXPECT_NE(std::ranges::find(d.required_acknowledgements, rec::VERSIONING_UNPRICED), d.required_acknowledgements.end());
    EXPECT_EQ(confirmationCode([&] { (void)rec::update(superUser, v.id, enableRequest(k30d, d.token)); }),
              rec::VERSIONING_UNPRICED);
    EXPECT_TRUE(puts().empty());
    auto u = enableRequest(k30d, d.token);
    u.accept_unpriced = true;
    EXPECT_EQ(rec::update(superUser, v.id, u).provider.status, "enabled");
}

TEST_F(RecoveryPolicyTest, AnAlreadyVersionedBucketIsNotEnabledAgain) {
    const auto v = managedVault();
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->buckets.at(v.bucket).versioning = padmin::Versioning::Enabled;
    }
    // Versions may exist already with nothing expiring them: a 30-day retention shortens that history.
    const auto d = rec::versioningDisclosure(superUser, v.id, k30d);
    EXPECT_NE(std::ranges::find(d.required_acknowledgements, rec::RETENTION_SHORTEN), d.required_acknowledgements.end());
    EXPECT_TRUE(d.report.history.unaccounted_history);
    auto u = enableRequest(k30d, d.token);
    u.accept_retention_shortening = true;
    const auto st = rec::update(superUser, v.id, u);
    EXPECT_TRUE(puts().empty()) << "no PutBucketVersioning for a bucket that is already Enabled";
    EXPECT_EQ(st.provider.status, "enabled");
    EXPECT_FALSE(st.provider.enabled_by_vaulthalla);
    EXPECT_TRUE(st.provider.settles_at);
}

TEST_F(RecoveryPolicyTest, EventuallyConsistentReadsAreRetriedBoundedly) {
    const auto v = managedVault();
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->staleReadsAfterPut = 3;
    }
    const auto readsBefore = versioningReads();
    auto st = enable(v, k30d);
    EXPECT_EQ(st.provider.status, "enabled");
    EXPECT_EQ(versioningReads() - readsBefore, 1u + 4u) << "one read before the PUT, three stale reads, then Enabled";
    EXPECT_FALSE(std::ranges::any_of(st.warnings, [](const auto& w) { return w.find("hasn't confirmed") != std::string::npos; }));

    const auto w = managedVault();
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->staleReadsAfterPut = 50;
    }
    const auto readsBefore2 = versioningReads();
    st = enable(w, k30d);
    EXPECT_EQ(versioningReads() - readsBefore2, 1u + 6u) << "bounded";
    EXPECT_TRUE(std::ranges::any_of(st.warnings, [](const auto& s) { return s.find("hasn't confirmed") != std::string::npos; }));
}

TEST_F(RecoveryPolicyTest, ModeAwayNeverSuspendsAndStatusSaysTheBucketStillVersions) {
    const auto v = managedVault();
    (void)enable(v, k30d);
    rec::Update off;
    off.mode = Mode::Off;
    const auto st = rec::update(superUser, v.id, off);
    EXPECT_EQ(st.mode, Mode::Off);
    ASSERT_EQ(puts().size(), 1u) << "only the enable";
    EXPECT_EQ(st.provider.status, "enabled");
    EXPECT_TRUE(std::ranges::any_of(st.warnings, [](const auto& w) { return w.find("recovery mode is off") != std::string::npos; }));
}

TEST_F(RecoveryPolicyTest, SuspendingIsConfirmedAndDeletesNothing) {
    const auto v = managedVault();
    seedBucket(v.bucket, {{"a", 1}, {"b", 2}});
    (void)enable(v, k30d);
    EXPECT_EQ(confirmationCode([&] { (void)rec::suspendVersioning(superUser, v.id, false); }), rec::VERSIONING_SUSPEND);
    EXPECT_EQ(puts().size(), 1u);
    const auto st = rec::suspendVersioning(superUser, v.id, true);
    ASSERT_EQ(puts().size(), 2u);
    EXPECT_EQ(puts()[1].second, padmin::Versioning::Suspended);
    EXPECT_EQ(st.provider.status, "suspended");
    EXPECT_TRUE(std::ranges::any_of(st.warnings, [](const auto& w) { return w.find("suspended") != std::string::npos; }));
    EXPECT_TRUE(audited(v.bucket, "recovery.versioning.suspend"));
    EXPECT_EQ(ruleDays(v.bucket, lifecycle::kOwnedRuleId).value_or(0), 30u) << "the retention rule stays";
    std::scoped_lock lock(cloud->mutex);
    EXPECT_EQ(cloud->buckets.at(v.bucket).objects.size(), 2u);
}

TEST_F(RecoveryPolicyTest, ShorteningRetentionNeedsItsOwnAcceptance) {
    const auto v = managedVault();
    (void)enable(v, kForever);
    EXPECT_FALSE(ruleDays(v.bucket, lifecycle::kOwnedRuleId)) << "indefinite: no NoncurrentDays of ours";
    EXPECT_EQ(ruleDays(v.bucket, lifecycle::kManifestRuleId).value_or(0), 1u);

    auto d = rec::versioningDisclosure(superUser, v.id, k30d);
    EXPECT_EQ(confirmationCode([&] { (void)rec::update(superUser, v.id, enableRequest(k30d, d.token)); }),
              rec::RETENTION_SHORTEN) << "indefinite → 30 days";
    EXPECT_FALSE(ruleDays(v.bucket, lifecycle::kOwnedRuleId));
    auto u = enableRequest(k30d, d.token);
    u.accept_retention_shortening = true;
    EXPECT_EQ(rec::update(superUser, v.id, u).provider.retention_days.value_or(0), 30u);
    EXPECT_EQ(ruleDays(v.bucket, lifecycle::kOwnedRuleId).value_or(0), 30u);

    d = rec::versioningDisclosure(superUser, v.id, k90d);
    EXPECT_EQ(rec::update(superUser, v.id, enableRequest(k90d, d.token)).provider.retention_days.value_or(0), 90u)
        << "longer: no extra acceptance";
    d = rec::versioningDisclosure(superUser, v.id, k60d);
    EXPECT_EQ(confirmationCode([&] { (void)rec::update(superUser, v.id, enableRequest(k60d, d.token)); }),
              rec::RETENTION_SHORTEN) << "90 → 60 days";
    EXPECT_EQ(ruleDays(v.bucket, lifecycle::kOwnedRuleId).value_or(0), 90u);
}

TEST_F(RecoveryPolicyTest, ForeignRulesAreKeptAndAShorterOneIsReportedAsEffective) {
    const auto v = managedVault();
    padmin::LifecycleRule expiring;
    expiring.id = "other-app-versions";
    expiring.foreign = true;
    expiring.expire_noncurrent_days = 7;
    expiring.raw_xml = "<Rule><ID>other-app-versions</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status>"
                       "<NoncurrentVersionExpiration><NoncurrentDays>7</NoncurrentDays></NoncurrentVersionExpiration></Rule>";
    padmin::LifecycleRule aborting;
    aborting.id = "other-app-multipart";
    aborting.foreign = true;
    aborting.abort_incomplete_multipart_days = 2;
    aborting.raw_xml = "<Rule><ID>other-app-multipart</ID><Status>Enabled</Status></Rule>";
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->buckets.at(v.bucket).lifecycle = {expiring, aborting};
    }
    const auto d = rec::versioningDisclosure(superUser, v.id, k30d);
    EXPECT_TRUE(std::ranges::any_of(d.consequences, [](const auto& c) { return c.find("other-app-versions") != std::string::npos; }));
    EXPECT_EQ(d.report.pre_activation_monthly.expected.has_value(), d.report.priced);
    const auto st = rec::update(superUser, v.id, enableRequest(k30d, d.token));
    EXPECT_TRUE(std::ranges::any_of(st.warnings, [](const auto& w) { return w.find("after 7 days") != std::string::npos; }));

    const auto now = rules(v.bucket);
    const auto find = [&](const std::string& id) { return std::ranges::find(now, id, &padmin::LifecycleRule::id); };
    ASSERT_NE(find("other-app-versions"), now.end());
    ASSERT_NE(find("other-app-multipart"), now.end());
    EXPECT_EQ(find("other-app-versions")->raw_xml, expiring.raw_xml) << "foreign rules go back byte for byte";
    EXPECT_EQ(find("other-app-multipart")->raw_xml, aborting.raw_xml);
    EXPECT_NE(find(lifecycle::kOwnedRuleId), now.end());
    EXPECT_NE(find(lifecycle::kManifestRuleId), now.end());

    const auto refreshed = rec::status(superUser, v.id, /*refreshProvider=*/true);
    EXPECT_EQ(refreshed.provider.effective_noncurrent_days.value_or(0), 7u);
    ASSERT_EQ(refreshed.provider.foreign_noncurrent_rules.size(), 1u) << "the manifest rule is ours, not foreign";
    EXPECT_EQ(refreshed.provider.foreign_noncurrent_rules[0], "other-app-versions: 7 days");
    EXPECT_TRUE(std::ranges::any_of(refreshed.provider.warnings,
                                    [](const auto& w) { return w.find("sooner than Vaulthalla's retention") != std::string::npos; }));
}

TEST_F(RecoveryPolicyTest, ProvisioningNeverEnablesVersioning) {
    const auto v = managedVault();
    std::scoped_lock lock(cloud->mutex);
    EXPECT_EQ(cloud->buckets.at(v.bucket).versioning, padmin::Versioning::Unversioned);
    EXPECT_TRUE(cloud->putVersioningCalls.empty());
}

TEST_F(RecoveryPolicyTest, LocalFieldsAreValidatedAndNeedNoProvider) {
    const auto v = managedVault();
    const auto calls = callsOn(v.bucket);
    rec::Update u;
    u.mode = Mode::LocalSnapshots;
    u.snapshot_quota_bytes = 1'000'000;
    u.cost_alert_monthly = "12.50";
    u.local_versioning = vh::recovery::LocalVersioningPatch{.enabled = true, .keep_last = 5, .max_age_days = 30,
                                                            .quota_bytes = std::nullopt};
    const auto st = rec::update(superUser, v.id, u);
    EXPECT_EQ(st.mode, Mode::LocalSnapshots);
    EXPECT_EQ(st.snapshot_quota_bytes.value_or(0), 1'000'000u);
    ASSERT_TRUE(st.cost_alert_monthly);
    EXPECT_EQ(st.cost_alert_monthly->currency, "USD");
    EXPECT_TRUE(st.local_versioning.enabled);
    EXPECT_EQ(st.local_versioning.keep_last.value_or(0), 5u);
    // A patch: absent fields are unchanged, 0 clears a limit.
    rec::Update patch;
    patch.local_versioning = vh::recovery::LocalVersioningPatch{.enabled = std::nullopt, .keep_last = 0,
                                                                .max_age_days = std::nullopt, .quota_bytes = 4096};
    const auto patched = rec::update(superUser, v.id, patch);
    EXPECT_TRUE(patched.local_versioning.enabled);
    EXPECT_FALSE(patched.local_versioning.keep_last);
    EXPECT_EQ(patched.local_versioning.max_age_days.value_or(0), 30u);
    EXPECT_EQ(patched.local_versioning.quota_bytes.value_or(0), 4096u);
    EXPECT_EQ(callsOn(v.bucket), calls) << "local settings never reach the provider";

    for (const auto* bad : {"abc", "1.123456789", "-1", "1e3", "1234567890123"}) {
        rec::Update b;
        b.cost_alert_monthly = bad;
        EXPECT_THROW((void)rec::update(superUser, v.id, b), ops::Invalid) << bad;
    }
    rec::Update keep;
    keep.local_versioning = vh::recovery::LocalVersioningPatch{.enabled = true, .keep_last = 10001, .max_age_days = std::nullopt,
                                                               .quota_bytes = std::nullopt};
    EXPECT_THROW((void)rec::update(superUser, v.id, keep), ops::Invalid);
    rec::Update clear;
    clear.cost_alert_monthly = "";
    clear.snapshot_quota_bytes = 0;
    const auto cleared = rec::update(superUser, v.id, clear);
    EXPECT_FALSE(cleared.cost_alert_monthly);
    EXPECT_FALSE(cleared.snapshot_quota_bytes);
}

TEST_F(RecoveryPolicyTest, PolicyChangesFollowSyncConfigUpstreamConfigureAndTheKey) {
    using KeyPerm = rbac::permission::admin::keys::APIPermissions;
    using SyncPerm = rbac::permission::vault::sync::SyncConfigPermissions;
    const auto v = managedVault();

    const auto stranger = createUser("rp_stranger", "unprivileged");
    rec::Update local;
    local.mode = Mode::LocalSnapshots;
    EXPECT_THROW((void)rec::update(stranger, v.id, local), ops::Denied);
    EXPECT_THROW((void)rec::status(stranger, v.id), ops::Denied);
    EXPECT_THROW((void)rec::costs(stranger, v.id), ops::Denied);

    unsigned deniedBySync = 0, deniedByUpstream = 0, deniedByKey = 0, allowedCount = 0;
    for (const auto* role : {"unprivileged", "auditor", "support", "identity_admin", "security_admin", "platform_operator",
                             "vault_admin", "admin", "key_custodian", "super_admin"}) {
        const auto user = std::string(role) == "super_admin" ? superUser : createUser(std::string("rp_rbac_") + role, role);
        const bool sync = rbac::resolver::Vault::has<SyncPerm>({.user = user, .permission = SyncPerm::Edit, .vault_id = v.id});
        const bool configure = user->upstreamPerms().canConfigure();
        const bool key = rbac::resolver::Admin::has<KeyPerm>({.user = user, .permission = KeyPerm::Consume, .api_key_id = v.keyId});
        const auto allowed = [&](auto&& fn) {
            try {
                fn();
                return true;
            } catch (const ops::Denied&) {
                return false;
            } catch (const ops::Error&) {
                return true;   // authorized, refused for another reason (confirmation, …)
            }
        };
        const bool expected = sync && configure && key;
        // The disclosure reads like costs: sync settings + the vault's pricing statistics.
        const bool readsCosts =
            rbac::resolver::Vault::has<SyncPerm>({.user = user, .permission = SyncPerm::View, .vault_id = v.id}) &&
            ops::stats::canViewVault(user, v.id);
        EXPECT_EQ(allowed([&] { (void)rec::versioningDisclosure(user, v.id, k30d); }), readsCosts) << role;
        EXPECT_EQ(allowed([&] { (void)rec::costs(user, v.id); }), readsCosts) << role;
        EXPECT_EQ(allowed([&] { (void)rec::update(user, v.id, enableRequest(k30d, "")); }), expected) << role;
        EXPECT_EQ(allowed([&] { (void)rec::suspendVersioning(user, v.id, false); }), expected) << role;
        EXPECT_EQ(allowed([&] { (void)rec::update(user, v.id, local); }), sync) << role;
        if (!sync) ++deniedBySync;
        else if (!configure) ++deniedByUpstream;
        else if (!key) ++deniedByKey;
        else ++allowedCount;
    }
    EXPECT_GT(deniedBySync, 0u);
    EXPECT_GT(allowedCount, 0u);
    std::cout << "[recovery rbac] denied by sync.config.edit: " << deniedBySync << ", by admin.upstream.configure: "
              << deniedByUpstream << ", by key Consume: " << deniedByKey << ", allowed: " << allowedCount << std::endl;

    // admin.upstream.configure without Consume on the vault's key, and a vault's owner without configure.
    const auto roleName = "rp_configurer_" + tag();
    (void)ops::roles::createAdminRole(superUser, {.name = roleName, .permissions = {.changes = {
        {"admin.upstream.view", true}, {"admin.upstream.configure", true}}}}, "test");
    const auto configurer = createUser("rp_configurer", roleName);
    const auto own = managedVault(configurer);
    EXPECT_TRUE(configurer->upstreamPerms().canConfigure());
    EXPECT_FALSE(rbac::resolver::Admin::has<KeyPerm>({.user = configurer, .permission = KeyPerm::Consume, .api_key_id = own.keyId}));
    EXPECT_THROW((void)rec::update(configurer, own.id, enableRequest(k30d, "")), ops::Denied);
    const auto owner = createUser("rp_owner", "unprivileged");
    const auto owned = managedVault(owner);
    EXPECT_FALSE(owner->upstreamPerms().canConfigure());
    EXPECT_THROW((void)rec::update(owner, owned.id, enableRequest(k30d, "")), ops::Denied);
    const bool ownerSync = rbac::resolver::Vault::has<SyncPerm>({.user = owner, .permission = SyncPerm::Edit, .vault_id = owned.id});
    bool ownerLocal = true;
    try {
        (void)rec::update(owner, owned.id, local);
    } catch (const ops::Denied&) {
        ownerLocal = false;
    }
    EXPECT_EQ(ownerLocal, ownerSync) << "local settings need only sync.config.edit";
}

TEST_F(RecoveryPolicyTest, CostsUseMeasuredUsageAndRaiseOneAlertPerDay) {
    const auto v = managedVault();
    (void)enable(v, k30d);
    const auto now = std::time(nullptr);
    for (int i = 0; i < 10; ++i) {
        db::query::recovery::UsageCounters c;
        c.overwrite_objects = 10;
        c.overwritten_bytes = 1'000'000'000ull;
        c.put_requests = 34;
        db::query::recovery::Usage::add(v.id, vh::recovery::usage::utcDay(now - i * 86400), c);
    }
    rec::Update alert;
    alert.cost_alert_monthly = "0.10";
    (void)rec::update(superUser, v.id, alert);

    const auto r = rec::costs(superUser, v.id);
    EXPECT_EQ(r.phase, "active");
    EXPECT_TRUE(r.priced);
    EXPECT_EQ(r.observation.window_days, 10u);
    EXPECT_EQ(r.retention.value_or(""), "30d");
    ASSERT_TRUE(r.projected_monthly.expected);
    EXPECT_EQ(r.projected_monthly.basis, "observed");
    EXPECT_TRUE(r.alert.exceeded);
    EXPECT_FALSE(r.current_month_to_date.reason && r.current_month_to_date.reason->find("not active") != std::string::npos)
        << "versioning is on: month to date is computed";
    (void)rec::costs(superUser, v.id);

    const auto alerts = db::Transactions::exec("test::alerts", [&](pqxx::work& txn) {
        return txn.exec("SELECT COUNT(*) FROM operator_notification WHERE type = $1 AND vault_id = $2",
                        pqxx::params{std::string(vh::recovery::cost::kAlertType), v.id}).one_row_ref()[0].as<int64_t>();
    });
    EXPECT_EQ(alerts, 1) << "one alert per vault per day, refreshed";
}

}
