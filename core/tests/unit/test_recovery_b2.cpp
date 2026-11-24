// Provider versioning on Backblaze B2 (ops::recovery and the provisioning that feeds it), against the test DB, an
// in-memory provider account (FakeAdmin; B2's own adapter is test_b2_lifecycle.cpp) and the signed fixture catalog:
//  - a bucket Vaulthalla creates keeps only the latest version (the owner's default: versioning off), scoped to o/
//    for an encrypting (opaque_v1) vault and to the whole bucket plus the manifest rule for a --no-encrypt one;
//  - provider versioning: N days and indefinite map onto the owned rule, no PutBucketVersioning, no propagation wait,
//    the disclosure / unpriced / shortening acknowledgements as on AWS; status says supported, the rule, foreign
//    rules and warnings;
//  - mode off (or local snapshots) returns the bucket to the latest version only, with acceptance when that deletes
//    history; an adopted or unmanaged bucket is never rewritten without it, a protected one never;
//  - a concurrent change of the bucket is a Conflict; suspending is refused with the reason;
//  - keepsHistory (local versioning's backlog replay) is false on a bucket that keeps only the latest version.

#include "../helpers/recovery_pricing.hpp"
#include "../helpers/sync_conflict_harness.hpp"
#include "../helpers/upstream_admin_fakes.hpp"

#include "db/query/recovery/Policy.hpp"
#include "db/query/upstream/Audit.hpp"
#include "db/query/upstream/Bucket.hpp"
#include "ops/Recovery.hpp"
#include "ops/RecoveryJson.hpp"
#include "ops/Upstream.hpp"
#include "ops/Vaults.hpp"
#include "recovery/cost/Report.hpp"
#include "recovery/provider/Capabilities.hpp"
#include "recovery/provider/Policy.hpp"
#include "recovery/provider/State.hpp"
#include "auth/stepup/StepUp.hpp"
#include "runtime/Deps.hpp"
#include "storage/Manager.hpp"
#include "storage/s3/provider/admin/Admin.hpp"
#include "storage/upstream/Guard.hpp"
#include "storage/upstream/Lifecycle.hpp"
#include "storage/upstream/Provisioner.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/model/S3Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <functional>
#include <map>

namespace vh::test_recovery_b2 {

using namespace test_support::sync_conflicts;
using namespace test_support::upstream_admin;
namespace padmin = storage::s3::provider::admin;
namespace up = ops::upstream;
namespace rec = ops::recovery;
namespace pol = vh::recovery::provider::policy;
namespace lifecycle = storage::upstream::lifecycle;
using vh::recovery::Mode;
using vh::recovery::ProviderRetention;

const ProviderRetention kB2d30{.indefinite = false, .days = 30};
const ProviderRetention kB2d90{.indefinite = false, .days = 90};
const ProviderRetention kB2Forever{.indefinite = true, .days = 0};
constexpr const char* kB2Host = "s3.us-west-004.backblazeb2.com";

template <typename Fn>
std::string b2Confirmation(Fn&& fn) {
    try {
        fn();
    } catch (const ops::NeedsConfirmation& e) {
        return e.code;
    }
    return {};
}

class RecoveryB2Test : public Harness {
protected:
    std::shared_ptr<FakeCloud> cloud;

    void SetUp() override {
        Harness::SetUp();
        if (skipTests) return;
        cloud = std::make_shared<FakeCloud>();
        cloud->newBucketVersioning = padmin::Versioning::Enabled;   // every B2 bucket
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
        // New encrypting vaults get opaque_v1, as outside tests (gtest_main makes the suite default path_v0).
        vault::model::setNewEncryptingLayoutForTesting(std::nullopt);
    }

    void TearDown() override {
        vault::model::setNewEncryptingLayoutForTesting(vault::model::StorageLayout::PathV0);
        padmin::setFactoryForTesting(std::nullopt);
        storage::upstream::provision::setObjectHeadForTesting({});
        vh::recovery::cost::setCatalogStoreForTesting(nullptr);
        pol::setReadBackForTesting(6, std::chrono::milliseconds(250));
    }

    static unsigned b2Key() {
        auto key = std::make_shared<vault::model::APIKey>(superUser->id, "b2r_key_" + tag(), vault::model::S3Provider::BackblazeB2,
                                                          "0041234567890ab0000000001", "K004secret-value-000000000000000",
                                                          "us-west-004", std::string("https://") + kB2Host);
        const auto id = runtime::Deps::get().apiKeyManager->addAPIKey(key);
        (void)up::enableAdmin(superUser, id, {});
        return id;
    }

    static std::string bucketName() { return "vh-b2r-" + tag(); }

    struct V {
        uint32_t id = 0;
        unsigned keyId = 0;
        std::string bucket;
    };

    // A vault on a bucket Vaulthalla creates now (managed).
    static V createdVault(const bool encrypt = true) {
        V v;
        v.keyId = b2Key();
        v.bucket = bucketName();
        const auto vault = ops::vaults::create(superUser, {.name = "b2r_vault_" + tag(), .type = vault::model::VaultType::S3,
                                                           .owner_id = superUser->id,
                                                           .s3 = ops::vaults::S3Spec{.api_key_id = v.keyId, .bucket = v.bucket,
                                                                                     .encrypt_upstream = encrypt,
                                                                                     .provision = up::Provision{.mode = up::BucketMode::Create}}});
        v.id = vault->id;
        return v;
    }

    // A vault on an existing bucket with history, as 1.25.0 left them: managed, but no rule and nothing recorded.
    V legacyManagedVault() {
        auto v = createdVault();
        std::scoped_lock lock(cloud->mutex);
        cloud->buckets.at(v.bucket).lifecycle.clear();
        const auto row = db::query::upstream::Bucket::getByIdentity("backblaze-b2", kB2Host, v.bucket);
        EXPECT_TRUE(row);
        if (row) db::query::upstream::Bucket::recordRetention(row->id, "unset", std::nullopt, std::nullopt);
        return v;
    }

    void seedBucket(const std::string& name, std::map<std::string, uint64_t> objects = {}) {
        std::scoped_lock lock(cloud->mutex);
        cloud->buckets[name].objects = std::move(objects);
        cloud->buckets[name].versioning = padmin::Versioning::Enabled;
        cloud->buckets[name].previousVersioning = padmin::Versioning::Enabled;
    }

    // A vault on a bucket an administrator adopted (explicitly, with data in it).
    V adoptedVault() {
        V v;
        v.keyId = b2Key();
        v.bucket = bucketName();
        seedBucket(v.bucket, {{"enc/a.txt", 5}});
        const auto vault = ops::vaults::create(superUser, {.name = "b2r_vault_" + tag(), .type = vault::model::VaultType::S3,
                                                           .owner_id = superUser->id,
                                                           .s3 = ops::vaults::S3Spec{.api_key_id = v.keyId, .bucket = v.bucket,
                                                                                     .provision = up::Provision{.mode = up::BucketMode::Adopt,
                                                                                                                .accept_adoption = true}}});
        v.id = vault->id;
        return v;
    }

    // A vault on a bucket Vaulthalla doesn't manage.
    V unmanagedVault() {
        V v;
        v.keyId = b2Key();
        v.bucket = bucketName();
        seedBucket(v.bucket, {{"enc/a.txt", 5}, {"enc/b.txt", 7}});
        const auto vault = ops::vaults::create(superUser, {.name = "b2r_vault_" + tag(), .type = vault::model::VaultType::S3,
                                                           .owner_id = superUser->id,
                                                           .s3 = ops::vaults::S3Spec{.api_key_id = v.keyId, .bucket = v.bucket}});
        v.id = vault->id;
        return v;
    }

    static vh::recovery::Status enable(const V& v, const ProviderRetention& r,
                                       const std::function<void(rec::Update&)>& tweak = {}) {
        const auto d = rec::versioningDisclosure(superUser, v.id, r);
        rec::Update u;
        u.mode = Mode::ProviderVersioning;
        u.provider_retention = r;
        u.disclosure_token = d.token;
        u.accept_unpriced = true;   // the fixture catalog has no Backblaze profile
        if (tweak) tweak(u);
        return rec::update(superUser, v.id, u);
    }

    static rec::Update modeOff(const bool accept = false, const Mode mode = Mode::Off) {
        rec::Update u;
        u.mode = mode;
        u.accept_retention_shortening = accept;
        return u;
    }

    std::vector<padmin::LifecycleRule> rules(const std::string& bucket) {
        std::scoped_lock lock(cloud->mutex);
        return cloud->buckets.at(bucket).lifecycle;
    }

    std::optional<padmin::LifecycleRule> rule(const std::string& bucket, const std::string& id) {
        for (const auto& r : rules(bucket))
            if (r.id == id) return r;
        return std::nullopt;
    }

    unsigned callsOn(const std::string& bucket) {
        std::scoped_lock lock(cloud->mutex);
        return cloud->bucketCalls[bucket];
    }

    unsigned lifecycleWrites() {
        std::scoped_lock lock(cloud->mutex);
        return cloud->putLifecycleCalls;
    }

    size_t versioningPuts() {
        std::scoped_lock lock(cloud->mutex);
        return cloud->putVersioningCalls.size();
    }

    static std::string retentionMode(const V& v) {
        const auto row = db::query::upstream::Bucket::getByIdentity("backblaze-b2", kB2Host, v.bucket);
        if (!row) return "no row";
        const auto versioning = db::query::upstream::Bucket::getVersioning(row->id);
        return versioning ? versioning->retention_mode : "none";
    }

    static bool audited(const std::string& bucket, const std::string& action) {
        return std::ranges::any_of(db::query::upstream::Audit::list(bucket, 200),
                                   [&](const auto& r) { return r.action == action; });
    }

    static bool has(const std::vector<std::string>& lines, const std::string& part) {
        return std::ranges::any_of(lines, [&](const std::string& l) { return l.find(part) != std::string::npos; });
    }
};

// ---- the owner's default -------------------------------------------------------------------------------------------

TEST_F(RecoveryB2Test, ABucketVaulthallaCreatesKeepsOnlyTheLatestVersionScopedToTheVaultsFiles) {
    const auto v = createdVault(/*encrypt=*/true);
    const auto owned = rule(v.bucket, lifecycle::kOwnedRuleId);
    ASSERT_TRUE(owned) << "versioning off is really off on B2";
    EXPECT_EQ(owned->prefix, "o/") << "an opaque vault's files; nothing under .vaulthalla/";
    EXPECT_EQ(owned->expire_noncurrent_days.value_or(0), 1u);
    EXPECT_FALSE(owned->expire_current_days) << "the current version is never touched";
    EXPECT_FALSE(rule(v.bucket, lifecycle::kManifestRuleId));
    EXPECT_EQ(retentionMode(v), "latest");
    EXPECT_EQ(versioningPuts(), 0u);
    EXPECT_TRUE(audited(v.bucket, "recovery.history.off"));
    EXPECT_FALSE(vh::recovery::provider::bucketVersioningForVault(v.id).keepsHistory())
        << "no backlog replays into a bucket that keeps only the latest version";

    const auto st = rec::status(superUser, v.id, /*refreshProvider=*/true);
    EXPECT_TRUE(st.provider.supported) << st.provider.unsupported_reason;
    EXPECT_EQ(st.provider.provider.value_or(""), "backblaze-b2");
    EXPECT_EQ(st.provider.status, "enabled");
    EXPECT_TRUE(st.provider.capabilities.always_versioned);
    EXPECT_FALSE(st.provider.capabilities.suspend);
    EXPECT_EQ(st.provider.retention_mode, "latest");
    EXPECT_EQ(st.provider.effective_noncurrent_days.value_or(0), 1u);
    ASSERT_EQ(st.provider.vaulthalla_rules.size(), 1u);
    EXPECT_NE(st.provider.vaulthalla_rules[0].find("'o/'"), std::string::npos);
    EXPECT_FALSE(has(st.warnings, "keeps every old version")) << "nothing to warn about";
    EXPECT_FALSE(has(st.warnings, "costs can't be estimated")) << "no history, no versioning costs";

    const nlohmann::json j = st;
    EXPECT_EQ(j.at("provider").at("capabilities").at("history_off"), true);
    EXPECT_EQ(j.at("provider").at("retention_mode"), "latest");
}

TEST_F(RecoveryB2Test, ANoEncryptVaultGetsTheWholeBucketAndTheManifestRule) {
    const auto v = createdVault(/*encrypt=*/false);
    const auto owned = rule(v.bucket, lifecycle::kOwnedRuleId);
    ASSERT_TRUE(owned);
    EXPECT_EQ(owned->prefix, "") << "names are paths: the whole bucket (its index is a plain PUT, read current only)";
    EXPECT_EQ(owned->expire_noncurrent_days.value_or(0), 1u);
    const auto manifest = rule(v.bucket, lifecycle::kManifestRuleId);
    ASSERT_TRUE(manifest);
    EXPECT_EQ(manifest->prefix, ".vaulthalla/");
}

// ---- provider versioning -------------------------------------------------------------------------------------------

TEST_F(RecoveryB2Test, NDaysIsTheOwnedRuleWithoutPutBucketVersioningOrAPropagationWait) {
    const auto v = createdVault();
    EXPECT_EQ(b2Confirmation([&] {
        rec::Update u;
        u.mode = Mode::ProviderVersioning;
        u.provider_retention = kB2d30;
        (void)rec::update(superUser, v.id, u);
    }), rec::VERSIONING_DISCLOSURE) << "the disclosure is asked for as on AWS";

    const auto d = rec::versioningDisclosure(superUser, v.id, kB2d30);
    EXPECT_TRUE(has(d.consequences, "Backblaze B2"));
    EXPECT_FALSE(has(d.consequences, "15 minutes"));
    EXPECT_TRUE(has(d.consequences, "No rule touches .vaulthalla/"));
    EXPECT_TRUE(std::ranges::find(d.required_acknowledgements, rec::RETENTION_SHORTEN) == d.required_acknowledgements.end())
        << "30 days keeps more than the latest version only";

    const auto st = enable(v, kB2d30);
    EXPECT_EQ(st.mode, Mode::ProviderVersioning);
    EXPECT_EQ(st.provider.retention_mode, "days");
    EXPECT_EQ(st.provider.retention_days.value_or(0), 30u);
    EXPECT_TRUE(st.provider.settled) << "B2 buckets are versioned already: nothing propagates";
    EXPECT_FALSE(st.provider.enabled_by_vaulthalla);
    EXPECT_EQ(versioningPuts(), 0u) << "never a PutBucketVersioning on B2";
    const auto owned = rule(v.bucket, lifecycle::kOwnedRuleId);
    ASSERT_TRUE(owned);
    EXPECT_EQ(owned->prefix, "o/");
    EXPECT_EQ(owned->expire_noncurrent_days.value_or(0), 30u);
    EXPECT_FALSE(rule(v.bucket, lifecycle::kManifestRuleId));
    EXPECT_TRUE(vh::recovery::provider::bucketVersioningForVault(v.id).keepsHistory());

    // Longer is not a shortening; shorter needs its own acceptance.
    (void)enable(v, kB2d90);
    EXPECT_EQ(rule(v.bucket, lifecycle::kOwnedRuleId)->expire_noncurrent_days.value_or(0), 90u);
    EXPECT_EQ(b2Confirmation([&] { (void)enable(v, kB2d30); }), rec::RETENTION_SHORTEN);
    EXPECT_EQ(rule(v.bucket, lifecycle::kOwnedRuleId)->expire_noncurrent_days.value_or(0), 90u);
    (void)enable(v, kB2d30, [](rec::Update& u) { u.accept_retention_shortening = true; });
    EXPECT_EQ(rule(v.bucket, lifecycle::kOwnedRuleId)->expire_noncurrent_days.value_or(0), 30u);

    // Indefinite: no rule of ours at all.
    (void)enable(v, kB2Forever);
    EXPECT_FALSE(rule(v.bucket, lifecycle::kOwnedRuleId));
    EXPECT_EQ(retentionMode(v), "indefinite");
}

TEST_F(RecoveryB2Test, ReturningToOffNeedsAcceptanceAndKeepsOnlyTheLatestVersion) {
    const auto v = createdVault();
    (void)enable(v, kB2d30);
    const auto writes = lifecycleWrites();

    EXPECT_EQ(b2Confirmation([&] { (void)rec::update(superUser, v.id, modeOff()); }), rec::RETENTION_SHORTEN);
    EXPECT_EQ(lifecycleWrites(), writes) << "nothing is sent before the acceptance";
    EXPECT_EQ(db::query::recovery::Policy::get(v.id).mode, Mode::ProviderVersioning);

    const auto st = rec::update(superUser, v.id, modeOff(true, Mode::LocalSnapshots));
    EXPECT_EQ(st.mode, Mode::LocalSnapshots);
    EXPECT_EQ(rule(v.bucket, lifecycle::kOwnedRuleId)->expire_noncurrent_days.value_or(0), 1u);
    EXPECT_EQ(retentionMode(v), "latest");
    EXPECT_FALSE(vh::recovery::provider::bucketVersioningForVault(v.id).keepsHistory());

    // Already so: setting off again sends nothing and asks nothing.
    const auto calls = callsOn(v.bucket);
    (void)rec::update(superUser, v.id, modeOff());
    EXPECT_EQ(callsOn(v.bucket), calls);
}

TEST_F(RecoveryB2Test, AnExisting125BucketIsBroughtInLineWithOneAcceptedUpdate) {
    // What production has: B2 buckets created by 1.25.0, no rule, every version kept.
    const auto v = legacyManagedVault();
    auto st = rec::status(superUser, v.id, /*refreshProvider=*/true);
    EXPECT_TRUE(st.provider.supported);
    EXPECT_TRUE(has(st.warnings, "keeps every old version")) << "status says the bucket isn't really off";
    EXPECT_TRUE(st.provider.vaulthalla_rules.empty());

    EXPECT_EQ(b2Confirmation([&] { (void)rec::update(superUser, v.id, modeOff()); }), rec::RETENTION_SHORTEN)
        << "deleting the history kept so far is asked";
    st = rec::update(superUser, v.id, modeOff(true));
    EXPECT_EQ(retentionMode(v), "latest");
    EXPECT_EQ(rule(v.bucket, lifecycle::kOwnedRuleId)->expire_noncurrent_days.value_or(0), 1u);
    EXPECT_FALSE(has(st.warnings, "keeps every old version"));

    // The other choice: 30 days of history, from the same state.
    const auto w = legacyManagedVault();
    EXPECT_EQ(b2Confirmation([&] { (void)enable(w, kB2d30); }), rec::RETENTION_SHORTEN)
        << "every version so far is kept: 30 days deletes the older ones";
    (void)enable(w, kB2d30, [](rec::Update& u) { u.accept_retention_shortening = true; });
    EXPECT_EQ(rule(w.bucket, lifecycle::kOwnedRuleId)->expire_noncurrent_days.value_or(0), 30u);
}

// ---- adopted, unmanaged, protected ---------------------------------------------------------------------------------

TEST_F(RecoveryB2Test, AnAdoptedBucketKeepsItsRulesUntilAnAcceptedChangeAndForeignRulesStay) {
    const auto v = adoptedVault();
    EXPECT_FALSE(rule(v.bucket, lifecycle::kOwnedRuleId)) << "adopting never writes a rule";
    padmin::LifecycleRule foreign;
    foreign.id = "b2:logs/";
    foreign.foreign = true;
    foreign.prefix = "logs/";
    foreign.expire_noncurrent_days = 3;
    foreign.raw_json = R"({"fileNamePrefix":"logs/","daysFromHidingToDeleting":3})";
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->buckets.at(v.bucket).lifecycle = {foreign};
    }
    EXPECT_EQ(b2Confirmation([&] { (void)rec::update(superUser, v.id, modeOff()); }), rec::RETENTION_SHORTEN);
    EXPECT_FALSE(rule(v.bucket, lifecycle::kOwnedRuleId));
    (void)rec::update(superUser, v.id, modeOff(true));
    const auto now = rules(v.bucket);
    const auto kept = std::ranges::find(now, std::string("b2:logs/"), &padmin::LifecycleRule::id);
    ASSERT_NE(kept, now.end());
    EXPECT_EQ(kept->raw_json, foreign.raw_json) << "foreign rules go back as they were";
    EXPECT_TRUE(rule(v.bucket, lifecycle::kOwnedRuleId));
}

TEST_F(RecoveryB2Test, AnUnmanagedBucketIsOnlyChangedWhenAdoptedInTheSameStep) {
    const auto v = unmanagedVault();
    const auto calls = callsOn(v.bucket);
    auto st = rec::update(superUser, v.id, modeOff(true, Mode::LocalSnapshots));
    EXPECT_EQ(st.mode, Mode::LocalSnapshots) << "the preference changes (local snapshots keep working)";
    EXPECT_TRUE(has(st.warnings, "--adopt-bucket"));
    EXPECT_EQ(callsOn(v.bucket), calls) << "the bucket is never touched silently";
    EXPECT_FALSE(rule(v.bucket, lifecycle::kOwnedRuleId));

    auto u = modeOff(true);
    u.accept_adoption = true;
    st = rec::update(superUser, v.id, u);
    EXPECT_EQ(st.provider.bucket_state, "adopted");
    EXPECT_EQ(rule(v.bucket, lifecycle::kOwnedRuleId)->expire_noncurrent_days.value_or(0), 1u);
}

TEST_F(RecoveryB2Test, AProtectedBucketIsNeverTouched) {
    const auto v = legacyManagedVault();
    (void)up::protect(superUser, v.keyId, v.bucket, "b2 recovery test lock");
    const auto calls = callsOn(v.bucket);
    const auto st = rec::update(superUser, v.id, modeOff(true));
    EXPECT_TRUE(has(st.warnings, "protected"));
    EXPECT_THROW((void)enable(v, kB2d30), ops::Denied);
    EXPECT_EQ(callsOn(v.bucket), calls);
    EXPECT_EQ(retentionMode(v), "unset");
    (void)up::unprotect(superUser, v.keyId, v.bucket, true);
}

// ---- refusals ------------------------------------------------------------------------------------------------------

TEST_F(RecoveryB2Test, SuspendingIsRefusedWithTheReason) {
    const auto v = createdVault();
    const auto calls = callsOn(v.bucket);
    try {
        (void)rec::suspendVersioning(superUser, v.id, true);
        FAIL() << "B2 can't suspend";
    } catch (const ops::Invalid& e) {
        EXPECT_NE(std::string(e.what()).find("--mode off"), std::string::npos) << e.what();
    }
    EXPECT_EQ(callsOn(v.bucket), calls);
    EXPECT_EQ(versioningPuts(), 0u);
}

TEST_F(RecoveryB2Test, AConcurrentChangeOfTheBucketIsAConflict) {
    const auto v = legacyManagedVault();
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->lifecycleConflictOnce.insert(v.bucket);
    }
    EXPECT_THROW((void)rec::update(superUser, v.id, modeOff(true)), ops::Conflict);
    EXPECT_EQ(retentionMode(v), "unset") << "nothing is recorded for a write that didn't happen";
    EXPECT_TRUE(audited(v.bucket, "recovery.history.off"));
    (void)rec::update(superUser, v.id, modeOff(true));
    EXPECT_EQ(retentionMode(v), "latest") << "a retry reads the bucket again";
}

TEST_F(RecoveryB2Test, AForeignRuleThatDeletesSoonerIsReported) {
    const auto v = createdVault();
    (void)enable(v, kB2d30);
    padmin::LifecycleRule foreign;
    foreign.id = "b2:(all files)";
    foreign.foreign = true;
    foreign.prefix = "";
    foreign.expire_noncurrent_days = 7;
    foreign.raw_json = R"({"fileNamePrefix":"","daysFromHidingToDeleting":7})";
    {
        std::scoped_lock lock(cloud->mutex);
        cloud->buckets.at(v.bucket).lifecycle.push_back(foreign);
    }
    const auto st = rec::status(superUser, v.id, /*refreshProvider=*/true);
    EXPECT_EQ(st.provider.effective_noncurrent_days.value_or(0), 7u);
    ASSERT_EQ(st.provider.foreign_noncurrent_rules.size(), 1u);
    EXPECT_EQ(st.provider.foreign_noncurrent_rules[0], "b2:(all files): 7 days");
    EXPECT_TRUE(has(st.warnings, "sooner than Vaulthalla's retention"));
    EXPECT_TRUE(has(st.warnings, ".vaulthalla/")) << "and it reaches the opaque vault's manifest";
}

TEST_F(RecoveryB2Test, DeletingProviderHistoryIsADataDestroyStepUp) {
    const auto v = legacyManagedVault();
    namespace su = auth::stepup;
    {
        // An agent can't produce a step-up: history off on a bucket that keeps everything is refused, nothing is sent.
        const su::Scope agent(su::Channel::Agent);
        const auto calls = callsOn(v.bucket);
        try {
            (void)rec::update(superUser, v.id, modeOff(true));
            FAIL() << "an agent deleted provider history";
        } catch (const ops::StepUpRequired& e) {
            EXPECT_EQ(e.family, "data.destroy");
        }
        EXPECT_EQ(callsOn(v.bucket), calls);
        EXPECT_EQ(retentionMode(v), "unset");
        // What deletes nothing needs no step-up: keeping every version (indefinite).
        EXPECT_NO_THROW((void)enable(v, kB2Forever));
    }
    {
        // The host (vh over the unix socket) never prompts.
        const su::Scope host(su::Channel::Host);
        EXPECT_NO_THROW((void)rec::update(superUser, v.id, modeOff(true)));
        EXPECT_EQ(retentionMode(v), "latest");
    }
}

}
