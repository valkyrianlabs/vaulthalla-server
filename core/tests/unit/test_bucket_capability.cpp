// A bucket's write capability (design/encryption/06-publish-without-preconditions.md §7; storage/s3/Capability.hpp,
// storage/BucketCapability.hpp, migration 136).
//
// BucketProbe*          DB-free: every row of the probe's verdict table on the versioned fake bucket (conditional
//                       PUT supported / rejected with 501 as Backblaze B2 does / silently ignored; versions kept or
//                       not; GET If-Match honoured or not), the opaque_v1 request rules, cleanup by version id, a
//                       refused cleanup, a probe that can't reach a verdict, the stored JSON round trip.
// BucketCapabilityDb*   DB-backed: the verdict stored per vault and cleared by a bucket change; the path_v0 index on
//                       a bucket without conditional writes (the regression: it failed every pass before); an
//                       opaque_v1 vault there stalls with one clear reason, writes nothing of a manifest and is
//                       listed by health; a conditional bucket that starts refusing conditions is marked changed,
//                       stalls without retrying unconditionally, and alerts once; recovery envelopes are written
//                       plainly there; creating an encrypting vault on such a bucket is refused (CLI ↔ ws parity of
//                       `vh vault storage probe`: test_ops_parity_vault_storage.cpp).

#include "../helpers/db_suite.hpp"
#include "../helpers/versioned_bucket.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "db/Transactions.hpp"
#include "db/query/sync/Manifest.hpp"
#include "db/query/vault/BucketCapability.hpp"
#include "db/query/vault/Vault.hpp"
#include "notifications/OperatorNotificationBus.hpp"
#include "ops/Error.hpp"
#include "ops/Vaults.hpp"
#include "stats/model/SystemHealth.hpp"
#include "storage/BucketCapability.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/ObjectKeys.hpp"
#include "storage/s3/Capability.hpp"
#include "sync/manifest/Objects.hpp"
#include "sync/manifest/Store.hpp"
#include "sync/model/Event.hpp"
#include "sync/model/RemoteManifest.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <memory>
#include <string>

namespace vh::test_bucket_capability {

using storage::s3::WriteCapability;
using test_support::versioned::Versioning;
using test_support::versioned::VersionedBucket;
using Puts = VersionedBucket::ConditionalPuts;

namespace bucket_capability_test {

std::shared_ptr<VersionedBucket> bucketWith(const Versioning versioning, const Puts puts) {
    auto bucket = std::make_shared<VersionedBucket>(versioning);
    bucket->conditionalPuts = puts;
    bucket->md5Etags = true;
    return bucket;
}

std::string got(const storage::s3::ProbeResult& r, const std::string& step) {
    for (const auto& s : r.steps)
        if (s.step == step) return s.got;
    return "<missing>";
}

}

// ── BucketProbe: the verdict table (DB-free) ─────────────────────────────────────────────────────────────────────────

TEST(BucketProbe, AnS3BucketHonouringConditionsIsConditional) {
    namespace t = bucket_capability_test;
    const auto bucket = t::bucketWith(Versioning::Enabled, Puts::Supported);
    const auto r = storage::s3::probeBucket(*bucket);
    EXPECT_EQ(r.capability, WriteCapability::Conditional);
    EXPECT_EQ(r.conditional_put, "supported");
    EXPECT_TRUE(r.versioning);
    EXPECT_TRUE(r.get_if_match);
    EXPECT_TRUE(r.md5_etags);
    EXPECT_EQ(t::got(r, "put_if_none_match_absent"), "ok");
    EXPECT_EQ(t::got(r, "put_if_none_match_present"), "precondition_failed");
    EXPECT_EQ(t::got(r, "put_if_match_wrong"), "precondition_failed");
    EXPECT_EQ(t::got(r, "put_if_match_right"), "ok");
    EXPECT_EQ(r.leftover_versions, 0u);
    EXPECT_TRUE(bucket->keys().empty()) << "every probe version is deleted by id";
    EXPECT_GT(r.probed_at, 0);
}

TEST(BucketProbe, AnUnversionedBucketHonouringConditionsIsStillConditional) {
    const auto bucket = bucket_capability_test::bucketWith(Versioning::Unversioned, Puts::Supported);
    const auto r = storage::s3::probeBucket(*bucket);
    EXPECT_EQ(r.capability, WriteCapability::Conditional) << "versions are not needed with conditional writes";
    EXPECT_FALSE(r.versioning);
    EXPECT_TRUE(bucket->keys().empty()) << "unversioned: the key itself is deleted";
}

TEST(BucketProbe, ABackblazeLikeBucketRejectingConditionsIsVersionLog) {
    namespace t = bucket_capability_test;
    const auto bucket = t::bucketWith(Versioning::Enabled, Puts::Reject501);
    const auto r = storage::s3::probeBucket(*bucket);
    EXPECT_EQ(r.capability, WriteCapability::VersionLog);
    EXPECT_EQ(r.conditional_put, "rejected");
    EXPECT_EQ(t::got(r, "put_if_none_match_absent"), "not_implemented");
    EXPECT_TRUE(r.versioning);
    EXPECT_TRUE(r.get_if_match);
    EXPECT_EQ(r.leftover_versions, 0u);
    EXPECT_TRUE(bucket->keys().empty());
}

TEST(BucketProbe, ABucketSilentlyIgnoringConditionsIsVersionLogNeverConditional) {
    const auto bucket = bucket_capability_test::bucketWith(Versioning::Enabled, Puts::Ignore);
    const auto r = storage::s3::probeBucket(*bucket);
    EXPECT_EQ(r.conditional_put, "ignored");
    EXPECT_EQ(r.capability, WriteCapability::VersionLog)
        << "a provider that drops If-None-Match would let two writers overwrite each other unnoticed";
    EXPECT_TRUE(bucket->keys().empty());
}

TEST(BucketProbe, NeitherConditionsNorVersionsIsInsufficient) {
    for (const auto puts : {Puts::Reject501, Puts::Ignore}) {
        const auto bucket = bucket_capability_test::bucketWith(Versioning::Unversioned, puts);
        const auto r = storage::s3::probeBucket(*bucket);
        EXPECT_EQ(r.capability, WriteCapability::Insufficient);
        EXPECT_FALSE(r.versioning);
    }
    // Suspended versioning writes "null" ids: no versions to arbitrate with.
    const auto suspended = bucket_capability_test::bucketWith(Versioning::Suspended, Puts::Reject501);
    EXPECT_EQ(storage::s3::probeBucket(*suspended).capability, WriteCapability::Insufficient);
}

TEST(BucketProbe, ABucketIgnoringGetIfMatchIsInsufficientWhateverItsWrites) {
    const auto bucket = bucket_capability_test::bucketWith(Versioning::Enabled, Puts::Supported);
    bucket->ignoreGetIfMatch = true;
    const auto r = storage::s3::probeBucket(*bucket);
    EXPECT_FALSE(r.get_if_match);
    EXPECT_EQ(r.capability, WriteCapability::Insufficient) << "every pinned read relies on it";
}

TEST(BucketProbe, TheProbeHoldsToTheOpaqueRequestRules) {
    const auto bucket = bucket_capability_test::bucketWith(Versioning::Enabled, Puts::Reject501);
    bucket->setOpaqueLayout(true);
    const auto r = storage::s3::probeBucket(*bucket);
    EXPECT_EQ(r.capability, WriteCapability::VersionLog) << "no OpaqueRequestRefused: .vaulthalla/probe/<uid> is allowed";
    for (const auto& req : bucket->requests()) {
        EXPECT_TRUE(req.key.starts_with(storage::s3::kProbePrefix)) << req.key;
        EXPECT_TRUE(req.metadata.empty()) << "no x-amz-meta-*";
    }
}

TEST(BucketProbe, ARefusedCleanupIsCountedNotHidden) {
    const auto bucket = bucket_capability_test::bucketWith(Versioning::Enabled, Puts::Reject501);
    bucket->refuseDeletes = true;
    const auto r = storage::s3::probeBucket(*bucket);
    EXPECT_EQ(r.capability, WriteCapability::VersionLog);
    EXPECT_EQ(r.leftover_versions, 2u);
    EXPECT_EQ(bucket->keys().size(), 1u);
}

TEST(BucketProbe, AProbeThatCannotReachAVerdictThrowsAndCleansUp) {
    const auto bucket = bucket_capability_test::bucketWith(Versioning::Enabled, Puts::Supported);
    bucket->failAfter(VersionedBucket::Op::Put, VersionedBucket::Failure::Http503, 1);
    EXPECT_THROW((void)storage::s3::probeBucket(*bucket), storage::s3::ProbeFailed);
    EXPECT_TRUE(bucket->keys().empty()) << "what the probe wrote before the failure is deleted";
}

TEST(BucketProbe, TheStoredFormRoundTrips) {
    const auto bucket = bucket_capability_test::bucketWith(Versioning::Enabled, Puts::Reject501);
    const auto r = storage::s3::probeBucket(*bucket);
    const auto j = storage::s3::toJson(r);
    EXPECT_EQ(j.at("v"), 1);
    EXPECT_EQ(j.at("capability"), "version_log");
    const auto back = storage::s3::probeResultFromJson(j);
    EXPECT_EQ(back.capability, r.capability);
    EXPECT_EQ(back.conditional_put, r.conditional_put);
    EXPECT_EQ(back.steps.size(), r.steps.size());
    EXPECT_EQ(back.probed_at, r.probed_at);
    EXPECT_EQ(storage::s3::publishModeFromString("version_log"), WriteCapability::VersionLog);
    EXPECT_FALSE(storage::s3::publishModeFromString("insufficient")) << "not a stored manifest_publish value";
    EXPECT_TRUE(storage::s3::sendsPreconditions(WriteCapability::Unknown)) << "never probed: no silent downgrade";
    EXPECT_FALSE(storage::s3::sendsPreconditions(WriteCapability::VersionLog));
    EXPECT_EQ(storage::object_keys::classify(std::string(storage::s3::kProbePrefix) +
                                             crypto::id::toBase32(crypto::id::newObjectUid())),
              storage::object_keys::KeyClass::Metadata);
}

// ── BucketCapabilityDb (DB-backed) ───────────────────────────────────────────────────────────────────────────────────

class BucketCapabilityDbTest : public vh::test::db::Suite {
protected:
    static void SetUpTestSuite() { (void)setUpDbSuite("test_bucket_capability"); }
    static void TearDownTestSuite() {
        if (skipTests) return;
        tearDownDbSuite();
    }

    void TearDown() override {
        if (!skipTests) {
            storage::bucket_capability::setLazyProbingForTesting(std::nullopt);
            storage::bucket_capability::setControllerFactoryForTesting({});
        }
        Suite::TearDown();
    }

    unsigned int keyId{};

    unsigned int addKey() {
        auto apiKey = std::make_shared<vault::model::APIKey>(superUser->id, "cap_key_" + test::uniqueTag('k'),
                                                             vault::model::S3Provider::BackblazeB2,
                                                             "AKIACAPABILITYTEST00", "capability-secret-000000000000000",
                                                             "us-west-004", "https://s3.us-west-004.backblazeb2.com");
        return runtime::Deps::get().apiKeyManager->addAPIKey(apiKey);
    }

    // An S3 vault row with the given layout (bypassing ops, like test_manifest_db.cpp).
    std::shared_ptr<vault::model::S3Vault> s3Vault(const vault::model::StorageLayout layout) {
        if (!keyId) keyId = addKey();
        const auto tag = test::uniqueTag('c');
        auto s3 = std::make_shared<vault::model::S3Vault>("cap_" + tag, keyId, "cap-bucket-" + tag);
        s3->owner_id = superUser->id;
        s3->mount_point = "cap_" + tag;
        s3->encrypt_upstream = layout != vault::model::StorageLayout::Transparent;
        s3->storage_layout = layout;
        s3->id = db::query::vault::Vault::upsertVault(s3, std::make_shared<sync::model::RemotePolicy>());
        return std::dynamic_pointer_cast<vault::model::S3Vault>(db::query::vault::Vault::getVault(s3->id));
    }

    static void record(const unsigned int vaultId, VersionedBucket& bucket) {
        db::query::vault::BucketCapability::record(vaultId, storage::s3::probeBucket(bucket));
    }
};

TEST_F(BucketCapabilityDbTest, TheVerdictIsStoredPerVaultAndABucketChangeForgetsIt) {
    const auto v = s3Vault(vault::model::StorageLayout::Transparent);
    EXPECT_EQ(db::query::vault::BucketCapability::get(v->id).capability, WriteCapability::Unknown);
    const auto bucket = bucket_capability_test::bucketWith(Versioning::Enabled, Puts::Reject501);
    record(v->id, *bucket);
    const auto stored = db::query::vault::BucketCapability::get(v->id);
    EXPECT_EQ(stored.capability, WriteCapability::VersionLog);
    ASSERT_TRUE(stored.probe);
    EXPECT_EQ(stored.probe->conditional_put, "rejected");

    // Insufficient is stored as a probe without a manifest_publish value.
    const auto other = s3Vault(vault::model::StorageLayout::Transparent);
    const auto unversioned = bucket_capability_test::bucketWith(Versioning::Unversioned, Puts::Reject501);
    record(other->id, *unversioned);
    EXPECT_EQ(db::query::vault::BucketCapability::get(other->id).capability, WriteCapability::Insufficient);

    // Another bucket: the verdict goes with the old one.
    auto moved = std::make_shared<vault::model::S3Vault>(*v);
    moved->bucket = v->bucket + "-moved";
    (void)db::query::vault::Vault::upsertVault(moved, nullptr);
    EXPECT_EQ(db::query::vault::BucketCapability::get(v->id).capability, WriteCapability::Unknown);
    EXPECT_FALSE(db::query::vault::BucketCapability::get(v->id).probe);
}

TEST_F(BucketCapabilityDbTest, APathV0IndexPublishesPlainlyOnABucketWithoutConditionalWrites) {
    // The regression: on Backblaze B2 every changing pass of a vault without opaque storage failed at the index
    // publish (If-Match / If-None-Match answered 501). Unprobed, it still fails, typed; probed, the index is written.
    const auto v = s3Vault(vault::model::StorageLayout::Transparent);
    const auto bucket = bucket_capability_test::bucketWith(Versioning::Enabled, Puts::Reject501);
    const auto cloud = std::make_shared<storage::CloudEngine>(v, bucket);

    EXPECT_THROW(cloud->publishRemoteIndexManifest(std::nullopt), sync::model::SyncStalled)
        << "never probed: conditions are still sent, and the refusal stalls (nothing written without them)";
    EXPECT_FALSE(bucket->current(sync::model::remote_manifest::INDEX_V1_KEY));
    EXPECT_FALSE(db::query::vault::BucketCapability::get(v->id).changed_at)
        << "a bucket never probed is not 'changed': it is probed on its next use";

    record(v->id, *bucket);
    cloud->publishRemoteIndexManifestWithRetry();
    EXPECT_TRUE(bucket->current(sync::model::remote_manifest::INDEX_V1_KEY));
    cloud->publishRemoteIndexManifestWithRetry();
    EXPECT_EQ(bucket->history(sync::model::remote_manifest::INDEX_V1_KEY).size(), 2u) << "plain PUTs, one per publish";
}

TEST_F(BucketCapabilityDbTest, AnOpaqueVaultOnABackblazeLikeBucketPublishesAndARestartFindsItsRoot) {
    // Spec 06 §5: on a bucket without conditional writes that keeps versions, the root's provider versions arbitrate.
    const auto v = s3Vault(vault::model::StorageLayout::OpaqueV1);
    const auto bucket = bucket_capability_test::bucketWith(Versioning::Enabled, Puts::Reject501);
    record(v->id, *bucket);
    const std::string rootKey(sync::manifest::kRootKey);
    {
        const auto cloud = std::make_shared<storage::CloudEngine>(v, bucket);
        cloud->encryptionManager->load_key();
        cloud->publishRemoteIndexManifestWithRetry();
        const auto state = db::query::sync::Manifest::state(v->id);
        ASSERT_EQ(state.epoch, 1u);
        ASSERT_TRUE(state.root_version_id);
        EXPECT_EQ(*state.root_version_id, bucket->current(rootKey)->version_id);
        EXPECT_EQ(state.own_epoch, 1u);
        EXPECT_FALSE(state.base_version_id) << "a first root has no base";

        // Every later publish: the changed segments (none here), one root PUT and one ListObjectVersions.
        bucket->resetCounters();
        cloud->publishRemoteIndexManifestWithRetry();
        auto c = bucket->counters();
        EXPECT_EQ(c.put, 1u);
        EXPECT_EQ(c.list, 1u);
        EXPECT_EQ(c.get + c.head + c.del, 0u);
        const auto second = db::query::sync::Manifest::state(v->id);
        EXPECT_EQ(second.epoch, 2u);
        EXPECT_EQ(second.base_version_id, state.root_version_id);
        EXPECT_TRUE(second.settle_window.empty());

        // A pass that changed nothing: one HEAD.
        bucket->resetCounters();
        cloud->applyRemoteIndexMutation({});
        EXPECT_FALSE(cloud->refreshRemoteIndexFromManifestIfChanged());
        c = bucket->counters();
        EXPECT_EQ(c.head, 1u);
        EXPECT_EQ(c.put + c.get + c.list + c.del, 0u);
    }

    // A restart: another engine with the database only. Its first pass costs one HEAD; its first publish loads the
    // settled root by version id (one LIST, the root and its segments) and settles on it (a PUT, a LIST).
    const auto cloud = std::make_shared<storage::CloudEngine>(v, bucket);
    cloud->encryptionManager->load_key();
    bucket->resetCounters();
    EXPECT_FALSE(cloud->refreshRemoteIndexFromManifestIfChanged());
    EXPECT_EQ(bucket->counters().head, 1u);
    EXPECT_EQ(bucket->counters().list, 0u);
    bucket->resetCounters();
    cloud->publishRemoteIndexManifestWithRetry();
    const auto c = bucket->counters();
    const auto third = db::query::sync::Manifest::state(v->id);
    EXPECT_EQ(third.epoch, 3u);
    EXPECT_EQ(*third.root_version_id, bucket->current(rootKey)->version_id);
    EXPECT_EQ(c.list, 2u);
    EXPECT_EQ(c.put, 1u);
    EXPECT_EQ(c.del, 0u);
    RecordProperty("restart_publish_gets", static_cast<int>(c.get));
    EXPECT_GE(c.get, 1u) << "the settled root, by version id";
    EXPECT_EQ(bucket->history(rootKey).size(), 3u) << "one version per publish, nothing deleted";

    const auto health = stats::model::SystemHealth::snapshot();
    EXPECT_TRUE(std::ranges::none_of(health.vaultsManifestUnpublishable,
                                     [&](const auto& u) { return u.vaultId == v->id; }))
        << "a version_log bucket publishes: health has nothing to say";
}

TEST_F(BucketCapabilityDbTest, AnOpaqueVaultOnABucketWithNeitherStallsWithOneReasonAndWritesNoManifest) {
    const auto v = s3Vault(vault::model::StorageLayout::OpaqueV1);
    const auto bucket = bucket_capability_test::bucketWith(Versioning::Unversioned, Puts::Reject501);
    record(v->id, *bucket);
    const auto cloud = std::make_shared<storage::CloudEngine>(v, bucket);
    cloud->encryptionManager->load_key();
    bucket->resetCounters();

    try {
        cloud->publishRemoteIndexManifestWithRetry();
        FAIL() << "the publish must stall";
    } catch (const sync::model::SyncStalled& e) {
        EXPECT_TRUE(std::string(e.what()).starts_with("manifest_publish_unsupported: ")) << e.what();
    }
    EXPECT_EQ(bucket->counters().put, 0u) << "no segment, no hint, no root: never half a publish";
    EXPECT_TRUE(bucket->keys().empty());
    EXPECT_FALSE(db::query::sync::Manifest::state(v->id).epoch);

    const auto health = stats::model::SystemHealth::snapshot();
    const auto it = std::ranges::find_if(health.vaultsManifestUnpublishable,
                                         [&](const auto& u) { return u.vaultId == v->id; });
    ASSERT_NE(it, health.vaultsManifestUnpublishable.end());
    EXPECT_EQ(it->reason, "bucket_capability_insufficient");
    EXPECT_EQ(health.overallStatus, stats::model::SystemHealthStatus::Degraded);
    EXPECT_TRUE(nlohmann::json(health).at("vaults_manifest_unpublishable").is_array());
}

TEST_F(BucketCapabilityDbTest, AConditionalBucketThatStartsRefusingConditionsStallsAndAlertsOnce) {
    const auto v = s3Vault(vault::model::StorageLayout::Transparent);
    const auto bucket = bucket_capability_test::bucketWith(Versioning::Enabled, Puts::Supported);
    record(v->id, *bucket);
    const auto cloud = std::make_shared<storage::CloudEngine>(v, bucket);
    cloud->publishRemoteIndexManifestWithRetry();
    ASSERT_TRUE(bucket->current(sync::model::remote_manifest::INDEX_V1_KEY));

    // The endpoint changes under the vault: conditions are refused now. No silent downgrade.
    (void)notifications::OperatorNotificationBus::instance().drain(512);
    bucket->conditionalPuts = Puts::Reject501;
    const auto before = bucket->history(sync::model::remote_manifest::INDEX_V1_KEY).size();
    for (int pass = 0; pass < 2; ++pass)
        EXPECT_THROW(cloud->publishRemoteIndexManifest(std::nullopt), sync::model::SyncStalled);
    EXPECT_EQ(bucket->history(sync::model::remote_manifest::INDEX_V1_KEY).size(), before)
        << "nothing is written without the condition";
    const auto stored = db::query::vault::BucketCapability::get(v->id);
    EXPECT_EQ(stored.capability, WriteCapability::Conditional) << "still conditional: only a probe changes that";
    ASSERT_TRUE(stored.changed_at);
    std::size_t alerts = 0;
    for (const auto& a : notifications::OperatorNotificationBus::instance().drain(512))
        if (a.eventKey == "bucket_capability_changed") ++alerts;
    EXPECT_EQ(alerts, 1u) << "two stalled publishes, one alert";
    EXPECT_THROW((void)cloud->writeCapability(), sync::model::SyncStalled) << "stalled until probed again";
    EXPECT_TRUE(std::ranges::any_of(db::query::vault::BucketCapability::unpublishable(),
                                    [&](const auto& u) { return u.vault_id == v->id; }) == false)
        << "health lists opaque_v1 vaults only; this one stalls through its sync state";

    // The probe records what the bucket does now and clears the mark.
    record(v->id, *bucket);
    EXPECT_FALSE(db::query::vault::BucketCapability::get(v->id).changed_at);
    EXPECT_EQ(cloud->writeCapability(), WriteCapability::VersionLog);
    cloud->publishRemoteIndexManifestWithRetry();
    EXPECT_GT(bucket->history(sync::model::remote_manifest::INDEX_V1_KEY).size(), before);
}

TEST_F(BucketCapabilityDbTest, LazyProbingRecordsAnOlderBindingOnFirstUse) {
    const auto v = s3Vault(vault::model::StorageLayout::Transparent);
    const auto bucket = bucket_capability_test::bucketWith(Versioning::Enabled, Puts::Reject501);
    const auto cloud = std::make_shared<storage::CloudEngine>(v, bucket);
    EXPECT_EQ(cloud->writeCapability(), WriteCapability::Unknown) << "test mode never probes on its own";
    storage::bucket_capability::setLazyProbingForTesting(true);
    EXPECT_EQ(cloud->writeCapability(), WriteCapability::VersionLog);
    EXPECT_EQ(db::query::vault::BucketCapability::get(v->id).capability, WriteCapability::VersionLog);
    cloud->publishRemoteIndexManifestWithRetry();
    EXPECT_TRUE(bucket->current(sync::model::remote_manifest::INDEX_V1_KEY));
}

TEST_F(BucketCapabilityDbTest, AnEncryptingVaultIsCreatedOnAVersionLogBucketAndRefusedOnOneWithNeither) {
    // New encrypting vaults are opaque_v1: their manifest needs conditional writes or object versions (spec 06 §7).
    if (!keyId) keyId = addKey();
    // gtest_main makes new encrypting vaults path_v0 for the older suites; the product creates them opaque_v1.
    vault::model::setNewEncryptingLayoutForTesting(std::nullopt);
    struct RestoreLayout {
        ~RestoreLayout() { vault::model::setNewEncryptingLayoutForTesting(vault::model::StorageLayout::PathV0); }
    } restore;
    const auto createOn = [&](const std::shared_ptr<VersionedBucket>& bucket, const std::string& name) {
        storage::bucket_capability::setControllerFactoryForTesting(
            [bucket](unsigned int, const std::string&) -> std::shared_ptr<storage::s3::Controller> { return bucket; });
        return ops::vaults::create(superUser, {.name = name, .type = vault::model::VaultType::S3,
                                               .s3 = ops::vaults::S3Spec{.api_key_id = keyId,
                                                                         .bucket = "cap-enc-" + test::uniqueTag('b'),
                                                                         .encrypt_upstream = true}});
    };

    const auto b2 = createOn(bucket_capability_test::bucketWith(Versioning::Enabled, Puts::Reject501),
                             "cap_enc_" + test::uniqueTag('e'));
    ASSERT_TRUE(b2);
    const auto created = std::dynamic_pointer_cast<vault::model::S3Vault>(db::query::vault::Vault::getVault(b2->id));
    ASSERT_TRUE(created);
    EXPECT_EQ(created->storage_layout, vault::model::StorageLayout::OpaqueV1);
    EXPECT_EQ(db::query::vault::BucketCapability::get(b2->id).capability, WriteCapability::VersionLog);

    const auto name = "cap_enc_" + test::uniqueTag('e');
    try {
        (void)createOn(bucket_capability_test::bucketWith(Versioning::Unversioned, Puts::Reject501), name);
        FAIL() << "an encrypting vault must be refused on a bucket with neither";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "bucket_capability_insufficient");
    }
    EXPECT_FALSE(db::query::vault::Vault::vaultExists(name, superUser->id));
}

TEST_F(BucketCapabilityDbTest, EnvelopesAreWrittenPlainlyWhereConditionsAreRejected) {
    // Recipient enrollment failed on Backblaze B2 before spec 06: the envelope PUT carried If-None-Match. A kid is the
    // envelope's hash, so a plain PUT loses nothing.
    const auto v = s3Vault(vault::model::StorageLayout::OpaqueV1);
    const auto bucket = bucket_capability_test::bucketWith(Versioning::Enabled, Puts::Reject501);
    record(v->id, *bucket);
    const auto store = std::make_shared<sync::manifest::S3Store>(
        bucket, db::query::vault::BucketCapability::get(v->id).capability);
    const auto key = std::string(".vaulthalla/key/") + crypto::id::toBase32(crypto::id::newObjectUid());
    const std::vector<uint8_t> envelope{0x89, 'V', 'H', 'K'};
    (void)store->putOnce(key, envelope);
    (void)store->putOnce(key, envelope);
    EXPECT_EQ(bucket->current(key)->body, envelope);
    EXPECT_EQ(bucket->history(key).size(), 2u) << "the same bytes twice: idempotent without a condition";
}

}
