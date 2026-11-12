// A bucket's write capability (design/encryption/06-publish-without-preconditions.md §7; storage/s3/Capability.hpp).
//
// BucketProbe*          DB-free: every row of the probe's verdict table on the versioned fake bucket (conditional
//                       PUT supported / rejected with 501 as Backblaze B2 does / silently ignored; versions kept or
//                       not; GET If-Match honoured or not), the opaque_v1 request rules, cleanup by version id, a
//                       refused cleanup, a probe that can't reach a verdict, the stored JSON round trip.

#include "../helpers/versioned_bucket.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "storage/ObjectKeys.hpp"
#include "storage/s3/Capability.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

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

}
