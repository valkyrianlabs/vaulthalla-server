// Backblaze B2 lifecycle rules through B2Admin (its native API, b2api v4), and the provider-versioning primitives on
// top of them, DB-free: every request goes through curl::http's test transport, which keeps one bucket the way B2
// does (a revision that every b2_update_bucket bumps and checks against ifRevisionIs, lifecycleRules, bucketInfo).
//  - reading: b2_list_buckets (every bucket type), rules mapped onto the provider-neutral model; a rule is
//    Vaulthalla's only when it equals one recorded in bucketInfo, everything else is foreign and kept verbatim;
//  - writing: one b2_update_bucket with ifRevisionIs = the revision read, the record of our rules in bucketInfo, every
//    other bucketInfo entry and every foreign rule as they were; a change in between is a 409 and nothing is written;
//  - what B2 can't hold (a disabled rule, a rule without a day value) and a key without writeBuckets are refused
//    before b2_update_bucket;
//  - recovery's applyRetention / applyLatestOnly / describeRetention over it: N days, indefinite and "latest" each give
//    the expected rule set, opaque_v1 vaults are scoped to o/ with nothing under .vaulthalla/, transparent vaults get
//    the whole bucket plus the manifest rule; a foreign rule that deletes sooner is reported;
//  - the capability contract per provider (AWS, B2, R2).

#include "recovery/provider/Capabilities.hpp"
#include "recovery/provider/Policy.hpp"
#include "storage/s3/curl/Http.hpp"
#include "storage/s3/provider/admin/Adapters.hpp"
#include "storage/upstream/Guard.hpp"
#include "storage/upstream/Lifecycle.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace vh::test_b2_lifecycle {

namespace admin = storage::s3::provider::admin;
namespace http = storage::s3::curl::http;
namespace lifecycle = storage::upstream::lifecycle;
namespace pol = vh::recovery::provider::policy;
namespace rp = vh::recovery::provider;
using vault::model::APIKey;
using vault::model::S3Provider;
using vault::model::StorageLayout;

constexpr const char* kBlKeyId = "0041234567890ab0000000001";
constexpr const char* kBlSecret = "K004LifecycleTestApplicationKey0001";
constexpr const char* kBlToken = "4_002LifecycleTokenForTheAccount0123";
constexpr const char* kBlApiUrl = "https://api004.backblazeb2.com";
constexpr const char* kBlBucket = "vault-bucket-b2";

std::shared_ptr<APIKey> blKey() {
    return std::make_shared<APIKey>(1, "b2-admin", S3Provider::BackblazeB2, kBlKeyId, kBlSecret, "us-west-004",
                                    "https://s3.us-west-004.backblazeb2.com");
}

http::Response blRespond(const long status, const std::string& body = {}) {
    http::Response r;
    r.status = status;
    r.body = body;
    return r;
}

nlohmann::json blRule(const std::string& prefix, const nlohmann::json& hide, const nlohmann::json& upload = nullptr,
                      const nlohmann::json& cancel = nullptr) {
    return {{"fileNamePrefix", prefix},
            {"daysFromHidingToDeleting", hide},
            {"daysFromUploadingToHiding", upload},
            {"daysFromStartingToCancelingUnfinishedLargeFiles", cancel}};
}

class B2Lifecycle : public ::testing::Test {
protected:
    // The bucket as B2 holds it.
    int64_t revision = 7;
    nlohmann::json rules = nlohmann::json::array();
    nlohmann::json info = nlohmann::json::object();
    std::vector<std::string> capabilities{"listBuckets", "readBuckets", "writeBuckets", "listFiles", "readFiles",
                                          "writeFiles", "deleteFiles"};
    // Runs before b2_update_bucket is answered: another writer changing the bucket in between.
    std::function<void()> beforeUpdate;
    std::vector<http::Request> sent;

    void SetUp() override {
        storage::upstream::guard::setForTesting({});
        http::setTransportForTesting([this](const http::Request& r) { return answer(r); });
        pol::setReadBackForTesting(1, std::chrono::milliseconds(0));
    }

    void TearDown() override {
        http::setTransportForTesting(std::nullopt);
        storage::upstream::guard::clearForTesting();
        pol::setReadBackForTesting(6, std::chrono::milliseconds(250));
    }

    nlohmann::json bucketJson() const {
        return {{"accountId", "acct0123"}, {"bucketId", "4a48fe8875c6214145260818"}, {"bucketName", kBlBucket},
                {"bucketType", "allPrivate"}, {"revision", revision}, {"lifecycleRules", rules}, {"bucketInfo", info}};
    }

    http::Response answer(const http::Request& r) {
        sent.push_back(r);
        if (r.url == admin::B2Admin::kAuthorizeUrl)
            return blRespond(200, nlohmann::json{{"accountId", "acct0123"},
                                                 {"authorizationToken", kBlToken},
                                                 {"apiInfo", {{"storageApi", {{"apiUrl", kBlApiUrl},
                                                                              {"allowed", {{"capabilities", capabilities},
                                                                                           {"buckets", nullptr}}}}}}}}
                                      .dump());
        if (r.url == std::string(kBlApiUrl) + "/b2api/v4/b2_list_buckets") {
            const auto body = nlohmann::json::parse(r.body);
            if (body.value("bucketName", "") != kBlBucket) return blRespond(200, R"({"buckets": []})");
            return blRespond(200, nlohmann::json{{"buckets", nlohmann::json::array({bucketJson()})}}.dump());
        }
        if (r.url == std::string(kBlApiUrl) + "/b2api/v4/b2_update_bucket") {
            if (beforeUpdate) beforeUpdate();
            const auto body = nlohmann::json::parse(r.body);
            if (!body.contains("ifRevisionIs") || body["ifRevisionIs"] != revision)
                return blRespond(409, R"({"status": 409, "code": "conflict", "message": "The ifRevisionIs test failed."})");
            if (body.contains("lifecycleRules")) rules = body["lifecycleRules"];
            if (body.contains("bucketInfo")) info = body["bucketInfo"];
            ++revision;
            return blRespond(200, bucketJson().dump());
        }
        // The S3-compatible API: HEAD, ?versioning, ?object-lock.
        if (r.url.find("?versioning") != std::string::npos)
            return blRespond(200, "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>");
        if (r.url.find("?object-lock") != std::string::npos)
            return blRespond(404, "<Error><Code>ObjectLockConfigurationNotFoundError</Code></Error>");
        if (r.method == "HEAD") return blRespond(200);
        return blRespond(404, R"({"status": 404, "code": "not_found", "message": "no such call"})");
    }

    [[nodiscard]] std::vector<http::Request> to(const std::string& api) const {
        std::vector<http::Request> out;
        for (const auto& r : sent)
            if (r.url.ends_with("/" + api)) out.push_back(r);
        return out;
    }

    // Another application's rule and bucketInfo entry, as they would be before Vaulthalla looks.
    void seedForeign() {
        rules = nlohmann::json::array({blRule("logs/", 7, 30), blRule("", nullptr, nullptr, 3)});
        info = {{"Cache-Control", "max-age=600"}, {"owner", "other-app"}};
    }

    [[nodiscard]] std::vector<nlohmann::json> rulesWithPrefix(const std::string& prefix) const {
        std::vector<nlohmann::json> out;
        for (const auto& r : rules)
            if (r.value("fileNamePrefix", "") == prefix) out.push_back(r);
        return out;
    }

    [[nodiscard]] nlohmann::json record() const {
        if (!info.contains(admin::kB2RuleRecordKey)) return nullptr;
        return nlohmann::json::parse(info[admin::kB2RuleRecordKey].get<std::string>());
    }
};

// ---- the mapping --------------------------------------------------------------------------------------------------

TEST_F(B2Lifecycle, ARuleIsOursOnlyWhenItEqualsARecordedOneEverythingElseIsForeignAndVerbatim) {
    const auto recordText = nlohmann::json{{"v", 1},
                                           {"rules", nlohmann::json::array({[] {
                                                auto j = blRule("o/", 30);
                                                j["id"] = "vaulthalla-managed";
                                                return j;
                                            }()})}}.dump();
    const nlohmann::json bucketInfo{{admin::kB2RuleRecordKey, recordText}, {"Cache-Control", "max-age=600"}};
    auto native = nlohmann::json::array({blRule("o/", 30), blRule("o/", 7), blRule("logs/", 7, 30),
                                         nlohmann::json{{"fileNamePrefix", "x/"}, {"daysFromHidingToDeleting", 2},
                                                        {"somethingNew", true}}});
    const auto mapped = admin::b2lifecycle::fromNative(native, bucketInfo);
    ASSERT_EQ(mapped.size(), 4u);
    EXPECT_EQ(mapped[0].id, "vaulthalla-managed");
    EXPECT_FALSE(mapped[0].foreign);
    EXPECT_EQ(mapped[0].expire_noncurrent_days.value_or(0), 30u);
    EXPECT_EQ(mapped[1].id, "b2:o/") << "the same prefix with other values was edited or added outside Vaulthalla";
    EXPECT_TRUE(mapped[1].foreign);
    EXPECT_TRUE(mapped[2].foreign);
    EXPECT_EQ(mapped[2].expire_current_days.value_or(0), 30u);
    EXPECT_TRUE(mapped[3].unmodeled) << "a field this model doesn't know";
    for (const auto& r : mapped) EXPECT_TRUE(r.enabled) << "B2 rules have no disabled state";

    // Written back: ours from the fields, every foreign rule exactly as listed, our record next to the other entries.
    const auto [rulesOut, infoOut] = admin::b2lifecycle::toNative(mapped, bucketInfo);
    ASSERT_EQ(rulesOut.size(), 4u);
    EXPECT_EQ(rulesOut[0], blRule("o/", 30));
    EXPECT_EQ(rulesOut[1], native[1]);
    EXPECT_EQ(rulesOut[2], native[2]);
    EXPECT_EQ(rulesOut[3], native[3]) << "even with a field Vaulthalla doesn't model";
    EXPECT_EQ(infoOut.at("Cache-Control"), "max-age=600");
    const auto rec = nlohmann::json::parse(infoOut.at(admin::kB2RuleRecordKey).get<std::string>());
    ASSERT_EQ(rec.at("rules").size(), 1u);
    EXPECT_EQ(rec.at("rules")[0].at("id"), "vaulthalla-managed");

    // Without a rule of ours the record goes; the rest of bucketInfo stays.
    const std::vector<admin::LifecycleRule> foreignOnly(mapped.begin() + 1, mapped.end());
    const auto [_, noRecord] = admin::b2lifecycle::toNative(foreignOnly, bucketInfo);
    EXPECT_FALSE(noRecord.contains(admin::kB2RuleRecordKey));
    EXPECT_EQ(noRecord.at("Cache-Control"), "max-age=600");

    // A corrupt record claims nothing.
    EXPECT_TRUE(admin::b2lifecycle::fromNative(native, {{admin::kB2RuleRecordKey, "{not json"}})[0].foreign);
}

TEST_F(B2Lifecycle, WhatB2CantHoldIsRefusedBeforeAnyWrite) {
    admin::B2Admin b2(blKey());
    admin::LifecycleRule disabled;
    disabled.id = "vaulthalla-managed";
    disabled.enabled = false;
    disabled.expire_noncurrent_days = 3;
    admin::LifecycleRule empty;
    empty.id = "vaulthalla-managed";
    admin::LifecycleRule zero;
    zero.id = "vaulthalla-managed";
    zero.expire_noncurrent_days = 0;
    for (const auto& r : {disabled, empty, zero})
        EXPECT_THROW(b2.putLifecycle(kBlBucket, {r}), std::invalid_argument);
    EXPECT_THROW(b2.putLifecycle("b2-reserved", {}), std::invalid_argument) << "B2's own name rules first";
    EXPECT_TRUE(sent.empty());
}

// ---- reading and writing ------------------------------------------------------------------------------------------

TEST_F(B2Lifecycle, InspectReadsTheRulesThroughTheNativeApi) {
    seedForeign();
    admin::B2Admin b2(blKey());
    EXPECT_TRUE(b2.supportsLifecycle());
    const auto config = b2.inspect(kBlBucket);
    EXPECT_TRUE(config.lifecycle_readable);
    EXPECT_FALSE(config.notifications_readable);
    EXPECT_EQ(config.versioning, admin::Versioning::Enabled);
    ASSERT_EQ(config.lifecycle.size(), 2u);
    EXPECT_TRUE(std::ranges::all_of(config.lifecycle, [](const admin::LifecycleRule& r) { return r.foreign; }));
    ASSERT_EQ(to("b2_list_buckets").size(), 1u);
    const auto body = nlohmann::json::parse(to("b2_list_buckets")[0].body);
    EXPECT_EQ(body.at("bucketName"), kBlBucket);
    EXPECT_EQ(body.at("bucketTypes"), nlohmann::json::array({"all"})) << "restricted and shared buckets too";
    EXPECT_EQ(to("b2_list_buckets")[0].headers.size(), 2u);

    // A second inspect on the same client authorizes once.
    (void)b2.inspect(kBlBucket);
    EXPECT_EQ(std::ranges::count_if(sent, [](const http::Request& r) { return r.url == admin::B2Admin::kAuthorizeUrl; }), 1);

    // A native failure never fails the inspect: the rules are reported unreadable.
    capabilities.clear();
    admin::B2Admin refused(blKey());
    http::setTransportForTesting([this](const http::Request& r) {
        if (r.url == admin::B2Admin::kAuthorizeUrl)
            return blRespond(401, R"({"status": 401, "code": "unauthorized", "message": "bad key"})");
        return answer(r);
    });
    const auto unreadable = refused.inspect(kBlBucket);
    EXPECT_FALSE(unreadable.lifecycle_readable);
    EXPECT_TRUE(std::ranges::any_of(unreadable.warnings, [](const std::string& w) {
        return w.find("native API") != std::string::npos;
    }));
    for (const auto& w : unreadable.warnings) EXPECT_EQ(w.find(kBlSecret), std::string::npos);
}

TEST_F(B2Lifecycle, AWriteIsConditionalOnTheRevisionReadAndKeepsEverythingElse) {
    seedForeign();
    admin::B2Admin b2(blKey());
    auto config = b2.inspect(kBlBucket);
    const auto merged = lifecycle::mergeOwnedRule(config.lifecycle, {.expire_noncurrent_days = 30u, .prefix = std::string("o/")},
                                                  true);
    b2.putLifecycle(kBlBucket, merged.rules);

    ASSERT_EQ(to("b2_update_bucket").size(), 1u);
    const auto update = to("b2_update_bucket")[0];
    const auto body = nlohmann::json::parse(update.body);
    EXPECT_EQ(body.at("ifRevisionIs"), 7) << "the revision the inspect read";
    EXPECT_EQ(body.at("bucketId"), "4a48fe8875c6214145260818");
    EXPECT_EQ(body.at("accountId"), "acct0123");
    EXPECT_EQ(revision, 8);
    ASSERT_EQ(rules.size(), 3u);
    EXPECT_EQ(rules[0], blRule("logs/", 7, 30)) << "foreign rules byte for byte";
    EXPECT_EQ(rules[1], blRule("", nullptr, nullptr, 3));
    EXPECT_EQ(rules[2], blRule("o/", 30));
    EXPECT_EQ(info.at("Cache-Control"), "max-age=600");
    EXPECT_EQ(info.at("owner"), "other-app");
    ASSERT_FALSE(record().is_null());
    EXPECT_EQ(record().at("rules")[0].at("id"), "vaulthalla-managed");
    for (const auto& r : sent) {
        EXPECT_EQ(r.body.find(kBlSecret), std::string::npos);
        if (!r.url.starts_with(kBlApiUrl)) continue;
        for (const auto& [k, v] : r.headers) {
            if (k == "Authorization") {
                EXPECT_EQ(v, kBlToken) << "native calls carry the session token";
            }
        }
    }

    // Read back, the rule is ours again (matched against the record), and a second identical merge changes nothing.
    config = b2.inspect(kBlBucket);
    const auto ours = std::ranges::find_if(config.lifecycle, [](const admin::LifecycleRule& r) { return !r.foreign; });
    ASSERT_NE(ours, config.lifecycle.end());
    EXPECT_EQ(ours->id, lifecycle::kOwnedRuleId);
    EXPECT_FALSE(lifecycle::mergeOwnedRule(config.lifecycle, {.expire_noncurrent_days = 30u, .prefix = std::string("o/")},
                                           true).changed);
}

TEST_F(B2Lifecycle, AConcurrentChangeIsAConflictAndNothingIsWritten) {
    seedForeign();
    admin::B2Admin b2(blKey());
    const auto config = b2.inspect(kBlBucket);
    // Someone adds a rule in the Backblaze console between Vaulthalla's read and its write.
    beforeUpdate = [this] {
        rules.push_back(blRule("tmp/", 1));
        ++revision;
        beforeUpdate = nullptr;
    };
    const auto merged = lifecycle::mergeOwnedRule(config.lifecycle, {.expire_noncurrent_days = 30u}, true);
    try {
        b2.putLifecycle(kBlBucket, merged.rules);
        FAIL() << "a write over a changed bucket must be refused";
    } catch (const admin::ProviderError& e) {
        EXPECT_EQ(e.http_status, 409);
        EXPECT_NE(std::string(e.what()).find("nothing was written"), std::string::npos) << e.what();
    }
    EXPECT_EQ(rules.size(), 3u);
    EXPECT_EQ(rules[2], blRule("tmp/", 1)) << "the other writer's change stands";
    EXPECT_FALSE(info.contains(admin::kB2RuleRecordKey));

    // Through recovery's GET-merge-PUT-GET it surfaces as the same 409 (ops maps it to a Conflict).
    beforeUpdate = [this] {
        ++revision;
        beforeUpdate = nullptr;
    };
    admin::B2Admin again(blKey());
    EXPECT_THROW((void)pol::applyRetention(again, kBlBucket, {.indefinite = false, .days = 30}, true,
                                           rp::ruleScopeFor("backblaze-b2", StorageLayout::OpaqueV1)),
                 admin::ProviderError);
    EXPECT_FALSE(info.contains(admin::kB2RuleRecordKey));
}

TEST_F(B2Lifecycle, AKeyWithoutWriteBucketsIsRefusedBeforeTheUpdate) {
    capabilities = {"listBuckets", "listFiles", "readFiles", "writeFiles"};
    admin::B2Admin b2(blKey());
    const auto config = b2.inspect(kBlBucket);
    EXPECT_TRUE(config.lifecycle_readable) << "listBuckets reads them";
    try {
        b2.putLifecycle(kBlBucket, lifecycle::mergeOwnedRule(config.lifecycle, {.expire_noncurrent_days = 1u}, true).rules);
        FAIL();
    } catch (const admin::CapabilityMissing& e) {
        EXPECT_EQ(e.capability, "writeBuckets");
    }
    EXPECT_TRUE(to("b2_update_bucket").empty());
    const auto probe = b2.probe();
    const auto lc = std::ranges::find_if(probe.items, [](const admin::Capability& c) { return c.name == "lifecycle"; });
    ASSERT_NE(lc, probe.items.end());
    EXPECT_FALSE(lc->ok);
    EXPECT_NE(lc->detail.find("writeBuckets"), std::string::npos);
}

// ---- recovery's rules on B2 ---------------------------------------------------------------------------------------

TEST_F(B2Lifecycle, NDaysIndefiniteAndLatestEachGiveTheirRuleSetOnAnOpaqueVault) {
    seedForeign();
    const auto scope = rp::ruleScopeFor("backblaze-b2", StorageLayout::OpaqueV1);
    const pol::VaultView view{.data_prefix = "o/", .protect_metadata = true, .warn_current_expiry = true};
    ASSERT_EQ(scope.prefix.value_or("?"), "o/");
    EXPECT_FALSE(scope.manifest_rule);

    {
        admin::B2Admin b2(blKey());
        const auto r = pol::applyRetention(b2, kBlBucket, {.indefinite = false, .days = 30}, true, scope, view);
        EXPECT_TRUE(r.written);
        ASSERT_EQ(rulesWithPrefix("o/").size(), 1u);
        EXPECT_EQ(rulesWithPrefix("o/")[0], blRule("o/", 30));
        EXPECT_TRUE(rulesWithPrefix(".vaulthalla/").empty()) << "nothing may delete the manifest's older roots";
        EXPECT_EQ(r.effective_days.value_or(0), 30u);
        ASSERT_EQ(r.vaulthalla_rules.size(), 1u);
        EXPECT_NE(r.vaulthalla_rules[0].find("'o/'"), std::string::npos);
        EXPECT_FALSE(std::ranges::any_of(r.warnings, [](const std::string& w) { return w.find("logs/") != std::string::npos; }))
            << "logs/ hides current files, but none of this vault's (they are under o/)";
    }
    {
        admin::B2Admin b2(blKey());
        (void)pol::applyRetention(b2, kBlBucket, {.indefinite = true, .days = 0}, true, scope, view);
        EXPECT_TRUE(rulesWithPrefix("o/").empty()) << "indefinite: no rule of ours";
        EXPECT_TRUE(record().is_null()) << "and no record";
        EXPECT_EQ(rules.size(), 2u) << "the foreign rules stay";
    }
    {
        admin::B2Admin b2(blKey());
        const auto r = pol::applyLatestOnly(b2, kBlBucket, scope, view);
        EXPECT_TRUE(r.written);
        ASSERT_EQ(rulesWithPrefix("o/").size(), 1u);
        EXPECT_EQ(rulesWithPrefix("o/")[0], blRule("o/", 1)) << "B2's keep-only-the-latest-version, on the vault's files";
        EXPECT_EQ(r.effective_days.value_or(0), 1u);
        const auto again = pol::applyLatestOnly(b2, kBlBucket, scope, view);
        EXPECT_FALSE(again.written) << "already so: nothing sent";
    }
}

TEST_F(B2Lifecycle, ATransparentVaultGetsTheWholeBucketAndTheManifestRule) {
    const auto scope = rp::ruleScopeFor("backblaze-b2", StorageLayout::Transparent);
    EXPECT_EQ(scope.prefix.value_or("?"), "");
    EXPECT_TRUE(scope.manifest_rule);
    EXPECT_EQ(rp::ruleScopeFor("backblaze-b2", StorageLayout::PathV0).prefix.value_or("?"), "");

    admin::B2Admin b2(blKey());
    (void)pol::applyLatestOnly(b2, kBlBucket, scope);
    EXPECT_EQ(rulesWithPrefix(""), std::vector<nlohmann::json>{blRule("", 1)}) << "B2's documented keep-only-the-last-version";
    EXPECT_EQ(rulesWithPrefix(".vaulthalla/"), std::vector<nlohmann::json>{blRule(".vaulthalla/", 1)});
    ASSERT_EQ(record().at("rules").size(), 2u);

    admin::B2Admin later(blKey());
    (void)pol::applyRetention(later, kBlBucket, {.indefinite = true, .days = 0}, true, scope);
    EXPECT_TRUE(rulesWithPrefix("").empty());
    EXPECT_EQ(rulesWithPrefix(".vaulthalla/").size(), 1u) << "the index's old copies still go after a day";
}

TEST_F(B2Lifecycle, AnEarlierWholeBucketRuleIsReScopedAndAForeignShorterRuleIsReported) {
    // A path_v0 vault's rule, then the vault moved to opaque storage (vh vault migrate-layout): the next write scopes
    // it to o/ and drops the manifest rule, which would now delete the manifest's older roots.
    admin::B2Admin first(blKey());
    (void)pol::applyRetention(first, kBlBucket, {.indefinite = false, .days = 30}, true,
                              rp::ruleScopeFor("backblaze-b2", StorageLayout::PathV0));
    ASSERT_EQ(rulesWithPrefix("").size(), 1u);
    rules.push_back(blRule("", 5));   // someone else's whole-bucket rule, shorter

    const pol::VaultView view{.data_prefix = "o/", .protect_metadata = true, .warn_current_expiry = true};
    admin::B2Admin b2(blKey());
    const auto r = pol::applyRetention(b2, kBlBucket, {.indefinite = false, .days = 30}, true,
                                       rp::ruleScopeFor("backblaze-b2", StorageLayout::OpaqueV1), view);
    EXPECT_EQ(rulesWithPrefix("o/"), std::vector<nlohmann::json>{blRule("o/", 30)});
    EXPECT_TRUE(rulesWithPrefix(".vaulthalla/").empty());
    EXPECT_EQ(rulesWithPrefix(""), std::vector<nlohmann::json>{blRule("", 5)}) << "the foreign rule stays";
    EXPECT_EQ(r.foreign_whole_days.value_or(0), 5u);
    EXPECT_EQ(r.effective_days.value_or(0), 5u) << "the smallest value of every matching rule applies on B2";
    EXPECT_TRUE(std::ranges::any_of(r.warnings, [](const std::string& w) {
        return w.find(".vaulthalla/") != std::string::npos && w.find("b2:(all files)") != std::string::npos;
    })) << "a foreign whole-bucket rule reaches the opaque vault's manifest";
}

// ---- the contract -------------------------------------------------------------------------------------------------

TEST(B2LifecycleContract, CapabilitiesPerProvider) {
    const auto aws = rp::capabilitiesOf("aws-s3");
    EXPECT_TRUE(aws.enable && aws.suspend && aws.retention_days && aws.retention_indefinite && aws.restore_copy);
    EXPECT_FALSE(aws.always_versioned);
    EXPECT_FALSE(aws.history_off);
    EXPECT_EQ(aws.propagation_minutes, 15u);

    const auto b2 = rp::capabilitiesOf("backblaze-b2");
    EXPECT_TRUE(b2.always_versioned && b2.retention_days && b2.retention_indefinite && b2.history_off);
    EXPECT_TRUE(b2.list_versions && b2.restore_transfer);
    EXPECT_FALSE(b2.enable);
    EXPECT_FALSE(b2.suspend);
    EXPECT_FALSE(b2.restore_copy) << "no documented CopyObject from a version id";
    EXPECT_EQ(b2.propagation_minutes, 0u);
    EXPECT_TRUE(std::ranges::any_of(b2.unsupported, [](const std::string& u) { return u.starts_with("suspend: "); }));

    const auto r2 = rp::capabilitiesOf("cloudflare-r2");
    EXPECT_FALSE(r2.retention_days || r2.retention_indefinite || r2.history_off || r2.list_versions);
    EXPECT_EQ(rp::unsupportedReason("cloudflare-r2"), admin::kR2VersioningUnsupported);
    EXPECT_TRUE(rp::unsupportedReason("aws-s3").empty());
    EXPECT_TRUE(rp::unsupportedReason("backblaze-b2").empty());
    EXPECT_FALSE(rp::unsupportedReason("s3:minio").empty());

    // AWS rules stay where they are (as before); only B2 is scoped by layout.
    EXPECT_FALSE(rp::ruleScopeFor("aws-s3", StorageLayout::OpaqueV1).prefix);
    EXPECT_TRUE(rp::ruleScopeFor("aws-s3", StorageLayout::OpaqueV1).manifest_rule);
}

}
