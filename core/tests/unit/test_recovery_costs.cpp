// Provider versioning cost model (recovery.md "Costs"): golden decimal figures from the signed price-bot catalog
// (core/test-assets/pricing/versioning, loaded through the real PriceCatalogStore with signature verification),
// thin observations as ranges, illustrative scenarios without data, unpriced reports with no money at all, the
// unverified-catalog flag, the IA minimum storage duration, and month-to-date from noncurrent byte-hours.
// DB-free: estimate() is a pure function of its inputs.

#include "../helpers/recovery_pricing.hpp"

#include "ops/RecoveryJson.hpp"
#include "recovery/cost/Estimator.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <fstream>
#include <functional>

namespace vh::test_recovery_costs {

namespace cost = vh::recovery::cost;
namespace rq = db::query::recovery;
namespace pricing = storage::s3::pricing;
using vh::recovery::ProviderRetention;

constexpr std::time_t kNow = 1792065600;   // 2026-10-15T12:00:00Z

cost::CatalogInfo profileFor(const std::string& provider, const std::string& region, const std::string& storageClass,
                             const bool verified = true) {
    auto store = test_support::recovery_pricing::catalogStore(verified);
    const auto result = store->getProfile({.provider = provider, .region = region, .storage_class = storageClass});
    cost::CatalogInfo info;
    EXPECT_TRUE(result.ok) << result.error;
    if (!result.ok) return info;
    info.profile = result.profile;
    info.verified = result.signature_verified;
    info.stale = result.stale;
    info.source = result.source;
    info.age_seconds = result.age_seconds;
    return info;
}

std::vector<rq::UsageDay> days(const std::vector<uint64_t>& overwrittenPerDay, const uint64_t overwritesPerDay = 10,
                               const uint64_t manifestPutsPerDay = 24) {
    std::vector<rq::UsageDay> out;
    unsigned d = 1;
    for (const auto bytes : overwrittenPerDay) {
        rq::UsageDay day;
        day.vault_id = 7;
        day.day = "2026-10-" + std::string(d < 10 ? "0" : "") + std::to_string(d);
        day.counters.overwritten_bytes = bytes;
        day.counters.overwrite_objects = overwritesPerDay;
        day.counters.put_requests = overwritesPerDay + manifestPutsPerDay;
        out.push_back(day);
        ++d;
    }
    return out;
}

cost::Inputs baseInputs() {
    cost::Inputs in;
    in.vault_id = 7;
    in.provider = "aws-s3";
    in.bucket = "vh-costs";
    in.region = "us-east-2";
    in.storage_class = "standard";
    in.current_objects = 1000;
    in.current_bytes = 100'000'000'000ull;
    in.average_key_bytes = 40;
    in.versioning_status = "unversioned";
    in.now = kNow;
    return in;
}

const vh::recovery::RetentionScenario& scenario(const vh::recovery::CostReport& r, const std::string& name) {
    const auto it = std::ranges::find(r.scenarios, name, &vh::recovery::RetentionScenario::retention);
    EXPECT_NE(it, r.scenarios.end()) << name;
    return *it;
}

// The fixture catalog verifies against its public key, and a tampered profile does not load.
TEST(RecoveryCostCatalog, LoadsTheSignedFixtureThroughTheRealStore) {
    const auto info = profileFor("aws-s3", "us-east-2", "standard");
    ASSERT_TRUE(info.profile);
    EXPECT_TRUE(info.verified);
    EXPECT_FALSE(info.stale);
    EXPECT_EQ(info.profile->raw.at("versioning").at("status"), "supported");

    const auto dir = test_support::recovery_pricing::copyFixture();
    {
        std::ofstream f(dir / "profiles/aws-s3/us-east-2/standard.json", std::ios::app);
        f << " ";
    }
    config::StorageRatesApiConfig cfg;
    cfg.signature_warning_only = false;
    cfg.signature_public_key_path = dir / "public-key.pem";
    cfg.cache_ttl_seconds = cfg.refresh_interval_seconds = 365u * 24 * 3600;
    pricing::PriceCatalogStore tampered(cfg, nullptr, dir);
    EXPECT_FALSE(tampered.getProfile({.provider = "aws-s3", .region = "us-east-2", .storage_class = "standard"}).ok);
}

// Hand-computed: 10 days of 1 GB/day overwritten (10 objects/day, 24 manifest publishes/day), 1000 current objects
// (manifest ≈ 256000 bytes), S3 Standard us-east-2 at 0.023 USD per GB-month, retention 30 days:
//   versions  1e9 B/day × 30 d                  = 30 000 000 000 B
//   manifest  24/day × 256 000 B × 2 d          =     12 288 000 B
//   monthly   30 012 288 000 B × 0.023 / 1e9    = 0.690282624 USD → "0.69028262"
TEST(RecoveryCostModel, GoldenFiguresForAMeasuredStandardBucket) {
    auto in = baseInputs();
    in.catalog = profileFor("aws-s3", "us-east-2", "standard");
    in.usage = days(std::vector<uint64_t>(10, 1'000'000'000ull));
    in.retention = ProviderRetention{.indefinite = false, .days = 30};
    const auto r = cost::estimate(in);

    ASSERT_TRUE(r.priced) << r.unpriced_reason.value_or("");
    EXPECT_EQ(r.phase, "pre_activation");
    EXPECT_EQ(r.currency.value_or(""), "USD");
    EXPECT_EQ(r.confidence, "high");
    EXPECT_TRUE(r.catalog.verified);
    EXPECT_EQ(r.observation.window_days, 10u);
    EXPECT_TRUE(r.observation.sufficient);
    EXPECT_EQ(r.observation.overwritten_bytes_per_day, "1000000000");
    EXPECT_EQ(r.pre_activation_monthly.basis, "observed");
    ASSERT_TRUE(r.pre_activation_monthly.expected);
    EXPECT_EQ(r.pre_activation_monthly.expected->amount, "0.69028262");
    EXPECT_FALSE(r.pre_activation_monthly.low) << "enough days measured: one figure, no range";
    EXPECT_EQ(r.projected_monthly.expected->amount, "0.69028262");
    EXPECT_EQ(r.current.monthly_storage->amount, "2.30000000");

    // 90 d: 90e9 + 12 288 000 B; 365 d and indefinite (12 months = 365 days): 365e9 + 12 288 000 B.
    EXPECT_EQ(scenario(r, "30d").monthly_cost.expected->amount, "0.69028262");
    EXPECT_EQ(scenario(r, "30d").steady_noncurrent_bytes, 30'000'000'000ull);
    EXPECT_EQ(scenario(r, "90d").monthly_cost.expected->amount, "2.07028262");
    EXPECT_EQ(scenario(r, "365d").monthly_cost.expected->amount, "8.39528262");
    EXPECT_EQ(scenario(r, "indefinite").monthly_cost.expected->amount, "8.39528262");
    EXPECT_EQ(scenario(r, "indefinite").steady_noncurrent_bytes, 365'000'000'000ull);

    ASSERT_EQ(r.accumulation.size(), 12u);
    EXPECT_EQ(r.accumulation.front().noncurrent_bytes, 30'000'000'000ull) << "month 1 (30.4 d) is past the 30 d retention";
    EXPECT_EQ(r.accumulation.back().monthly_cost.expected->amount, "0.69028262");

    // Restore by transfer: 0.09 egress + 0.0004/1000 GET + 0.005/1000 PUT; by copy: 0.005/1000 COPY + 0.0004/1000 HEAD.
    EXPECT_EQ(r.recovery_per_gb.expected->amount, "0.09000540");
    EXPECT_EQ(r.recovery_per_object.expected->amount, "0.00000540");

    EXPECT_FALSE(r.current_month_to_date.expected) << "versioning isn't active yet";
    EXPECT_FALSE(r.history.unaccounted_history) << "an unversioned bucket has no hidden history";
    EXPECT_FALSE(r.unmodeled.empty());
    EXPECT_NE(std::ranges::find(r.unmodeled, "taxes"), r.unmodeled.end());

    // Money is a decimal string in JSON, never a number.
    const nlohmann::json j = r;
    EXPECT_TRUE(j.at("pre_activation_monthly").at("expected").at("amount").is_string());
}

TEST(RecoveryCostModel, FewDaysGiveALowConfidenceRange) {
    auto in = baseInputs();
    in.catalog = profileFor("aws-s3", "us-east-2", "standard");
    in.usage = days({1'000'000'000ull, 2'000'000'000ull, 3'000'000'000ull});
    in.retention = ProviderRetention{.indefinite = false, .days = 30};
    const auto r = cost::estimate(in);
    EXPECT_EQ(r.confidence, "low");
    EXPECT_FALSE(r.observation.sufficient);
    const auto& f = r.pre_activation_monthly;
    ASSERT_TRUE(f.expected && f.low && f.high);
    // expected 2e9 B/day, low 1e9, high 3e9 (manifest 12 288 000 B each).
    EXPECT_EQ(f.expected->amount, "1.38028262");
    EXPECT_EQ(f.low->amount, "0.69028262");
    EXPECT_EQ(f.high->amount, "2.07028262");
}

TEST(RecoveryCostModel, NoMeasurementsGiveLabelledIllustrativeScenarios) {
    auto in = baseInputs();
    in.catalog = profileFor("aws-s3", "us-east-2", "standard");
    const auto r = cost::estimate(in);
    EXPECT_TRUE(r.priced);
    EXPECT_EQ(r.confidence, "low");
    EXPECT_EQ(r.observation.window_days, 0u);
    EXPECT_FALSE(r.pre_activation_monthly.expected) << "no retention chosen: the scenarios carry the figures";
    for (const auto& sc : r.scenarios) {
        EXPECT_EQ(sc.monthly_cost.basis, "illustrative") << sc.retention;
        ASSERT_TRUE(sc.monthly_cost.expected && sc.monthly_cost.low && sc.monthly_cost.high) << sc.retention;
        EXPECT_LT(std::stod(sc.monthly_cost.low->amount), std::stod(sc.monthly_cost.expected->amount));
        EXPECT_LT(std::stod(sc.monthly_cost.expected->amount), std::stod(sc.monthly_cost.high->amount));
    }
    EXPECT_TRUE(std::ranges::any_of(r.assumptions, [](const auto& a) { return a.kind == "illustrative"; }));
}

TEST(RecoveryCostModel, NoProfileMeansUnpricedAndNoMoneyAnywhere) {
    auto in = baseInputs();
    in.catalog.error = "pricing profile not found in catalog: aws-s3/ap-south-9/standard";
    in.usage = days(std::vector<uint64_t>(10, 1'000'000'000ull));
    in.retention = ProviderRetention{.indefinite = false, .days = 30};
    in.versioning_status = "enabled";
    in.month_to_date_byte_hours = "730000000000";
    const auto r = cost::estimate(in);
    EXPECT_FALSE(r.priced);
    EXPECT_EQ(r.confidence, "none");
    ASSERT_TRUE(r.unpriced_reason);
    EXPECT_NE(r.unpriced_reason->find("not found"), std::string::npos);

    const nlohmann::json j = r;
    std::function<void(const nlohmann::json&, const std::string&)> noMoney = [&](const nlohmann::json& v, const std::string& at) {
        if (v.is_object()) {
            if (v.contains("amount") && v.contains("currency")) ADD_FAILURE() << "money at " << at << ": " << v.dump();
            for (const auto& [k, child] : v.items())
                if (k != "alert") noMoney(child, at + "." + k);
        } else if (v.is_array()) {
            for (size_t i = 0; i < v.size(); ++i) noMoney(v[i], at + "[" + std::to_string(i) + "]");
        }
    };
    noMoney(j, "report");
    EXPECT_EQ(r.scenarios.size(), 4u) << "the byte figures are still there";
    EXPECT_EQ(r.scenarios.front().steady_noncurrent_bytes, 30'000'000'000ull);
    EXPECT_TRUE(r.pre_activation_monthly.reason);
}

TEST(RecoveryCostModel, ProvidersWithoutVersioningAreUnpriced) {
    auto in = baseInputs();
    in.provider = "cloudflare-r2";
    in.catalog = profileFor("cloudflare-r2", "global", "standard");
    const auto r = cost::estimate(in);
    EXPECT_FALSE(r.priced);
    EXPECT_NE(r.unpriced_reason.value_or("").find("versioning"), std::string::npos) << r.unpriced_reason.value_or("");
}

TEST(RecoveryCostModel, AnUnverifiedCatalogIsFlagged) {
    auto in = baseInputs();
    in.catalog = profileFor("aws-s3", "us-east-2", "standard", /*verified=*/false);
    in.catalog.note = "no public key configured: signature not verified";
    in.usage = days(std::vector<uint64_t>(10, 1'000'000'000ull));
    in.retention = ProviderRetention{.indefinite = false, .days = 30};
    const auto r = cost::estimate(in);
    EXPECT_TRUE(r.priced);
    EXPECT_FALSE(r.catalog.verified);
    EXPECT_TRUE(r.catalog.note);
    EXPECT_EQ(r.confidence, "medium");
    EXPECT_TRUE(std::ranges::any_of(r.confidence_reasons, [](const auto& s) { return s.find("not verified") != std::string::npos; }));
}

// Standard-IA bills 30 days at least: a 7-day retention costs what a 30-day one does (more stored history isn't
// kept, but the early expiration still bills the remaining days).
//   versions 1e9 B/day × 30 d = 30e9 B; manifest 24/day × 256 000 B × 30 d = 184 320 000 B
//   (30e9 + 184 320 000) × 0.0125 / 1e9 = 0.377304 USD
TEST(RecoveryCostModel, InfrequentAccessMinimumDurationBillsShortRetentions) {
    auto in = baseInputs();
    in.storage_class = "standard-ia";
    in.catalog = profileFor("aws-s3", "us-east-2", "standard-ia");
    in.usage = days(std::vector<uint64_t>(10, 1'000'000'000ull));
    in.retention = ProviderRetention{.indefinite = false, .days = 7};
    const auto week = cost::estimate(in);
    in.retention = ProviderRetention{.indefinite = false, .days = 30};
    const auto month = cost::estimate(in);
    ASSERT_TRUE(week.priced && month.priced);
    EXPECT_EQ(week.pre_activation_monthly.expected->amount, "0.37730400");
    EXPECT_EQ(month.pre_activation_monthly.expected->amount, "0.37730400");
    EXPECT_EQ(week.accumulation.front().noncurrent_bytes, 7'000'000'000ull) << "only a week of history is kept";
    EXPECT_TRUE(std::ranges::any_of(week.assumptions, [](const auto& a) {
        return a.kind == "provider_rule" && a.text.find("30 days") != std::string::npos;
    }));
    // A 7-day scenario isn't listed, but the 30d one notes the minimum size; recovery adds IA retrieval per GB.
    EXPECT_TRUE(std::ranges::any_of(scenario(month, "30d").notes, [](const auto& n) { return n.find("131072") != std::string::npos; }));
    EXPECT_EQ(month.recovery_per_gb.expected->amount, "0.10001100");   // 0.09 + 0.01 + 0.001/1000 + 0.01/1000
}

TEST(RecoveryCostModel, MonthToDateComesFromNoncurrentByteHours) {
    auto in = baseInputs();
    in.catalog = profileFor("aws-s3", "us-east-2", "standard");
    in.usage = days(std::vector<uint64_t>(10, 1'000'000'000ull));
    in.retention = ProviderRetention{.indefinite = false, .days = 30};
    in.versioning_status = "enabled";
    in.enabled_by_vaulthalla = true;
    in.history.versions = 3;
    in.history.bytes = 1'000'000'000ull;
    in.month_to_date_byte_hours = "730000000000";   // 1 GB for a whole billing month
    in.active = true;
    const auto r = cost::estimate(in);
    EXPECT_EQ(r.phase, "active");
    ASSERT_TRUE(r.current_month_to_date.expected);
    EXPECT_EQ(r.current_month_to_date.expected->amount, "0.02300000");
    ASSERT_TRUE(r.current_month_projected.expected);
    EXPECT_GT(std::stod(r.current_month_projected.expected->amount), 0.023) << "the rest of the month adds to it";
}

TEST(RecoveryCostModel, AlertComparesTheProjectedSurcharge) {
    auto in = baseInputs();
    in.catalog = profileFor("aws-s3", "us-east-2", "standard");
    in.usage = days(std::vector<uint64_t>(10, 1'000'000'000ull));
    in.retention = ProviderRetention{.indefinite = false, .days = 30};
    in.alert_threshold = "0.50";
    EXPECT_TRUE(cost::estimate(in).alert.exceeded);
    in.alert_threshold = "0.70";
    EXPECT_FALSE(cost::estimate(in).alert.exceeded);
}

TEST(RecoveryCostModel, ForeignShorterRuleCapsTheRetention) {
    auto in = baseInputs();
    in.catalog = profileFor("aws-s3", "us-east-2", "standard");
    in.usage = days(std::vector<uint64_t>(10, 1'000'000'000ull));
    in.retention = ProviderRetention{.indefinite = false, .days = 90};
    in.foreign_noncurrent_days = 30;
    const auto r = cost::estimate(in);
    EXPECT_EQ(r.pre_activation_monthly.expected->amount, "0.69028262") << "another app's 30-day rule wins";
    EXPECT_FALSE(scenario(r, "90d").notes.empty());
}

TEST(RecoveryCostModel, PricingDigestFollowsTheCatalogNotTheUsage) {
    auto in = baseInputs();
    in.catalog = profileFor("aws-s3", "us-east-2", "standard");
    in.usage = days(std::vector<uint64_t>(10, 1'000'000'000ull));
    const auto a = cost::pricingDigest(cost::estimate(in));
    in.usage = days(std::vector<uint64_t>(12, 5'000'000'000ull));
    in.average_key_bytes = 90;
    EXPECT_EQ(cost::pricingDigest(cost::estimate(in)), a);
    in.catalog = profileFor("aws-s3", "us-east-2", "standard-ia");
    EXPECT_NE(cost::pricingDigest(cost::estimate(in)), a);
}

}
