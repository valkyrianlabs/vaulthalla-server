#pragma once

#include "db/query/recovery/ObjectVersion.hpp"
#include "db/query/recovery/Usage.hpp"
#include "recovery/Model.hpp"
#include "storage/s3/pricing/PriceBotModels.hpp"

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// The provider versioning cost model (recovery.md "Costs"). Computed locally from a signed price-bot profile, the
// vault's own usage counters, the version index and the remote object index; nothing leaves the host. Decimal
// arithmetic end to end (boost cpp_dec_float_50); money is a string with 8 decimals.
//
// estimate() is pure (no database, no catalog): gather() in recovery/cost/Report.hpp builds its inputs.
namespace vh::recovery::cost {

// One billing month: 730 hours = 365/12 days (the catalog's billing month).
inline constexpr unsigned int kHoursPerMonth = 730;
// Measured days below this give a low-confidence range instead of one figure.
inline constexpr unsigned int kSufficientDays = 7;
// Illustrative rewrite rates (share of current bytes rewritten per month) when nothing was measured yet.
inline constexpr const char* kIllustrativeLow = "0.01";
inline constexpr const char* kIllustrativeExpected = "0.05";
inline constexpr const char* kIllustrativeHigh = "0.20";
// Manifest size assumption (bytes per indexed object, floor) and how long a superseded manifest is billed: one day
// noncurrent (kManifestNoncurrentDays) plus up to a day until lifecycle runs.
inline constexpr uint64_t kManifestBytesPerObject = 256;
inline constexpr uint64_t kManifestMinBytes = 1024;
inline constexpr unsigned int kManifestBilledDays = 2;
inline constexpr unsigned int kIllustrativeManifestPublishesPerDay = 24;
// Key-name bytes of a delete marker when the index can't say.
inline constexpr uint64_t kDefaultKeyBytes = 64;

struct CatalogInfo {
    std::optional<storage::s3::pricing::RatingProfile> profile;   // nullopt: none (error says why)
    std::string error;
    bool verified{false};
    bool stale{false};
    std::optional<int64_t> age_seconds;
    std::string source;
    std::optional<std::string> note;
};

struct Inputs {
    uint32_t vault_id{};
    std::optional<std::string> provider, bucket, region, storage_class;
    // Known before any catalog lookup (not an S3 vault, pricing disabled, no price profile for the provider/class).
    std::optional<std::string> unpriced_reason;
    CatalogInfo catalog;

    std::vector<db::query::recovery::UsageDay> usage;       // the observation window (≤ 30 UTC days)
    std::optional<std::string> first_usage_day;             // earliest measurement ever (unaccounted history)
    uint64_t current_objects{}, current_bytes{};            // remote index, Vaulthalla's manifest excluded
    std::optional<uint64_t> average_key_bytes;
    db::query::recovery::NoncurrentSummary history;

    std::string versioning_status{"unknown"};               // unversioned | enabled | suspended | unknown
    bool enabled_by_vaulthalla{false};
    // The retention the figures assume (chosen or recorded); nullopt = none chosen.
    std::optional<ProviderRetention> retention;
    // The shortest foreign NoncurrentDays over the whole vault (another application's lifecycle rule).
    std::optional<unsigned int> foreign_noncurrent_days;
    std::optional<std::string> month_to_date_byte_hours;    // noncurrent byte-hours this UTC month (active buckets)
    std::optional<std::string> alert_threshold;              // decimal amount in the catalog currency
    std::time_t now{};
};

[[nodiscard]] CostReport estimate(const Inputs& in);

// What a disclosure priced: catalog version, profile and the rates used (not the usage, which moves every minute).
// Binds the disclosure token: a new catalog or another storage class needs a new disclosure.
[[nodiscard]] std::string pricingDigest(const CostReport& report);

}
