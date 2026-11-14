#include "storage/s3/pricing/PriceEstimate.hpp"

#include "config/Registry.hpp"
#include "log/Registry.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/s3/pricing/LocalEstimator.hpp"
#include "storage/s3/pricing/PriceCatalogStore.hpp"
#include "storage/s3/pricing/PriceBotUsage.hpp"
#include "storage/s3/pricing/PriceProfileResolver.hpp"
#include "sync/model/Action.hpp"

#include <algorithm>
#include <nlohmann/json.hpp>
#include <sstream>

namespace vh::storage::s3::pricing {
namespace {

constexpr const char* kStorageForecastUnknown =
    "storage-at-rest monthly forecast omitted; estimate covers planned requests/transfers only";

void appendIfMissing(std::vector<std::string>& values, const std::string& value) {
    if (std::ranges::find(values, value) == values.end()) values.push_back(value);
}

PriceEstimateReport unavailableFromTarget(
    const std::optional<PriceProfileTarget>& target,
    const std::string& reason) {
    if (!target) return PriceEstimateReport::unsupported(reason);
    return PriceEstimateReport::unavailable(*target, reason);
}

bool budgetConservativeResponseMatchesRequest(const EstimateResult& result) {
    return result.estimate_mode == "budget_conservative" &&
        result.free_tier_policy == "ignore_account_wide_free_tiers";
}

PriceEstimateReport reportFromEstimate(
    const PriceProfileTarget& target,
    const RatingProfile& profile,
    const EstimateResult& estimate,
    const PriceEstimateMode requestedMode,
    const bool stale,
    const bool catalogVerified,
    std::optional<std::int64_t> catalogAgeSeconds,
    std::string catalogSource) {
    PriceEstimateReport report;
    report.available = true;
    report.supported = true;
    report.stale = stale;
    report.target = target;
    report.estimated_cost = estimate.estimated_cost;
    report.currency = estimate.currency;
    report.price_profile_id = profile.profile_id;
    report.catalog_version = profile.catalog_version;
    report.catalog_source = std::move(catalogSource);
    report.catalog_verified = catalogVerified;
    report.catalog_age_seconds = catalogAgeSeconds;
    report.confidence_level = estimate.confidence_level.empty()
        ? profile.confidence_level
        : estimate.confidence_level;
    report.estimate_mode = estimate.estimate_mode.empty()
        ? toString(requestedMode)
        : estimate.estimate_mode;
    report.free_tier_policy = estimate.free_tier_policy;
    report.free_tiers_applied = estimate.free_tiers_applied;
    report.unknowns = estimate.unknowns;
    appendIfMissing(report.unknowns, kStorageForecastUnknown);
    report.breakdown = estimate.breakdown;
    return report;
}

} // namespace

PriceEstimateReport estimatePlannedS3Sync(
    const vh::storage::CloudEngine& engine,
    const vh::sync::model::S3CostEstimate& s3Estimate,
    const PriceEstimateOptions options,
    IPriceBotClient* client,
    IPriceCatalogStore* catalogStore) {
    return estimatePlannedS3Sync(
        PriceSubject{engine.s3ProviderProfile(), engine.s3ApiKey(), engine.resolvedStorageTier()},
        s3Estimate, options, client, catalogStore);
}

PriceEstimateReport estimatePlannedS3Sync(
    const PriceSubject& subject,
    const vh::sync::model::S3CostEstimate& s3Estimate,
    const PriceEstimateOptions options,
    IPriceBotClient* client,
    IPriceCatalogStore* catalogStore) {
    const auto& pricing = config::Registry::get().pricing;
    const auto& cfg = pricing.storage_rates_api;
    if (options.disabled || !pricing.enabled)
        return PriceEstimateReport::unsupported("pricing disabled");

    const auto tier = options.storage_tier_override
        ? options.storage_tier_override
        : subject.tier;
    const auto target = resolvePriceProfileTarget(
        subject.profile,
        subject.key,
        tier);
    if (!target)
        return PriceEstimateReport::unsupported("S3 provider has no price-bot profile");

    const auto usage = toPriceBotUsageInput(s3Estimate, tier);

    if (!cfg.use_remote_estimator_for_debug) {
        PriceCatalogStore ownedStore(cfg);
        auto& store = catalogStore ? *catalogStore : static_cast<IPriceCatalogStore&>(ownedStore);
        const auto profileResult = store.getProfile(*target, options.force_refresh);
        if (!profileResult.ok) {
            log::Registry::sync()->warn(
                "[PriceCatalog] Profile unavailable for {}: {}",
                target->profileId(),
                profileResult.error);
            return unavailableFromTarget(target, profileResult.error);
        }

        const auto estimateResult = LocalEstimator{}.estimate(
            profileResult.profile,
            usage,
            {.mode = options.mode, .apply_free_tiers = options.mode != PriceEstimateMode::BudgetConservative});
        if (options.mode == PriceEstimateMode::BudgetConservative &&
            !budgetConservativeResponseMatchesRequest(estimateResult)) {
            return unavailableFromTarget(
                target,
                "local estimator did not return a budget-conservative free-tier policy");
        }

        return reportFromEstimate(
            *target,
            profileResult.profile,
            estimateResult,
            options.mode,
            profileResult.stale,
            profileResult.signature_verified,
            profileResult.age_seconds,
            profileResult.source.empty() ? kCatalogSourceDiskCache : profileResult.source);
    }

    PriceBotClient ownedClient(cfg);
    auto& priceClient = client ? *client : static_cast<IPriceBotClient&>(ownedClient);

    const auto profileResult = priceClient.getProfile(
        target->provider,
        target->region,
        target->storage_class,
        options.force_refresh);
    if (!profileResult.ok) {
        log::Registry::sync()->warn(
            "[PriceBot] Profile unavailable for {}: {}",
            target->profileId(),
            profileResult.error);
        return unavailableFromTarget(target, profileResult.error);
    }

    const auto estimateResult = priceClient.estimate(
        profileResult.value.raw,
        usage,
        options.force_refresh,
        options.mode);
    if (!estimateResult.ok) {
        log::Registry::sync()->warn(
            "[PriceBot] Estimate unavailable for {}: {}",
            target->profileId(),
            estimateResult.error);
        return unavailableFromTarget(target, estimateResult.error);
    }
    if (options.mode == PriceEstimateMode::BudgetConservative &&
        !budgetConservativeResponseMatchesRequest(estimateResult.value)) {
        return unavailableFromTarget(
            target,
            "price-bot did not return a budget-conservative free-tier policy");
    }

    return reportFromEstimate(
        *target,
        profileResult.value,
        estimateResult.value,
        options.mode,
        profileResult.stale || estimateResult.stale,
        true,
        std::nullopt,
        "remote-estimator");
}

std::string formatPriceEstimateForLog(const PriceEstimateReport& report) {
    if (!report.supported) return "pricing skipped: " + report.unavailable_reason;
    if (!report.available) return "pricing unavailable for " + report.target.profileId() + ": " + report.unavailable_reason;

    std::ostringstream out;
    out << "estimated_cost=" << report.estimated_cost << ' ' << report.currency
        << " profile=" << report.price_profile_id
        << " catalog=" << report.catalog_version
        << " source=" << (report.catalog_source.empty() ? "unknown" : report.catalog_source)
        << " verified=" << (report.catalog_verified ? "true" : "false")
        << " age_seconds=" << (report.catalog_age_seconds ? std::to_string(*report.catalog_age_seconds) : std::string("unknown"))
        << " confidence=" << report.confidence_level
        << " mode=" << (report.estimate_mode.empty() ? "unknown" : report.estimate_mode)
        << " free_tier_policy=" << (report.free_tier_policy.empty() ? "unknown" : report.free_tier_policy)
        << " stale=" << (report.stale ? "true" : "false")
        << " unknowns=" << report.unknowns.size();
    return out.str();
}

std::string formatPriceEstimateForDryRun(
    const PriceEstimateReport& report,
    const std::string_view label) {
    std::ostringstream out;
    out << "  " << label << ":\n";
    if (!report.supported) {
        out << "    Status: skipped (" << report.unavailable_reason << ")";
        return out.str();
    }
    if (!report.available) {
        out << "    Status: unavailable (" << report.unavailable_reason << ")\n"
            << "    Profile: " << report.target.profileId();
        return out.str();
    }

    out << "    Estimated cost: " << report.estimated_cost << ' ' << report.currency << "\n"
        << "    Profile: " << report.price_profile_id << "\n"
        << "    Catalog: " << (report.catalog_version.empty() ? "unknown" : report.catalog_version) << "\n"
        << "    Catalog source: " << (report.catalog_source.empty() ? "unknown" : report.catalog_source) << "\n"
        << "    Catalog verified: " << (report.catalog_verified ? "yes" : "no") << "\n"
        << "    Catalog age seconds: "
        << (report.catalog_age_seconds ? std::to_string(*report.catalog_age_seconds) : std::string("unknown")) << "\n"
        << "    Confidence: " << (report.confidence_level.empty() ? "unknown" : report.confidence_level) << "\n"
        << "    Mode: " << (report.estimate_mode.empty() ? "unknown" : report.estimate_mode) << "\n"
        << "    Free tier policy: "
        << (report.free_tier_policy.empty() ? "unknown" : report.free_tier_policy) << "\n"
        << "    Free tiers applied: "
        << (report.free_tiers_applied ? (*report.free_tiers_applied ? "yes" : "no") : "unknown")
        << "\n"
        << "    Stale cache: " << (report.stale ? "yes" : "no") << "\n"
        << "    Unknowns: " << report.unknowns.size();
    if (!report.unknowns.empty()) out << " (" << report.unknowns.front() << ")";
    return out.str();
}

} // namespace vh::storage::s3::pricing
