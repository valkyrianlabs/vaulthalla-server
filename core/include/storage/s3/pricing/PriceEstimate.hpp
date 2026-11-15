#pragma once

#include "storage/s3/pricing/PriceBotClient.hpp"
#include "storage/s3/pricing/PriceBotModels.hpp"
#include "storage/s3/provider/Provider.hpp"
#include "storage/s3/provider/StorageTier.hpp"
#include "storage/Fwd.hpp"
#include "sync/Fwd.hpp"
#include "vault/Fwd.hpp"

#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace vh::storage::s3::pricing {

class IPriceCatalogStore;

struct PriceEstimateOptions {
    bool force_refresh{false};
    bool disabled{false};
    PriceEstimateMode mode{PriceEstimateMode::Reporting};
    std::optional<provider::StorageTier> storage_tier_override{std::nullopt};
};

// Where the planned requests go, for a caller without a cloud engine (attach-remote prices a bucket a still-local
// vault doesn't hold yet): the provider's profile, the API key (its region) and the storage tier.
struct PriceSubject {
    provider::ProfilePtr profile;
    std::shared_ptr<vh::vault::model::APIKey> key;
    std::optional<provider::StorageTier> tier;
};

[[nodiscard]] PriceEstimateReport estimatePlannedS3Sync(
    const PriceSubject& subject,
    const vh::sync::model::S3CostEstimate& s3Estimate,
    PriceEstimateOptions options = {},
    IPriceBotClient* client = nullptr,
    IPriceCatalogStore* catalogStore = nullptr);

[[nodiscard]] PriceEstimateReport estimatePlannedS3Sync(
    const vh::storage::CloudEngine& engine,
    const vh::sync::model::S3CostEstimate& s3Estimate,
    PriceEstimateOptions options = {},
    IPriceBotClient* client = nullptr,
    IPriceCatalogStore* catalogStore = nullptr);

[[nodiscard]] std::string formatPriceEstimateForLog(const PriceEstimateReport& report);
[[nodiscard]] std::string formatPriceEstimateForDryRun(
    const PriceEstimateReport& report,
    std::string_view label = "Price estimate");

} // namespace vh::storage::s3::pricing
