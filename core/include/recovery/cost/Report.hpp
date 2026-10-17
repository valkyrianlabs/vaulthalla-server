#pragma once

#include "recovery/cost/Estimator.hpp"
#include "storage/s3/pricing/PriceCatalogStore.hpp"

#include <ctime>
#include <memory>
#include <optional>

// Gathering what the cost model needs for one vault (trusted: no authorization; ops::recovery authorizes).
namespace vh::recovery::cost {

// The rating profile for a target from the daemon's one shared catalog store (hydrated from the verified disk cache;
// it refreshes from the price bot only when the configuration allows, never per request). Never throws.
[[nodiscard]] CatalogInfo lookupProfile(const storage::s3::pricing::PriceProfileTarget& target);

// Tests: the store every lookup uses (nullptr restores the configured one).
void setCatalogStoreForTesting(std::shared_ptr<storage::s3::pricing::IPriceCatalogStore> store);

struct GatherOptions {
    // The retention to price; nullopt = the bucket's recorded Vaulthalla retention (none: scenarios only).
    std::optional<ProviderRetention> retention{};
    // Another application's shortest noncurrent rule over the vault (from a fresh inspect), when known.
    std::optional<unsigned int> foreign_noncurrent_days{};
    // Overrides the recorded versioning status (a fresh read).
    std::optional<std::string> versioning_status{};
};

// The inputs for a vault: price target and profile, usage of the last 30 UTC days, the remote index's current bytes,
// the version index, the bucket's recorded versioning state and the policy's alert threshold.
[[nodiscard]] Inputs gather(uint32_t vaultId, const GatherOptions& options, std::time_t now);
[[nodiscard]] CostReport reportForVault(uint32_t vaultId, const GatherOptions& options, std::time_t now);

}
