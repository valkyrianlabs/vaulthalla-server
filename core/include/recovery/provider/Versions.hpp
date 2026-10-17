#pragma once

#include "recovery/Fwd.hpp"
#include "storage/Fwd.hpp"
#include "storage/s3/RequestUsage.hpp"
#include "sync/model/Action.hpp"

#include <cstdint>
#include <ctime>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace vh::storage::s3 {
    struct ObjectVersionInfo;
}

namespace vh::storage::s3::pricing {
    struct PriceBudgetReservation;
}

// The provider version index (upstream_object_version): what the bucket's ListObjectVersions says, metadata only.
// Raw and unauthorized: ops::recovery authorizes. See .claude/context/recovery.md, "Provider versioning".
namespace vh::recovery::provider::versions {

// Vault path → object key ("/docs/a.txt" → "docs/a.txt"); the key prefix of a directory ("/docs" → "docs/",
// "/" → "") and back ("docs/a.txt" → "/docs/a.txt").
[[nodiscard]] std::string objectKeyOf(const std::filesystem::path& vaultPath);
[[nodiscard]] std::string directoryPrefixOf(const std::filesystem::path& vaultPath);
[[nodiscard]] std::filesystem::path vaultPathOf(const std::string& objectKey);

// Vaulthalla's own objects (the .vaulthalla/ index manifest): never vault content, never a recovery point.
[[nodiscard]] bool isInternalKey(const std::string& objectKey);

// One listed version as an 'observed' index row (no IV/key/hash: a listing has no metadata). became_noncurrent_at is
// the next newer version's LastModified when the caller knows it (versions of a key are listed newest first).
[[nodiscard]] db::query::recovery::ObjectVersionRow observedRow(uint32_t vaultId, const storage::s3::ObjectVersionInfo& v,
                                                                std::optional<std::time_t> supersededAt = std::nullopt);

struct RefreshOptions {
    unsigned int max_requests{10};    // ListObjectVersions pages this call may send (each ≤ page_size entries)
    unsigned int page_size{1000};
    bool price_preflight{true};       // a price-budget reservation for max_requests LISTs before anything is sent
};

struct RefreshResult {
    uint64_t requests{};              // LIST requests sent
    uint64_t versions{};              // object versions seen (not delete markers)
    uint64_t delete_markers{};
    uint64_t skipped_internal{};      // Vaulthalla's own keys (.vaulthalla/)
    uint64_t marked_gone{};           // index rows under the prefix the provider no longer lists
    bool complete{false};             // the whole prefix was listed; only then are unlisted rows marked gone
    std::optional<std::string> stopped_reason;   // request cap, request/price budget, …
    storage::s3::S3GatewayUpstreamUsage usage;   // source "recovery_version_list"
};

// Lists every version and delete marker under `prefix` (an object key prefix; "" = the whole bucket) into the index
// as observed rows (never downgrading a row Vaulthalla wrote), within options.max_requests LISTs, a price preflight
// and the vault's request budget. No HEAD, no GET: nothing but listing requests is ever sent. A listing stopped by a
// cap or budget keeps what it learned and marks nothing gone. Provider/transport failures propagate.
[[nodiscard]] RefreshResult refresh(const std::shared_ptr<storage::CloudEngine>& engine, const std::string& prefix,
                                    const RefreshOptions& options = {});

}

// Price preflight shared by provider recovery's metered operations (listing, restore), the way sync and conflict
// resolution do it: a BudgetConservative estimate + PriceBudgetService::preflight over the global/provider/vault scopes.
namespace vh::recovery::provider::metering {

class PriceReservation {
public:
    // Throws storage::ContentUnavailable when the price budget refuses (nothing may be sent then).
    PriceReservation(const storage::CloudEngine& engine, const sync::model::S3CostEstimate& planned,
                     const std::string& operation, const std::string& objectKey);
    ~PriceReservation();   // not settled: charged conservatively (requests may have been sent)
    PriceReservation(const PriceReservation&) = delete;
    PriceReservation& operator=(const PriceReservation&) = delete;

    void commit() noexcept;   // charge the reserved estimate
    void release() noexcept;  // nothing was sent

private:
    std::vector<storage::s3::pricing::PriceBudgetReservation> reservations_;
    std::optional<std::string> estimatedCost_;
    std::string what_;
    bool settled_{false};
};

}
