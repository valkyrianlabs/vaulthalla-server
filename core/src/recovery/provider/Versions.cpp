#include "recovery/provider/Versions.hpp"

#include "db/query/recovery/ObjectVersion.hpp"
#include "log/Registry.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/PlaintextReader.hpp"
#include "storage/ScopedS3RequestUsageCapture.hpp"
#include "storage/s3/Controller.hpp"
#include "storage/s3/pricing/PriceBudget.hpp"
#include "storage/s3/pricing/PriceEstimate.hpp"
#include "sync/model/RemoteManifest.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "vault/model/Vault.hpp"

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <fmt/format.h>

#include <algorithm>
#include <chrono>

namespace vh::recovery::provider {

namespace versions {

namespace {

constexpr const char* kVersionListOperation = "recovery_version_list";

std::string stripSlashes(std::string s) {
    while (!s.empty() && s.front() == '/') s.erase(s.begin());
    return s;
}

}

std::string objectKeyOf(const std::filesystem::path& vaultPath) {
    auto key = stripSlashes(vaultPath.lexically_normal().generic_string());
    while (!key.empty() && key.back() == '/') key.pop_back();
    return key;
}

std::string directoryPrefixOf(const std::filesystem::path& vaultPath) {
    const auto key = objectKeyOf(vaultPath);
    return key.empty() || key == "." ? std::string{} : key + "/";
}

std::filesystem::path vaultPathOf(const std::string& objectKey) {
    return std::filesystem::path("/" + stripSlashes(objectKey));
}

bool isInternalKey(const std::string& objectKey) {
    const auto key = stripSlashes(objectKey);
    return key.starts_with(".vaulthalla/") || sync::model::remote_manifest::isVaulthallaManifestKey(key);
}

db::query::recovery::ObjectVersionRow observedRow(const uint32_t vaultId, const storage::s3::ObjectVersionInfo& v,
                                                  const std::optional<std::time_t> supersededAt) {
    db::query::recovery::ObjectVersionRow row;
    row.vault_id = vaultId;
    row.object_key = v.key;
    row.version_id = v.version_id;
    row.is_delete_marker = v.delete_marker;
    row.is_latest = v.is_latest;
    if (!v.delete_marker) {
        if (!v.etag.empty()) row.etag = v.etag;
        row.size_bytes = v.size;
        row.storage_class = v.storage_class;
    }
    row.last_modified = v.last_modified;
    row.origin = "observed";
    if (!v.is_latest) row.became_noncurrent_at = supersededAt;
    return row;
}

RefreshResult refresh(const std::shared_ptr<storage::CloudEngine>& engine, const std::string& prefix,
                      const RefreshOptions& options) {
    if (!engine || !engine->vault) throw std::invalid_argument("listing provider versions needs a cloud vault engine");
    const auto vaultId = engine->vault->id;
    const auto maxRequests = std::max(1u, options.max_requests);
    RefreshResult out;

    std::optional<metering::PriceReservation> price;
    if (options.price_preflight) {
        sync::model::S3CostEstimate planned;
        planned.list_requests = maxRequests;
        try {
            price.emplace(*engine, planned, kVersionListOperation, prefix);
        } catch (const storage::ContentUnavailable& e) {
            out.stopped_reason = e.what();
            return out;
        }
    }

    const auto policy = engine->remote_policy();
    const auto listingStartedAt = std::chrono::system_clock::now();
    {
        // The vault's request budget, and this listing's own cap: LISTs only (a HEAD or GET here is a bug).
        const storage::ScopedS3RequestUsageCapture vaultBudget(
            *engine, policy ? std::make_optional(policy->s3_request_budget) : std::nullopt);
        storage::s3::S3RequestBudget cap;
        cap.max_list_requests = maxRequests;
        cap.max_head_requests = 0;
        cap.max_get_requests = 0;
        cap.max_put_requests = 0;
        cap.max_copy_requests = 0;
        cap.max_delete_requests = 0;
        cap.max_downloaded_bytes = 0;
        std::optional<storage::ScopedS3RequestUsageCapture> capture(std::in_place, *engine, cap);

        std::string keyMarker, versionIdMarker;
        // The newest version of a key seen so far (pages may split a key's versions): an older one became
        // noncurrent when the next newer one was written.
        std::string lastKey;
        std::optional<std::time_t> lastModified;
        try {
            while (true) {
                if (out.requests >= maxRequests) {
                    out.stopped_reason = fmt::format("stopped after {} ListObjectVersions request(s) (the per-call cap)",
                                                     out.requests);
                    break;
                }
                const auto page = engine->listObjectVersionsPage(prefix, keyMarker, versionIdMarker, options.page_size);
                ++out.requests;
                std::vector<db::query::recovery::ObjectVersionRow> rows;
                rows.reserve(page.versions.size());
                for (const auto& v : page.versions) {
                    const auto superseded = v.key == lastKey ? lastModified : std::nullopt;
                    lastKey = v.key;
                    lastModified = v.last_modified;
                    if (isInternalKey(v.key)) {
                        ++out.skipped_internal;
                        continue;
                    }
                    if (v.delete_marker) ++out.delete_markers;
                    else ++out.versions;
                    rows.push_back(observedRow(vaultId, v, superseded));
                }
                db::query::recovery::ObjectVersion::upsertMany(rows, std::chrono::system_clock::now());
                if (!page.truncated) {
                    out.complete = true;
                    break;
                }
                keyMarker = page.next_key_marker;
                versionIdMarker = page.next_version_id_marker;
            }
        } catch (const storage::s3::RequestBudgetExceeded& e) {
            out.stopped_reason = std::string("request budget: ") + e.what();
        }
        out.usage = capture->usage();
        out.usage.source = kVersionListOperation;
        capture.reset();
    }
    if (price) price->commit();

    if (out.complete) out.marked_gone = db::query::recovery::ObjectVersion::markGoneUnder(vaultId, prefix, listingStartedAt);
    log::Registry::cloud()->debug("[Recovery] Vault {}: listed provider versions under '{}': {} version(s), {} delete "
                                  "marker(s), {} request(s), {} gone{}", vaultId, prefix, out.versions,
                                  out.delete_markers, out.requests, out.marked_gone,
                                  out.stopped_reason ? " (" + *out.stopped_reason + ")" : std::string{});
    return out;
}

}

namespace metering {

namespace {

std::string meteringRequestId() {
    thread_local boost::uuids::random_generator generator;
    return boost::uuids::to_string(generator());
}

}

PriceReservation::PriceReservation(const storage::CloudEngine& engine, const sync::model::S3CostEstimate& planned,
                                   const std::string& operation, const std::string& objectKey)
    : what_(operation + " " + objectKey) {
    if (!engine.vault) throw std::invalid_argument("price preflight needs a vault");
    namespace pricing = storage::s3::pricing;
    try {
        const auto estimate = pricing::estimatePlannedS3Sync(engine, planned,
                                                             {.mode = pricing::PriceEstimateMode::BudgetConservative});
        const auto profile = engine.s3ProviderProfile();
        const auto costProfileId = profile ? profile->costProfileId() : std::optional<std::string>{};
        const auto providerKey = costProfileId ? *costProfileId : (profile ? profile->id() : std::string{"unknown"});
        const auto id = meteringRequestId();
        const pricing::PriceBudgetPreflightRequest request{
            .vault_id = engine.vault->id,
            .run_uuid = id,
            .provider_key = providerKey,
            .provider_supported = costProfileId && pricing::isSupportedPriceBudgetProvider(*costProfileId),
            .estimate = estimate,
            .dry_run = false,
            .override_policy_ids = {},
            .gateway_credential_id = {},
            .request_uuid = id,
            .operation = operation,
            .object_key = objectKey,
            .gateway_scopes_only = false,
            .synthetic = false,
            .usage_source = operation
        };
        const pricing::PriceBudgetService service;
        const auto decision = service.preflight(request);
        service.recordPreflightNotifications(request, decision);
        for (const auto& warning : decision.warnings)
            log::Registry::cloud()->warn("[Recovery] S3 price budget warning for vault {} ({}): {}", engine.vault->id,
                                         what_, warning);
        if (!decision.allowed)
            throw storage::ContentUnavailable(fmt::format("S3 price budget refused {}: {}", what_,
                                                          decision.reason.empty() ? "budget would be exceeded"
                                                                                  : decision.reason));
        reservations_ = decision.reservations;
        if (estimate.available) estimatedCost_ = estimate.estimated_cost;
    } catch (const storage::ContentUnavailable&) {
        throw;
    } catch (const std::exception& e) {
        // Fail closed: no price decision, nothing sent.
        throw storage::ContentUnavailable(fmt::format("S3 price preflight for {} failed: {}", what_, e.what()));
    }
}

PriceReservation::~PriceReservation() {
    if (settled_) return;
    settled_ = true;
    if (reservations_.empty()) return;
    try {
        storage::s3::pricing::PriceBudgetService{}.commit(reservations_, std::nullopt);
    } catch (const std::exception& e) {
        log::Registry::cloud()->error("[Recovery] Could not settle the price reservation for {}: {}", what_, e.what());
    }
}

void PriceReservation::commit() noexcept {
    if (settled_) return;
    settled_ = true;
    if (reservations_.empty()) return;
    try {
        storage::s3::pricing::PriceBudgetService{}.commit(reservations_, estimatedCost_);
    } catch (const std::exception& e) {
        log::Registry::cloud()->error("[Recovery] Could not settle the price reservation for {}: {}", what_, e.what());
    }
}

void PriceReservation::release() noexcept {
    if (settled_) return;
    settled_ = true;
    if (reservations_.empty()) return;
    try {
        storage::s3::pricing::PriceBudgetService{}.release(reservations_);
    } catch (const std::exception& e) {
        log::Registry::cloud()->error("[Recovery] Could not release the price reservation for {}: {}", what_, e.what());
    }
}

}

}
