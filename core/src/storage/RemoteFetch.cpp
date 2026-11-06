#include "storage/RemoteFetch.hpp"

#include "log/Registry.hpp"
#include "log/Redact.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/PlaintextReader.hpp"
#include "storage/s3/pricing/PriceBudget.hpp"
#include "storage/s3/pricing/PriceEstimate.hpp"
#include "sync/model/Action.hpp"
#include "vault/model/Vault.hpp"

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <fmt/format.h>

#include <utility>
#include <vector>

namespace vh::storage {

namespace remote_fetch_detail {

std::string newRemoteFetchId() {
    thread_local boost::uuids::random_generator generator;
    return boost::uuids::to_string(generator());
}

sync::model::S3CostEstimate plannedFetch(const uint64_t heads, const uint64_t gets, const uint64_t bytes) {
    sync::model::S3CostEstimate estimate;
    estimate.head_requests = heads;
    estimate.get_requests = gets;
    estimate.planned_body_download_bytes = bytes;
    estimate.remote_index_objects = 1;
    return estimate;
}

class PriceBudgetFetchReservation final : public RemoteFetchReservation {
public:
    PriceBudgetFetchReservation(const CloudEngine& engine, std::vector<s3::pricing::PriceBudgetReservation> reservations,
                                std::string path)
        : engine_(engine), reservations_(std::move(reservations)), path_(std::move(path)) {}

    ~PriceBudgetFetchReservation() override { release(); }

    void commit(const s3::S3GatewayUpstreamUsage& actual) noexcept override {
        if (settled_) return;
        settled_ = true;
        if (reservations_.empty()) return;
        try {
            const s3::pricing::PriceBudgetService service;
            if (actual.empty()) {
                service.release(reservations_);
                return;
            }
            // Charge what was actually fetched; an unavailable estimate keeps the reserved amount (conservative).
            const auto report = s3::pricing::estimatePlannedS3Sync(
                engine_,
                plannedFetch(actual.head_requests, actual.get_requests, actual.downloaded_bytes),
                {.mode = s3::pricing::PriceEstimateMode::BudgetConservative});
            service.commit(reservations_, report.available ? std::make_optional(report.estimated_cost) : std::nullopt);
        } catch (const std::exception& e) {
            log::Registry::cloud()->error("[RemoteFetch] Could not settle the price reservation for {}: {}", path_, e.what());
        }
    }

    void release() noexcept override {
        if (settled_) return;
        settled_ = true;
        if (reservations_.empty()) return;
        try {
            s3::pricing::PriceBudgetService{}.release(reservations_);
        } catch (const std::exception& e) {
            log::Registry::cloud()->error("[RemoteFetch] Could not release the price reservation for {}: {}", path_, e.what());
        }
    }

private:
    const CloudEngine& engine_;
    std::vector<s3::pricing::PriceBudgetReservation> reservations_;
    std::string path_;
    bool settled_{false};
};

}

std::unique_ptr<RemoteFetchReservation> priceBudgetRemoteFetchGate(const CloudEngine& engine,
                                                                   const RemoteFetchRequest& request) {
    if (!engine.vault) throw std::runtime_error("Remote fetch preflight needs a vault");

    const auto estimate = s3::pricing::estimatePlannedS3Sync(
        engine,
        remote_fetch_detail::plannedFetch(request.head_requests, request.get_requests, request.download_bytes),
        {.mode = s3::pricing::PriceEstimateMode::BudgetConservative});

    // The provider identity sync uses, so provider-scoped policies apply the same way.
    const auto profile = engine.s3ProviderProfile();
    const auto costProfileId = profile ? profile->costProfileId() : std::optional<std::string>{};
    const auto providerKey = costProfileId ? *costProfileId : (profile ? profile->id() : std::string{"unknown"});
    const bool providerSupported = costProfileId && s3::pricing::isSupportedPriceBudgetProvider(*costProfileId);

    const auto requestId = remote_fetch_detail::newRemoteFetchId();
    const s3::pricing::PriceBudgetPreflightRequest budgetRequest{
        .vault_id = engine.vault->id,
        .run_uuid = requestId,
        .provider_key = providerKey,
        .provider_supported = providerSupported,
        .estimate = estimate,
        .dry_run = false,
        .override_policy_ids = {},
        .gateway_credential_id = {},
        .request_uuid = requestId,
        .operation = request.operation,
        .object_key = request.path.generic_string(),
        .gateway_scopes_only = false,
        .synthetic = false,
        .usage_source = request.operation
    };

    const s3::pricing::PriceBudgetService service;
    const auto decision = service.preflight(budgetRequest);
    service.recordPreflightNotifications(budgetRequest, decision);
    for (const auto& warning : decision.warnings)
        log::Registry::cloud()->warn("[RemoteFetch] S3 price budget warning for vault {} ({} {}): {}",
                                     engine.vault->id, request.operation, log::path(request.path), warning);
    if (!decision.allowed)
        throw ContentUnavailable(fmt::format("S3 price budget refused {} of {}: {}", request.operation,
                                             request.path.string(),
                                             decision.reason.empty() ? "budget would be exceeded" : decision.reason));

    return std::make_unique<remote_fetch_detail::PriceBudgetFetchReservation>(engine, decision.reservations,
                                                                             request.path.string());
}

}
