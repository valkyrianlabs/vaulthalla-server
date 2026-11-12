#include "storage/BucketCapability.hpp"

#include "db/query/vault/BucketCapability.hpp"
#include "db/query/vault/Vault.hpp"
#include "log/Registry.hpp"
#include "notifications/OperatorNotificationBus.hpp"
#include "runtime/Deps.hpp"
#include "storage/s3/Controller.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"

#include <fmt/format.h>
#include <paths.h>

#include <chrono>
#include <map>
#include <mutex>

namespace vh::storage::bucket_capability {

namespace bucket_capability_detail {

using Q = db::query::vault::BucketCapability;
using s3::WriteCapability;

constexpr std::chrono::hours kRetryAfterFailedProbe{1};

std::mutex mutex;
std::optional<bool> lazyForTesting;
ControllerFactory factoryForTesting;
std::map<uint32_t, std::chrono::steady_clock::time_point> failedAt;

bool lazyProbing() {
    std::scoped_lock lock(mutex);
    if (lazyForTesting) return *lazyForTesting;
    return !paths::testMode;
}

std::shared_ptr<s3::Controller> controllerFor(const uint32_t apiKeyId, const std::string& bucket) {
    {
        std::scoped_lock lock(mutex);
        if (factoryForTesting) return factoryForTesting(apiKeyId, bucket);
    }
    if (paths::testMode) return nullptr;
    const auto& keys = runtime::Deps::get().apiKeyManager;
    if (!keys) throw s3::ProbeFailed("the API key manager is not available");
    const auto key = keys->getAPIKey(apiKeyId);
    if (!key) throw s3::ProbeFailed("API key " + std::to_string(apiKeyId) + " no longer exists");
    return std::make_shared<s3::Controller>(key, bucket);
}

void logVerdict(const uint32_t vaultId, const s3::ProbeResult& r) {
    const auto& log = log::Registry::cloud();
    if (r.capability == WriteCapability::Conditional)
        log->info("[bucket_capability] Vault {}: {} (conditional writes)", vaultId, r.reason);
    else
        log->warn("[bucket_capability] Vault {}: {} (capability {})", vaultId, r.reason, s3::to_string(r.capability));
}

}

Resolved resolve(const uint32_t vaultId, const s3::Controller& controller) {
    namespace d = bucket_capability_detail;
    const auto stored = d::Q::get(vaultId);
    Resolved out{.capability = stored.capability, .changed = stored.changed_at.has_value()};
    if (stored.probe || stored.changed_at || !d::lazyProbing()) return out;
    {
        std::scoped_lock lock(d::mutex);
        if (const auto it = d::failedAt.find(vaultId);
            it != d::failedAt.end() && std::chrono::steady_clock::now() - it->second < d::kRetryAfterFailedProbe)
            return out;
    }
    try {
        out.capability = probeAndRecord(vaultId, controller).capability;
        return out;
    } catch (const s3::ProbeFailed& e) {
        log::Registry::cloud()->warn("[bucket_capability] Vault {}: the bucket could not be probed ({}); conditional "
                                     "writes are kept, the probe is retried in an hour",
                                     vaultId, e.what());
        std::scoped_lock lock(d::mutex);
        d::failedAt[vaultId] = std::chrono::steady_clock::now();
        return out;
    }
}

Resolved reprobe(const uint32_t vaultId, const s3::Controller& controller) {
    if (!bucket_capability_detail::lazyProbing()) {
        const auto stored = bucket_capability_detail::Q::get(vaultId);
        return {.capability = stored.capability, .changed = stored.changed_at.has_value()};
    }
    return {.capability = probeAndRecord(vaultId, controller).capability, .changed = false};
}

s3::ProbeResult probeAndRecord(const uint32_t vaultId, const s3::Controller& controller) {
    namespace d = bucket_capability_detail;
    auto result = s3::probeBucket(controller);
    d::Q::record(vaultId, result);
    {
        std::scoped_lock lock(d::mutex);
        d::failedAt.erase(vaultId);
    }
    d::logVerdict(vaultId, result);
    return result;
}

std::optional<s3::ProbeResult> probeBinding(const uint32_t apiKeyId, const std::string& bucket, const bool opaqueLayout) {
    const auto controller = bucket_capability_detail::controllerFor(apiKeyId, bucket);
    if (!controller) return std::nullopt;
    controller->setOpaqueLayout(opaqueLayout);
    return s3::probeBucket(*controller);
}

std::optional<s3::ProbeResult> probeVault(const uint32_t vaultId) {
    const auto s3 = std::dynamic_pointer_cast<vault::model::S3Vault>(db::query::vault::Vault::getVault(vaultId));
    if (!s3) throw s3::ProbeFailed("vault " + std::to_string(vaultId) + " has no bucket");
    const auto controller = bucket_capability_detail::controllerFor(s3->api_key_id, s3->bucket);
    if (!controller) return std::nullopt;
    controller->setUsageVault(vaultId);
    controller->setOpaqueLayout(s3->storage_layout == vault::model::StorageLayout::OpaqueV1);
    return probeAndRecord(vaultId, *controller);
}

std::string noteChanged(const uint32_t vaultId, const std::string& detail) {
    namespace d = bucket_capability_detail;
    if (d::Q::get(vaultId).capability != s3::WriteCapability::Conditional) {
        log::Registry::cloud()->warn("[bucket_capability] Vault {}: the bucket refused a conditional write ({}) before "
                                     "it was probed; the next use probes it", vaultId, detail);
        {
            std::scoped_lock lock(d::mutex);
            d::failedAt.erase(vaultId);
        }
        return fmt::format("conditional_writes_refused: the bucket refused a conditional write ({}) and has not been "
                           "probed yet: run vh vault storage probe {}", detail, vaultId);
    }
    const auto stalled = fmt::format("bucket_capability_changed: {}; check the vault's endpoint, then run vh vault "
                                     "storage probe {}", detail, vaultId);
    log::Registry::cloud()->error("[bucket_capability] Vault {}: the bucket refused a conditional write although it was "
                                  "probed as supporting them ({}); its sync stalls until it is probed again (vh vault "
                                  "storage probe {})",
                                  vaultId, detail, vaultId);
    bool first = false;
    try {
        first = d::Q::markChanged(vaultId, detail);
    } catch (const std::exception& e) {
        log::Registry::cloud()->warn("[bucket_capability] Vault {}: could not record the change: {}", vaultId, e.what());
    }
    if (!first) return stalled;
    notifications::OperatorNotification n;
    n.eventKey = "bucket_capability_changed";
    n.eventType = "storage";
    n.severity = "critical";
    n.recipientGroup = "alerts";
    n.fingerprint = fmt::format("bucket_capability:{}", vaultId);
    const auto summary = fmt::format(
        "The bucket of vault {} refused a conditional write although its probe found that it supports them. The "
        "endpoint, a proxy in front of it, or the provider changed.", vaultId);
    const auto action = fmt::format(
        "The vault's sync stalls; nothing was written without the condition. Check the vault's endpoint, then run "
        "`vh vault storage probe {}` to record what the bucket supports now.", vaultId);
    n.rendered.subject = fmt::format("[Vaulthalla] Bucket write capability changed for vault {}", vaultId);
    n.rendered.text = summary + "\n\n" + action + "\n";
    n.rendered.html = "<p>" + summary + "</p><p>" + action + "</p>";
    n.tags = {{"event_type", "storage"}, {"severity", "critical"}, {"vault_id", std::to_string(vaultId)}};
    if (!notifications::OperatorNotificationBus::instance().enqueue(std::move(n)))
        log::Registry::cloud()->warn("[bucket_capability] Dropped the capability alert for vault {}: the queue is full",
                                     vaultId);
    return stalled;
}

std::string unpublishableReason(const s3::WriteCapability capability) {
    return capability == s3::WriteCapability::VersionLog
        ? std::string("the bucket does not support conditional writes (it rejects If-None-Match and If-Match): this "
                      "server version can't publish the vault's encrypted manifest on it yet. Content uploads continue; "
                      "the manifest that names them is not written (design/encryption/06-publish-without-preconditions.md)")
        : std::string("the bucket supports neither conditional writes nor object versions (or not If-Match on GET): "
                      "the vault's encrypted manifest can't be published on it");
}

void setLazyProbingForTesting(const std::optional<bool> enabled) {
    if (!paths::testMode) throw std::logic_error("bucket_capability test seams are test-mode only");
    std::scoped_lock lock(bucket_capability_detail::mutex);
    bucket_capability_detail::lazyForTesting = enabled;
    bucket_capability_detail::failedAt.clear();
}

void setControllerFactoryForTesting(ControllerFactory factory) {
    if (!paths::testMode) throw std::logic_error("bucket_capability test seams are test-mode only");
    std::scoped_lock lock(bucket_capability_detail::mutex);
    bucket_capability_detail::factoryForTesting = std::move(factory);
}

}
