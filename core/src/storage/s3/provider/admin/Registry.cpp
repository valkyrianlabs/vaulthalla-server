#include "storage/s3/provider/admin/Adapters.hpp"

#include "vault/model/APIKey.hpp"

#include <paths.h>

#include <mutex>

namespace vh::storage::s3::provider::admin {

namespace {

std::mutex& factoryMutex() {
    static std::mutex m;
    return m;
}

std::optional<Factory>& testFactory() {
    static std::optional<Factory> f;
    return f;
}

std::optional<Factory> currentTestFactory() {
    if (!paths::testMode) return std::nullopt;
    std::scoped_lock lock(factoryMutex());
    return testFactory();
}

}

void setFactoryForTesting(std::optional<Factory> factory) {
    std::scoped_lock lock(factoryMutex());
    testFactory() = std::move(factory);
}

std::unique_ptr<AdminClient> adminFor(const std::shared_ptr<vault::model::APIKey>& key) {
    if (!key) return nullptr;
    if (const auto f = currentTestFactory(); f && f->admin) return f->admin(key);
    switch (key->provider) {
    case vault::model::S3Provider::AWS: return std::make_unique<AwsAdmin>(key);
    case vault::model::S3Provider::CloudflareR2: return std::make_unique<R2Admin>(key);
    default: return nullptr;
    }
}

// R2 without a Cloudflare API token throws CapabilityMissing (with what the operator must add) instead of returning
// nullptr, so callers can tell "unsupported provider" from "missing token".
std::unique_ptr<EventsClient> eventsFor(const std::shared_ptr<vault::model::APIKey>& key) {
    if (!key) return nullptr;
    if (const auto f = currentTestFactory(); f && f->events) return f->events(key);
    switch (key->provider) {
    case vault::model::S3Provider::AWS: return std::make_unique<AwsEvents>(key);
    case vault::model::S3Provider::CloudflareR2: return std::make_unique<R2Events>(key);
    default: return nullptr;
    }
}

}
