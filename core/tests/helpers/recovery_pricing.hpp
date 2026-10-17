#pragma once

// The signed price-bot catalog under core/test-assets/pricing/versioning (manifest + every profile + the Ed25519 public
// key, as `price-bot publish` produced them) loaded through the real PriceCatalogStore: signatures verified, nothing
// fetched. Shared by test_recovery_costs.cpp and test_recovery_policy.cpp.

#include "config/Config.hpp"
#include "storage/s3/pricing/PriceCatalogStore.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <memory>
#include <string>

#include <unistd.h>

namespace vh::test_support::recovery_pricing {

inline std::filesystem::path fixtureDir() { return std::filesystem::path(VH_TEST_ASSETS_DIR) / "pricing" / "versioning"; }

// A fresh copy of the artifacts (fresh mtimes: the cache isn't stale) in a private directory.
inline std::filesystem::path copyFixture() {
    static std::atomic<unsigned> n{0};
    const auto dir = std::filesystem::temp_directory_path() /
                     ("vh-recovery-pricing-" + std::to_string(::getpid()) + "-" + std::to_string(n.fetch_add(1)));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    std::filesystem::copy(fixtureDir(), dir, std::filesystem::copy_options::recursive);
    return dir;
}

// verified: the public key is configured and verification is strict. Without it the store still loads the artifacts
// (warning-only, as the shipped configuration does) and reports them unverified.
inline std::shared_ptr<storage::s3::pricing::PriceCatalogStore> catalogStore(const bool verified = true) {
    const auto dir = copyFixture();
    config::StorageRatesApiConfig cfg;
    cfg.remote_refresh_enabled = false;
    cfg.cache_ttl_seconds = 365u * 24 * 3600;
    cfg.refresh_interval_seconds = 365u * 24 * 3600;
    cfg.signature_warning_only = !verified;
    if (verified) cfg.signature_public_key_path = dir / "public-key.pem";
    return std::make_shared<storage::s3::pricing::PriceCatalogStore>(cfg, nullptr, dir);
}

// A store with no catalog at all (every lookup fails: unpriced).
inline std::shared_ptr<storage::s3::pricing::PriceCatalogStore> emptyCatalogStore() {
    static std::atomic<unsigned> n{0};
    const auto dir = std::filesystem::temp_directory_path() /
                     ("vh-recovery-pricing-empty-" + std::to_string(::getpid()) + "-" + std::to_string(n.fetch_add(1)));
    std::filesystem::create_directories(dir);
    config::StorageRatesApiConfig cfg;
    cfg.remote_refresh_enabled = false;
    return std::make_shared<storage::s3::pricing::PriceCatalogStore>(cfg, nullptr, dir);
}

}
