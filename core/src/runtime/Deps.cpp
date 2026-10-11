#include "runtime/Deps.hpp"

#include "UsageManager.hpp"
#include "auth/Manager.hpp"
#include "crypto/secrets/Manager.hpp"
#include "fs/cache/Registry.hpp"
#include "identities/Manager.hpp"
#include "stats/model/CacheStats.hpp"
#include "stats/model/FuseStats.hpp"
#include "storage/Manager.hpp"
#include "sync/Controller.hpp"
#include "vault/APIKeyManager.hpp"

namespace vh::runtime {

    Deps& Deps::get() {
        static Deps instance;
        return instance;
    }

    void Deps::init() {
        auto& deps = get();

        if (!deps.storageManager) deps.storageManager = std::make_shared<storage::Manager>();
        if (!deps.apiKeyManager) deps.apiKeyManager = std::make_shared<vault::APIKeyManager>();
        if (!deps.authManager) deps.authManager = std::make_shared<auth::Manager>();
        if (!deps.identityManager) deps.identityManager = std::make_shared<identities::Manager>();
        if (!deps.sessionManager) deps.sessionManager = std::make_shared<auth::session::Manager>();
        if (!deps.secretsManager) deps.secretsManager = std::make_shared<crypto::secrets::Manager>();
        if (!deps.fsCache) deps.fsCache = std::make_shared<fs::cache::Registry>();
        if (!deps.shellUsageManager) deps.shellUsageManager = std::make_shared<protocols::shell::UsageManager>();
        if (!deps.httpCacheStats) deps.httpCacheStats = std::make_shared<stats::model::CacheStats>();
        if (!deps.fuseStats) deps.fuseStats = std::make_shared<stats::model::FuseStats>();
    }

    void Deps::setSyncController(std::shared_ptr<sync::Controller> controller) {
        get().syncController = std::move(controller);
    }

    Deps::SanityStatus Deps::sanityStatus() const {
        return {
            .storageManager = static_cast<bool>(storageManager),
            .apiKeyManager = static_cast<bool>(apiKeyManager),
            .authManager = static_cast<bool>(authManager),
            .identityManager = static_cast<bool>(identityManager),
            .sessionManager = static_cast<bool>(sessionManager),
            .secretsManager = static_cast<bool>(secretsManager),
            .syncController = static_cast<bool>(syncController),
            .fsCache = static_cast<bool>(fsCache),
            .shellUsageManager = static_cast<bool>(shellUsageManager),
            .httpCacheStats = static_cast<bool>(httpCacheStats),
            .fuseSession = fuseSession != nullptr
        };
    }

}
