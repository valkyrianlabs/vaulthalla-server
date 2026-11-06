#include "vault/Master.hpp"

#include "crypto/secrets/Dependents.hpp"
#include "crypto/util/encrypt.hpp"
#include "db/Transactions.hpp"

#include <paths.h>
#include <pqxx/pqxx>

#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>

namespace vh::vault::master {

namespace {

std::mutex cacheMutex;
// Keyed by the slot's sealed path, so a test that points paths::backingPath elsewhere never gets another
// directory's master.
std::map<std::string, std::shared_ptr<const crypto::secrets::KeyProvider>> cache;

std::string cacheKey(const unsigned int version) {
    return (paths::getBackingPath() / slotName(version)).string();
}

std::optional<unsigned int> previousVersion() {
    return db::Transactions::exec("vault::master::previousVersion", [](pqxx::work& txn) -> std::optional<unsigned int> {
        const auto res = txn.exec("SELECT previous_version FROM vault_master_state WHERE id");
        if (res.empty() || res.one_field_ref().is_null()) return std::nullopt;
        return res.one_field_ref().as<unsigned int>();
    });
}

std::shared_ptr<const crypto::secrets::KeyProvider> open(const unsigned int version, const bool allowCreate) {
    if (version == 0) throw std::invalid_argument("vault master versions start at 1");
    const auto key = cacheKey(version);
    {
        std::scoped_lock lock(cacheMutex);
        if (const auto it = cache.find(key); it != cache.end()) return it->second;
    }

    auto p = std::make_shared<crypto::secrets::KeyProvider>(slotName(version));
    if (version == currentVersion()) {
        if (allowCreate) {
            p->init();
        } else {
            try {
                p->initGuarded(crypto::secrets::dependents::vaultMaster());
            } catch (const crypto::secrets::MasterSecretLost& e) {
                // Inside a recovery window the previous master may still hold every row (migration 120, *_prev).
                if (const auto prev = previousVersion())
                    throw crypto::secrets::MasterSecretLost(
                        std::string(e.what()) + " A vault master rotation's recovery window is open: if version " +
                        std::to_string(*prev) + " still unseals here, `vh secret master rollback` restores every "
                        "key row it wrapped.");
                throw;
            }
        }
    } else {
        // Never generated: a version other than the current one is either sealed here or gone.
        if (!p->sealedExists())
            throw crypto::secrets::MasterSecretLost("The sealed vault master version " + std::to_string(version) +
                                                    " ('" + slotName(version) + "') is not on this host.");
        p->init();
    }

    std::scoped_lock lock(cacheMutex);
    const auto [it, _] = cache.emplace(key, std::move(p));
    return it->second;
}

}

std::string slotName(const unsigned int version) {
    if (version == 0) throw std::invalid_argument("vault master versions start at 1");
    const std::string base = paths::testMode ? "test_vault_master" : "vault_master";
    return version == 1 ? base : base + ".v" + std::to_string(version);
}

unsigned int currentVersion() {
    return db::Transactions::exec("vault::master::currentVersion", [](pqxx::work& txn) {
        return txn.exec("SELECT vh_vault_master_version()").one_field_ref().as<unsigned int>();
    });
}

std::shared_ptr<const crypto::secrets::KeyProvider> provider(const unsigned int version) { return open(version, false); }

std::vector<uint8_t> unwrap(const std::vector<uint8_t>& encryptedKey, const std::vector<uint8_t>& iv,
                            const unsigned int masterVersion) {
    const auto master = provider(masterVersion);  // MasterSecretLost propagates as itself
    return crypto::util::decrypt_aes256_gcm(encryptedKey, master->getMasterKey(), iv);
}

std::shared_mutex& gate() {
    static std::shared_mutex g;
    return g;
}

Writer::Writer(const bool allowCreate) : lock_(gate()) {
    version_ = currentVersion();
    provider_ = open(version_, allowCreate);
}

Wrapped Writer::wrap(const std::span<const uint8_t> key) const {
    Wrapped out{.master_version = version_};
    out.encrypted_key = crypto::util::encrypt_aes256_gcm(key, provider_->getMasterKey(), out.iv);
    return out;
}

void forget(const unsigned int version) {
    std::scoped_lock lock(cacheMutex);
    cache.erase(cacheKey(version));
}

void resetForTesting() {
    std::scoped_lock lock(cacheMutex);
    cache.clear();
}

}
