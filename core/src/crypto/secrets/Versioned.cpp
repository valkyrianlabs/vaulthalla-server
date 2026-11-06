#include "crypto/secrets/Versioned.hpp"

#include "crypto/secrets/Dependents.hpp"
#include "crypto/util/encrypt.hpp"
#include "db/Transactions.hpp"

#include <paths.h>
#include <pqxx/pqxx>

#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>

namespace vh::crypto::secrets::versioned {

namespace {

std::mutex cacheMutex;
// Keyed by the slot's sealed path, so a test that points paths::backingPath elsewhere never gets another
// directory's master.
std::map<std::string, std::shared_ptr<const KeyProvider>> cache;

std::string cacheKey(const Slot slot, const unsigned int version) {
    return (paths::getBackingPath() / slotName(slot, version)).string();
}

DependentsCheck dependentsOf(const Slot slot) {
    switch (slot) {
        case Slot::VaultMaster: return dependents::vaultMaster();
        case Slot::ApiKeyMaster: return dependents::apiKeyMaster();
        case Slot::GatewayMaster: return dependents::gatewayMaster();
    }
    throw std::logic_error("unknown master slot");
}

std::optional<unsigned int> previousVersion(const Slot slot) {
    return db::Transactions::exec("versioned::previousVersion", [&](pqxx::work& txn) -> std::optional<unsigned int> {
        const auto res = txn.exec("SELECT previous_version FROM master_secret_state WHERE slot = $1",
                                  pqxx::params{std::string(id(slot))});
        if (res.empty() || res.one_field_ref().is_null()) return std::nullopt;
        return res.one_field_ref().as<unsigned int>();
    });
}

std::string rollbackCommand(const Slot slot) {
    if (slot == Slot::VaultMaster) return "vh secret master rollback";
    return "vh secret master rollback --slot " + std::string(cliName(slot));
}

std::shared_ptr<const KeyProvider> openSlot(const Slot slot, const unsigned int version, const bool allowCreate) {
    if (version == 0) throw std::invalid_argument("master versions start at 1");
    const auto key = cacheKey(slot, version);
    {
        std::scoped_lock lock(cacheMutex);
        if (const auto it = cache.find(key); it != cache.end()) return it->second;
    }

    auto p = std::make_shared<KeyProvider>(slotName(slot, version));
    if (version == currentVersion(slot)) {
        if (allowCreate) {
            p->init();
        } else {
            try {
                p->initGuarded(dependentsOf(slot));
            } catch (const MasterSecretLost& e) {
                // Inside a recovery window the previous master may still hold every row (the *_prev wraps).
                if (const auto prev = previousVersion(slot))
                    throw MasterSecretLost(std::string(e.what()) + " A " + std::string(noun(slot)) +
                                           " rotation's recovery window is open: if version " + std::to_string(*prev) +
                                           " still unseals here, `" + rollbackCommand(slot) +
                                           "` restores every row it wrapped.");
                throw;
            }
        }
    } else {
        // Never generated: a version other than the current one is either sealed here or gone.
        if (!p->sealedExists())
            throw MasterSecretLost("The sealed " + std::string(noun(slot)) + " version " + std::to_string(version) +
                                   " ('" + slotName(slot, version) + "') is not on this host.");
        p->init();
    }

    std::scoped_lock lock(cacheMutex);
    const auto [it, _] = cache.emplace(key, std::move(p));
    return it->second;
}

}

std::string_view id(const Slot slot) noexcept {
    switch (slot) {
        case Slot::VaultMaster: return "vault_master";
        case Slot::ApiKeyMaster: return "ak_master";
        case Slot::GatewayMaster: return "s3gw_master";
    }
    return "unknown";
}

std::string_view noun(const Slot slot) noexcept {
    switch (slot) {
        case Slot::VaultMaster: return "vault master";
        case Slot::ApiKeyMaster: return "API key master";
        case Slot::GatewayMaster: return "S3 gateway master";
    }
    return "master";
}

std::string_view cliName(const Slot slot) noexcept {
    switch (slot) {
        case Slot::VaultMaster: return "vault";
        case Slot::ApiKeyMaster: return "api-keys";
        case Slot::GatewayMaster: return "s3-gateway";
    }
    return "unknown";
}

std::optional<Slot> parse(const std::string_view text) noexcept {
    for (const auto s : kSlots)
        if (text == id(s) || text == cliName(s)) return s;
    return std::nullopt;
}

std::string slotName(const Slot slot, const unsigned int version) {
    if (version == 0) throw std::invalid_argument("master versions start at 1");
    const std::string base = (paths::testMode ? "test_" : "") + std::string(id(slot));
    return version == 1 ? base : base + ".v" + std::to_string(version);
}

unsigned int currentVersion(const Slot slot) {
    return db::Transactions::exec("versioned::currentVersion", [&](pqxx::work& txn) {
        return txn.exec("SELECT vh_master_version($1)", pqxx::params{std::string(id(slot))})
            .one_field_ref()
            .as<unsigned int>();
    });
}

std::shared_ptr<const KeyProvider> provider(const Slot slot, const unsigned int version) {
    return openSlot(slot, version, false);
}

std::vector<uint8_t> unwrap(const Slot slot, const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& iv,
                            const unsigned int masterVersion) {
    const auto master = provider(slot, masterVersion);  // MasterSecretLost propagates as itself
    return util::decrypt_aes256_gcm(ciphertext, master->getMasterKey(), iv);
}

std::shared_mutex& gate(const Slot slot) {
    static std::array<std::shared_mutex, kSlots.size()> gates;
    return gates.at(static_cast<std::size_t>(slot));
}

Writer::Writer(const Slot slot, const bool allowCreate) : slot_(slot), lock_(gate(slot)) {
    version_ = currentVersion(slot);
    provider_ = openSlot(slot, version_, allowCreate);
}

Wrapped Writer::wrap(const std::span<const uint8_t> secret) const {
    Wrapped out{.master_version = version_};
    out.ciphertext = util::encrypt_aes256_gcm(secret, provider_->getMasterKey(), out.iv);
    return out;
}

std::vector<uint8_t> Writer::unwrap(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& iv) const {
    return util::decrypt_aes256_gcm(ciphertext, provider_->getMasterKey(), iv);
}

void forget(const Slot slot, const unsigned int version) {
    std::scoped_lock lock(cacheMutex);
    cache.erase(cacheKey(slot, version));
}

void resetForTesting() {
    std::scoped_lock lock(cacheMutex);
    cache.clear();
}

}
