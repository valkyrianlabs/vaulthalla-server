#include "crypto/secrets/KeyProvider.hpp"
#include "platform/Sealer.hpp"
#include "config/Registry.hpp"

#include <paths.h>
#include <sodium.h>
#include <stdexcept>

namespace vh::crypto::secrets {

namespace {

std::filesystem::path resolveSealedDir(const std::string& key) {
    return paths::getBackingPath() / (".sealed_" + key + ".blob");
}

}

KeyProvider::KeyProvider(const std::string& name)
    : name_(name), sealedDir_(resolveSealedDir(name)) {
}

void KeyProvider::init(const std::optional<std::string>& initSecret) {
    requirePosture();
    if (platform::sealer::present(sealedDir_, name_)) {
        masterKey_ = platform::sealer::unseal(sealedDir_, name_);
        return;
    }
    if (initSecret) masterKey_ = std::vector<uint8_t>(initSecret->begin(), initSecret->end());
    generateAndSeal();
}

void KeyProvider::initGuarded(const DependentsCheck& dependents) {
    requirePosture();
    if (platform::sealer::present(sealedDir_, name_)) {
        masterKey_ = platform::sealer::unseal(sealedDir_, name_);
        return;
    }
    if (dependents) {
        if (const auto what = dependents())
            throw MasterSecretLost(
                "The sealed master secret '" + name_ + "' is missing (" + sealedDir_.string() + "), but " + *what +
                " in the database are encrypted with it. Refusing to create a new one: that would make them "
                "permanently undecryptable. Restore the state directory from backup (with the same TPM or Secure "
                "Enclave), or restore the vault keys from their backups (`vh vault keys import`) and the internal "
                "secrets with `vh secret` (docs: vaults/secrets-and-key-export).");
    }
    generateAndSeal();
}

const std::vector<uint8_t>& KeyProvider::getMasterKey() const { return masterKey_; }

void KeyProvider::updateMasterKey(const std::vector<uint8_t>& newMasterKey) {
    masterKey_ = newMasterKey;
    generateAndSeal();
}

bool KeyProvider::sealedExists() const {
    return platform::sealer::complete(sealedDir_, name_);
}

std::string_view KeyProvider::backend() noexcept { return platform::sealer::backend(); }

std::string_view KeyProvider::posture() noexcept { return platform::sealer::posture(); }

void KeyProvider::requirePosture() {
    if (!config::Registry::get().secrets.require_hardware) return;
    if (const auto p = posture(); p != "hardware")
        throw std::runtime_error("secrets.require_hardware is set, but sealed secrets on this host are protected by '" +
                                 std::string(p) + "' sealing (" + std::string(backend()) +
                                 "), not hardware. Use a host with a hardware TPM (Linux) or the Secure Enclave "
                                 "(macOS), or turn the setting off.");
}

std::vector<uint8_t> KeyProvider::generateMasterSecret(const std::size_t bytes) {
    if (bytes == 0) throw std::invalid_argument("master secret size must be > 0");
    // Idempotent and thread-safe; a secret is never generated from an uninitialized libsodium.
    if (sodium_init() < 0) throw std::runtime_error("libsodium initialization failed; refusing to generate a master secret");
    std::vector<uint8_t> secret(bytes);
    randombytes_buf(secret.data(), secret.size());
    return secret;
}

void KeyProvider::generateAndSeal() {
    if (masterKey_.empty()) masterKey_ = generateMasterSecret();
    platform::sealer::seal(sealedDir_, name_, masterKey_);
}

} // namespace vh::crypto::secrets
