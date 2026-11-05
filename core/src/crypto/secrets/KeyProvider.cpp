#include "crypto/secrets/KeyProvider.hpp"
#include "platform/Sealer.hpp"

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
    if (platform::sealer::present(sealedDir_, name_)) {
        masterKey_ = platform::sealer::unseal(sealedDir_, name_);
        return;
    }
    if (initSecret) masterKey_ = std::vector<uint8_t>(initSecret->begin(), initSecret->end());
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
