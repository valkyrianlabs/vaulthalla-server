#include "crypto/secrets/KeyProvider.hpp"
#include "platform/Sealer.hpp"

#include <algorithm>
#include <random>
#include <paths.h>

namespace vh::crypto::secrets {

namespace {

std::filesystem::path resolveSealedDir(const std::string& key) {
    return paths::getBackingPath() / (".sealed_" + key + ".blob");
}

std::vector<uint8_t> randomKey(const std::size_t n = 32) {
    std::vector<uint8_t> k(n);
    std::random_device rd;
    std::generate(k.begin(), k.end(), [&] { return static_cast<uint8_t>(rd()); });
    return k;
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

void KeyProvider::generateAndSeal() {
    if (masterKey_.empty()) masterKey_ = randomKey();
    platform::sealer::seal(sealedDir_, name_, masterKey_);
}

} // namespace vh::crypto::secrets
