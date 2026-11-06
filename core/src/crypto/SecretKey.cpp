#include "crypto/SecretKey.hpp"
#include "crypto/SecretBytes.hpp"

#include <sodium.h>

#include <algorithm>
#include <stdexcept>

namespace vh::crypto {

SecretKey::SecretKey(const std::span<const uint8_t> bytes) {
    if (bytes.size() != bytes_.size()) throw std::invalid_argument("AES-256 keys are 32 bytes");
    std::ranges::copy(bytes, bytes_.begin());
    // Keep the key out of swap where the platform allows it; failure is not fatal.
    (void)sodium_mlock(bytes_.data(), bytes_.size());
}

SecretKey::~SecretKey() {
    sodium_munlock(bytes_.data(), bytes_.size());  // also zeroes the memory
    notifySecretWiped(bytes_.data(), bytes_);
}

std::shared_ptr<const SecretKey> SecretKey::random() {
    std::array<uint8_t, util::AES_KEY_SIZE> raw{};
    randombytes_buf(raw.data(), raw.size());
    auto key = std::make_shared<const SecretKey>(raw);
    sodium_memzero(raw.data(), raw.size());
    return key;
}

}
