#include "crypto/SecretKey.hpp"

#include <sodium.h>

#include <array>

namespace vh::crypto {

std::shared_ptr<const SecretKey> SecretKey::random() {
    std::array<uint8_t, util::AES_KEY_SIZE> raw{};
    randombytes_buf(raw.data(), raw.size());
    auto key = std::make_shared<const SecretKey>(raw);
    sodium_memzero(raw.data(), raw.size());
    return key;
}

}
