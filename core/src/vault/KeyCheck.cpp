#include "vault/KeyCheck.hpp"

#include <sodium.h>

#include <array>
#include <stdexcept>
#include <vector>

namespace vh::vault {

std::string keyCheck(const std::span<const uint8_t> key, const unsigned int vaultId, const unsigned int version) {
    if (key.size() != 32) throw std::invalid_argument("a key check needs a 32-byte vault key");

    const auto id = std::to_string(vaultId);
    std::vector<uint8_t> message(kKeyCheckDomain.begin(), kKeyCheckDomain.end());
    message.insert(message.end(), id.begin(), id.end());
    message.push_back(static_cast<uint8_t>(version >> 24));
    message.push_back(static_cast<uint8_t>(version >> 16));
    message.push_back(static_cast<uint8_t>(version >> 8));
    message.push_back(static_cast<uint8_t>(version));

    std::array<uint8_t, 16> digest{};
    if (crypto_generichash(digest.data(), digest.size(), message.data(), message.size(), key.data(), key.size()) != 0)
        throw std::runtime_error("crypto_generichash failed");

    std::array<char, 33> hex{};
    sodium_bin2hex(hex.data(), hex.size(), digest.data(), digest.size());
    return {hex.data(), 32};
}

bool keyCheckEquals(const std::string& a, const std::string& b) {
    if (a.size() != 32 || b.size() != 32) return false;
    return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

}
