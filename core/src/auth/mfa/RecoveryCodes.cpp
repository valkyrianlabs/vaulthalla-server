#include "auth/mfa/RecoveryCodes.hpp"

#include "crypto/util/uuid.hpp"

#include <sodium.h>

#include <cctype>
#include <stdexcept>

namespace vh::auth::mfa::recovery {

std::string generateCode() {
    crypto::util::ensure_sodium_init();
    std::string out;
    out.reserve(kCodeChars + 1);
    for (std::size_t i = 0; i < kCodeChars; ++i) {
        if (i == kCodeChars / 2) out.push_back('-');
        out.push_back(crypto::util::kBase32Crockford[randombytes_uniform(32)]);
    }
    return out;
}

std::optional<std::string> normalize(const std::string_view input) {
    if (input.size() > 32) return std::nullopt;
    std::string out;
    out.reserve(kCodeChars);
    for (const unsigned char raw : input) {
        if (raw == '-' || raw == ' ') continue;
        auto ch = static_cast<char>(std::toupper(raw));
        if (ch == 'I' || ch == 'L') ch = '1';
        else if (ch == 'O') ch = '0';
        if (std::string_view(crypto::util::kBase32Crockford).find(ch) == std::string_view::npos) {
            sodium_memzero(out.data(), out.size());
            return std::nullopt;
        }
        out.push_back(ch);
    }
    if (out.size() != kCodeChars) {
        sodium_memzero(out.data(), out.size());
        return std::nullopt;
    }
    return out;
}

Hash hash(const std::span<const uint8_t> pepper, const uint32_t userId, const std::string_view normalized) {
    if (pepper.size() < crypto_generichash_KEYBYTES_MIN || pepper.size() > crypto_generichash_KEYBYTES_MAX)
        throw std::invalid_argument("recovery code pepper has the wrong length");
    crypto::util::ensure_sodium_init();
    crypto_generichash_state state;
    if (crypto_generichash_init(&state, pepper.data(), pepper.size(), kHashBytes) != 0)
        throw std::runtime_error("BLAKE2b init failed");
    crypto_generichash_update(&state, reinterpret_cast<const unsigned char*>(kDomain.data()), kDomain.size());
    const std::array<unsigned char, 4> user{static_cast<unsigned char>(userId >> 24),
                                            static_cast<unsigned char>(userId >> 16),
                                            static_cast<unsigned char>(userId >> 8),
                                            static_cast<unsigned char>(userId)};
    crypto_generichash_update(&state, user.data(), user.size());
    crypto_generichash_update(&state, reinterpret_cast<const unsigned char*>(normalized.data()), normalized.size());
    Hash out{};
    crypto_generichash_final(&state, out.data(), out.size());
    sodium_memzero(&state, sizeof(state));
    return out;
}

}
