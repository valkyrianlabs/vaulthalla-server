#include "cloud/Signing.hpp"

#include <sodium.h>

#include <stdexcept>

namespace vh::cloud {

// Named, not anonymous: the unity build joins this file with others.
namespace signing_detail {

void ensureSodium() {
    if (sodium_init() < 0) throw std::runtime_error("libsodium failed to initialise");
}

void requireSeed(const std::span<const uint8_t> seed) {
    if (seed.size() != kSeedSize) throw std::invalid_argument("a cloud identity seed is 32 bytes");
}

}

std::string base64url(const std::span<const uint8_t> bytes) {
    signing_detail::ensureSodium();
    std::string out(sodium_base64_ENCODED_LEN(bytes.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING), '\0');
    sodium_bin2base64(out.data(), out.size(), bytes.data(), bytes.size(), sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    out.resize(out.find('\0'));
    return out;
}

std::string sha256Hex(const std::string_view bytes) {
    std::array<uint8_t, crypto_hash_sha256_BYTES> digest{};
    crypto_hash_sha256(digest.data(), reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(digest.size() * 2);
    for (const auto b : digest) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0xF]);
    }
    return out;
}

PublicKey publicKeyOf(std::span<const uint8_t> seed) {
    signing_detail::ensureSodium();
    signing_detail::requireSeed(seed);
    PublicKey pk{};
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk{};
    crypto_sign_seed_keypair(pk.data(), sk.data(), seed.data());
    sodium_memzero(sk.data(), sk.size());
    return pk;
}

std::string signDetached(const std::string_view message, std::span<const uint8_t> seed) {
    signing_detail::ensureSodium();
    signing_detail::requireSeed(seed);
    PublicKey pk{};
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk{};
    crypto_sign_seed_keypair(pk.data(), sk.data(), seed.data());
    std::array<uint8_t, crypto_sign_BYTES> sig{};
    crypto_sign_detached(sig.data(), nullptr, reinterpret_cast<const unsigned char*>(message.data()), message.size(),
                         sk.data());
    sodium_memzero(sk.data(), sk.size());
    return base64url(sig);
}

std::string fingerprint(const PublicKey& publicKey) {
    const auto hex = sha256Hex({reinterpret_cast<const char*>(publicKey.data()), publicKey.size()});
    return hex.substr(0, 4) + "-" + hex.substr(4, 4) + "-" + hex.substr(8, 4) + "-" + hex.substr(12, 4);
}

std::string newNonce() {
    signing_detail::ensureSodium();
    std::array<uint8_t, 16> raw{};
    randombytes_buf(raw.data(), raw.size());
    return base64url(raw);
}

std::string stringToSign(const SignedFields& f) {
    std::string out = "VHC1-Ed25519\n";
    for (const auto* part : {&f.method, &f.path, &f.query, &f.host, &f.installation}) out += *part + "\n";
    out += std::to_string(f.timestamp) + "\n" + f.nonce + "\n" + f.body_sha256;
    return out;
}

SignedHeaders sign(const SignedFields& f, std::span<const uint8_t> seed) {
    return {.authorization = "VHC1-Ed25519 Installation=" + f.installation + ", Timestamp=" + std::to_string(f.timestamp) +
                             ", Nonce=" + f.nonce + ", Signature=" + signDetached(stringToSign(f), seed),
            .content_sha256 = f.body_sha256};
}

}
