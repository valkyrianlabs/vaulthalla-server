#include "crypto/recovery/Seed.hpp"

#include "crypto/id/ObjectUid.hpp"
#include "crypto/util/uuid.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <sodium.h>

#include <algorithm>
#include <cctype>
#include <memory>

namespace vh::crypto::recovery {

namespace seed_detail {

constexpr std::string_view kAlphabet = "0123456789abcdefghjkmnpqrstvwxyz";
constexpr std::string_view kSalt = "vh.recovery.v1";

struct KdfDeleter {
    void operator()(EVP_KDF* p) const noexcept { EVP_KDF_free(p); }
};
struct KdfCtxDeleter {
    void operator()(EVP_KDF_CTX* p) const noexcept { EVP_KDF_CTX_free(p); }
};

char checkSymbol(const std::span<const uint8_t> seed) {
    std::array<uint8_t, crypto_hash_sha256_BYTES> digest{};
    crypto_hash_sha256(digest.data(), seed.data(), seed.size());
    return kAlphabet[digest[0] >> 3];
}

}

SeedError::SeedError(std::string code)
    : std::runtime_error("not a recovery seed (" + code + ")"), code_(std::move(code)) {}

RecoverySeed RecoverySeed::generate() {
    util::ensure_sodium_init();
    return RecoverySeed(SecretBytes::random(kSeedSize));
}

RecoverySeed RecoverySeed::fromBytes(const std::span<const uint8_t> bytes) {
    if (bytes.size() != kSeedSize) throw SeedError("bad_length");
    return RecoverySeed(SecretBytes(bytes));
}

RecoverySeed RecoverySeed::parse(const std::string_view text) {
    std::string clean;
    clean.reserve(kSeedTextSize);
    for (const char c : text) {
        if (std::isspace(static_cast<unsigned char>(c)) || c == '-') continue;
        clean.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    struct Wipe {
        std::string& s;
        ~Wipe() { wipeSecret(s); }
    } wipe{clean};
    if (clean.size() != kSeedTextSize) throw SeedError("bad_length");
    auto raw = id::fromBase32(std::string_view(clean).substr(0, kSeedTextSize - 1));
    if (!raw) throw SeedError("bad_symbol");
    RecoverySeed seed{SecretBytes(std::span<const uint8_t>(*raw))};
    sodium_memzero(raw->data(), raw->size());
    if (clean.back() != seed_detail::checkSymbol(seed.bytes())) throw SeedError("bad_check");
    return seed;
}

std::string RecoverySeed::text() const {
    id::ObjectUid raw{};
    std::ranges::copy(seed_.bytes(), raw.begin());
    auto out = id::toBase32(raw);
    sodium_memzero(raw.data(), raw.size());
    out.push_back(seed_detail::checkSymbol(seed_.bytes()));
    return out;
}

SecretBytes RecoverySeed::expand(const std::string_view label) const {
    const std::unique_ptr<EVP_KDF, seed_detail::KdfDeleter> kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    if (!kdf) throw std::runtime_error("OpenSSL HKDF is unavailable");
    const std::unique_ptr<EVP_KDF_CTX, seed_detail::KdfCtxDeleter> ctx(EVP_KDF_CTX_new(kdf.get()));
    if (!ctx) throw std::runtime_error("Failed to allocate an OpenSSL HKDF context");
    char digest[] = "SHA256";
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    std::string salt(seed_detail::kSalt), info(label);
    std::array<OSSL_PARAM, 6> params{
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<uint8_t*>(seed_.bytes().data()),
                                          seed_.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt.data(), salt.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info.data(), info.size()),
        OSSL_PARAM_construct_end()};
    std::array<uint8_t, 32> out{};
    if (EVP_KDF_derive(ctx.get(), out.data(), out.size(), params.data()) != 1)
        throw std::runtime_error("HKDF-SHA-256 derivation failed");
    SecretBytes key(out);
    sodium_memzero(out.data(), out.size());
    return key;
}

SecretBytes RecoverySeed::x25519SecretKey() const { return expand("x25519"); }

std::vector<uint8_t> RecoverySeed::x25519PublicKey() const {
    const auto sk = x25519SecretKey();
    std::vector<uint8_t> pk(crypto_scalarmult_BYTES);
    if (crypto_scalarmult_base(pk.data(), sk.bytes().data()) != 0)
        throw std::runtime_error("X25519 public key derivation failed");
    return pk;
}

SecretBytes RecoverySeed::ed25519Seed() const { return expand("ed25519"); }

std::vector<uint8_t> RecoverySeed::ed25519PublicKey() const {
    const auto seed = ed25519Seed();
    std::vector<uint8_t> pk(crypto_sign_PUBLICKEYBYTES);
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk{};
    const int rc = crypto_sign_seed_keypair(pk.data(), sk.data(), seed.bytes().data());
    sodium_memzero(sk.data(), sk.size());
    if (rc != 0) throw std::runtime_error("Ed25519 key derivation failed");
    return pk;
}

}
