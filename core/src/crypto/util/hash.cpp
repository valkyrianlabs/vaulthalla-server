#include "crypto/util/hash.hpp"

#include <sodium.h>
#include <paths.h>

#include <atomic>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <array>

constexpr std::size_t OPSLIMIT = crypto_pwhash_OPSLIMIT_MODERATE;
constexpr std::size_t MEMLIMIT = crypto_pwhash_MEMLIMIT_MODERATE;

namespace vh::crypto::hash {

namespace {
// The unit-test binary's switch (setMinimalPasswordCostForTesting); the daemon never sets it, test instances included.
std::atomic<bool> minimalCostForTesting{false};
}

void setMinimalPasswordCostForTesting() {
    if (!paths::isTestMode()) throw std::logic_error("setMinimalPasswordCostForTesting: refused outside test mode");
    minimalCostForTesting = true;
}

std::string blake2b(const std::filesystem::path& filepath) {
    constexpr size_t hash_len = crypto_generichash_BYTES;
    unsigned char hash[hash_len];

    std::ifstream file(filepath, std::ios::binary);
    if (!file) throw std::runtime_error("Failed to open file for hashing: " + filepath.string());

    crypto_generichash_state state;
    crypto_generichash_init(&state, nullptr, 0, hash_len);

    char buffer[8192];
    while (file.good()) {
        file.read(buffer, sizeof(buffer));
        crypto_generichash_update(&state, reinterpret_cast<unsigned char*>(buffer), file.gcount());
    }

    crypto_generichash_final(&state, hash, hash_len);

    std::ostringstream result;
    for (size_t i = 0; i < hash_len; ++i)
        result << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];

    return result.str();
}

std::string password(const std::string& password) {
    char hashed[crypto_pwhash_STRBYTES];

    const bool minimal = minimalCostForTesting.load();
    if (crypto_pwhash_str(hashed, password.c_str(), password.size(), minimal ? crypto_pwhash_OPSLIMIT_MIN : OPSLIMIT,
                          minimal ? crypto_pwhash_MEMLIMIT_MIN : MEMLIMIT) != 0)
        throw std::runtime_error("Password hashing failed (out of memory?)");

    return {hashed};
}

bool verifyPassword(const std::string& password, const std::string& hash) {
    return crypto_pwhash_str_verify(hash.c_str(), password.c_str(), password.size()) == 0;
}

namespace {
constexpr std::string_view kTokenDigestPrefix = "sha256:";
constexpr std::size_t kTokenDigestHexLen = crypto_hash_sha256_BYTES * 2;

void ensureSodium() {
    static const bool ready = sodium_init() >= 0;
    if (!ready) throw std::runtime_error("libsodium failed to initialize");
}

bool isLowerHex(const std::string_view s) {
    for (const char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

bool isPwhashString(const std::string& stored) {
    return stored.size() < crypto_pwhash_STRBYTES &&
           (stored.starts_with("$argon2id$") || stored.starts_with("$argon2i$"));
}
}

std::string tokenDigest(const std::string_view token) {
    ensureSodium();

    std::array<unsigned char, crypto_hash_sha256_BYTES> digest{};
    crypto_hash_sha256(digest.data(), reinterpret_cast<const unsigned char*>(token.data()), token.size());

    std::array<char, kTokenDigestHexLen + 1> hex{};
    sodium_bin2hex(hex.data(), hex.size(), digest.data(), digest.size());

    std::string out;
    out.reserve(kTokenDigestPrefix.size() + kTokenDigestHexLen);
    out.append(kTokenDigestPrefix);
    out.append(hex.data(), kTokenDigestHexLen);
    return out;
}

TokenMatch verifyToken(const std::string_view token, const std::string& stored) {
    if (stored.starts_with(kTokenDigestPrefix)) {
        const auto hex = std::string_view(stored).substr(kTokenDigestPrefix.size());
        if (hex.size() != kTokenDigestHexLen || !isLowerHex(hex)) return TokenMatch::Mismatch;

        const auto expected = tokenDigest(token);
        return sodium_memcmp(expected.data(), stored.data(), expected.size()) == 0
                   ? TokenMatch::Digest
                   : TokenMatch::Mismatch;
    }

    if (isPwhashString(stored)) {
        ensureSodium();
        if (crypto_pwhash_str_verify(stored.c_str(), token.data(), token.size()) == 0) return TokenMatch::Legacy;
    }

    return TokenMatch::Mismatch;
}

std::string generate_secure_password(const size_t length) {
    if (sodium_init() < 0) throw std::runtime_error("libsodium failed to initialize");

    constexpr std::string_view alphabet =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!@#$%^&*()-_=+[]{}<>?/|\\:;,.~";

    std::string password;
    password.reserve(length);
    for (size_t i = 0; i < length; ++i) password.push_back(alphabet[randombytes_uniform(alphabet.size())]);
    return password;
}

}
