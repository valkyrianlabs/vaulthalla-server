#include "share/Token.hpp"

#include "crypto/model/Secret.hpp"
#include "crypto/util/uuid.hpp"
#include "db/Transactions.hpp"
#include "db/query/crypto/Secret.hpp"
#include "crypto/secrets/Manager.hpp"
#include "log/Registry.hpp"
#include "runtime/Deps.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <mutex>
#include <optional>
#include <regex>
#include <stdexcept>

namespace vh::share {
namespace {
constexpr std::string_view kPublicDomain = "vh/share-token/public/v1";
constexpr std::string_view kSessionDomain = "vh/share-token/session/v1";
constexpr size_t kSecretBytes = 32;
constexpr size_t kHashBytes = crypto_generichash_BYTES;

std::mutex pepper_mutex;
std::optional<std::vector<uint8_t>> cached_pepper;
std::optional<std::vector<uint8_t>> testing_pepper;

void ensure_sodium() {
    static const int init = [] {
        if (sodium_init() < 0) throw std::runtime_error("libsodium init failed");
        return 1;
    }();
    (void)init;
}

std::vector<uint8_t> random_bytes(const size_t size) {
    ensure_sodium();
    std::vector<uint8_t> out(size);
    randombytes_buf(out.data(), out.size());
    return out;
}

[[noreturn]] void pepperUnavailable(const std::string& why) {
    vh::log::Registry::crypto()->error("[share::Token] Share token pepper unavailable: {}", why);
    throw std::runtime_error("Share token pepper unavailable");
}

std::vector<uint8_t> asBytes(const std::string& s) { return {s.begin(), s.end()}; }
std::string asString(const std::vector<uint8_t>& v) { return {v.begin(), v.end()}; }

// Seals `pepper`, then reads it back through the same path every later start uses: a pepper only counts as stored
// once that round trip returns the same bytes.
void sealAndVerify(const vh::crypto::secrets::Manager& secrets, const std::vector<uint8_t>& pepper) {
    secrets.setSecret(Token::kSealedPepperKey, asString(pepper));
    const auto back = secrets.getSecret(Token::kSealedPepperKey);
    if (!back || asBytes(*back) != pepper) pepperUnavailable("sealed pepper did not read back identically");
}

std::vector<uint8_t> load_or_create_pepper() {
    std::lock_guard lock(pepper_mutex);
    if (testing_pepper) return *testing_pepper;
    if (cached_pepper) return *cached_pepper;

    if (!vh::db::Transactions::dbPool_) pepperUnavailable("no database");
    const auto secrets = vh::runtime::Deps::get().secretsManager;
    if (!secrets) pepperUnavailable("no secrets manager");

    using vh::db::query::crypto::Secret;
    try {
        const auto legacy = Secret::getSecret(Token::kLegacyPepperKey);  // plaintext row from before #322, if any
        if (secrets->hasSecret(Token::kSealedPepperKey)) {
            // Throws when the master key can't open it: fail closed, never regenerate (every link would break).
            const auto sealed = secrets->getSecret(Token::kSealedPepperKey);
            if (!sealed) pepperUnavailable("sealed pepper vanished while loading");
            auto pepper = asBytes(*sealed);
            if (pepper.size() < crypto_generichash_KEYBYTES_MIN) pepperUnavailable("sealed pepper is too short");
            if (legacy) {
                // A conversion stopped after sealing: finish it, but only if both copies agree.
                if (legacy->value != pepper) pepperUnavailable("plaintext and sealed peppers differ; refusing to choose");
                Secret::deleteSecret(Token::kLegacyPepperKey);
                vh::log::Registry::crypto()->info("[share::Token] Removed the plaintext share token pepper (already sealed)");
            }
            cached_pepper = std::move(pepper);
            return *cached_pepper;
        }

        if (legacy) {
            if (legacy->value.size() < crypto_generichash_KEYBYTES_MIN) pepperUnavailable("plaintext pepper is too short");
            sealAndVerify(*secrets, legacy->value);
            Secret::deleteSecret(Token::kLegacyPepperKey);
            vh::log::Registry::crypto()->info("[share::Token] Sealed the share token pepper; existing links keep working");
            cached_pepper = legacy->value;
            return *cached_pepper;
        }

        auto pepper = random_bytes(crypto_generichash_KEYBYTES);
        sealAndVerify(*secrets, pepper);
        cached_pepper = std::move(pepper);
        return *cached_pepper;
    } catch (const std::exception& e) {
        if (std::string_view(e.what()) == "Share token pepper unavailable") throw;
        pepperUnavailable(e.what());
    }
}

std::string prefix_for(const TokenKind kind) {
    switch (kind) {
        case TokenKind::PublicShare: return "vhs";
        case TokenKind::ShareSession: return "vhss";
    }
    throw std::invalid_argument("Invalid share token kind");
}

std::string_view domain_for(const TokenKind kind) {
    switch (kind) {
        case TokenKind::PublicShare: return kPublicDomain;
        case TokenKind::ShareSession: return kSessionDomain;
    }
    throw std::invalid_argument("Invalid share token kind");
}

bool is_uuid(const std::string_view value) {
    static const std::regex pattern("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    return std::regex_match(value.begin(), value.end(), pattern);
}

bool is_secret_char(const char c) {
    return std::isalnum(static_cast<unsigned char>(c)) != 0;
}
}

std::string to_string(const TokenKind kind) {
    switch (kind) {
        case TokenKind::PublicShare: return "public_share";
        case TokenKind::ShareSession: return "share_session";
    }
    throw std::invalid_argument("Invalid share token kind");
}

GeneratedToken Token::generate(const TokenKind kind) {
    ensure_sodium();
    const auto secret_bytes = random_bytes(kSecretBytes);
    const auto secret = vh::crypto::util::b32_crockford_encode(secret_bytes.data(), secret_bytes.size(), vh::crypto::util::Case::Lower);
    GeneratedToken token;
    token.kind = kind;
    token.lookup_id = vh::crypto::util::uuid4_hex();
    token.secret = secret;
    token.raw = prefix_for(kind) + "_" + token.lookup_id + "_" + token.secret;
    token.hash = hashSecret(kind, token.secret);
    return token;
}

ParsedToken Token::parse(const std::string_view raw) {
    const auto first = raw.find('_');
    const auto second = first == std::string_view::npos ? std::string_view::npos : raw.find('_', first + 1);
    if (first == std::string_view::npos || second == std::string_view::npos || raw.find('_', second + 1) != std::string_view::npos)
        throw std::invalid_argument("Malformed share token");

    const auto prefix = raw.substr(0, first);
    const auto lookup = raw.substr(first + 1, second - first - 1);
    const auto secret = raw.substr(second + 1);
    if (!is_uuid(lookup)) throw std::invalid_argument("Malformed share token lookup id");
    if (secret.empty() || !std::ranges::all_of(secret, is_secret_char)) throw std::invalid_argument("Malformed share token secret");

    TokenKind kind;
    if (prefix == "vhs") kind = TokenKind::PublicShare;
    else if (prefix == "vhss") kind = TokenKind::ShareSession;
    else throw std::invalid_argument("Malformed share token prefix");

    return {kind, std::string(lookup), std::string(secret)};
}

std::vector<uint8_t> Token::hashForDomain(const std::string_view domain, const std::string_view value) {
    ensure_sodium();
    const auto pepper = load_or_create_pepper();
    std::vector<uint8_t> out(kHashBytes);

    crypto_generichash_state state;
    if (crypto_generichash_init(&state, pepper.data(), pepper.size(), out.size()) != 0)
        throw std::runtime_error("Share token hash initialization failed");
    crypto_generichash_update(&state, reinterpret_cast<const unsigned char*>(domain.data()), domain.size());
    static constexpr char sep = '\0';
    crypto_generichash_update(&state, reinterpret_cast<const unsigned char*>(&sep), 1);
    crypto_generichash_update(&state, reinterpret_cast<const unsigned char*>(value.data()), value.size());
    crypto_generichash_final(&state, out.data(), out.size());
    return out;
}

std::vector<uint8_t> Token::hashSecret(const TokenKind kind, const std::string_view secret) {
    return hashForDomain(domain_for(kind), secret);
}

bool Token::verify(const std::vector<uint8_t>& expected_hash, const TokenKind kind, const std::string_view secret) {
    const auto actual = hashSecret(kind, secret);
    if (actual.size() != expected_hash.size()) return false;
    return sodium_memcmp(actual.data(), expected_hash.data(), actual.size()) == 0;
}

std::string Token::redact(const std::string_view raw_or_lookup) {
    try {
        const auto parsed = parse(raw_or_lookup);
        return prefix_for(parsed.kind) + "_" + parsed.lookup_id + "_<redacted>";
    } catch (...) {
        if (is_uuid(raw_or_lookup)) return std::string(raw_or_lookup) + "_<redacted>";
        return "<redacted-share-token>";
    }
}

void Token::setPepperForTesting(std::vector<uint8_t> pepper) {
    if (pepper.size() < crypto_generichash_KEYBYTES_MIN) throw std::invalid_argument("Share token pepper is too short");
    std::lock_guard lock(pepper_mutex);
    testing_pepper = std::move(pepper);
    cached_pepper.reset();
}

void Token::resetPepperCacheForTesting() {
    std::lock_guard lock(pepper_mutex);
    cached_pepper.reset();
}

void Token::clearPepperForTesting() {
    std::lock_guard lock(pepper_mutex);
    testing_pepper.reset();
    cached_pepper.reset();
}

}
