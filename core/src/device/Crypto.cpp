#include "device/Crypto.hpp"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <stdexcept>

namespace vh::device::crypto {

namespace {

constexpr std::string_view kCommitDomain{"vh-pair-commit-v1"};
constexpr std::string_view kSasDomain{"vh-pair-v1"};
constexpr std::string_view kRotateDomain{"vh-device-rotate-v1"};
constexpr std::string_view kP256GroupName{"prime256v1"};

struct PkeyFree { void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); } };
struct X509Free { void operator()(X509* p) const noexcept { X509_free(p); } };
struct MdCtxFree { void operator()(EVP_MD_CTX* p) const noexcept { EVP_MD_CTX_free(p); } };
struct PkeyCtxFree { void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); } };
struct ParamBldFree { void operator()(OSSL_PARAM_BLD* p) const noexcept { OSSL_PARAM_BLD_free(p); } };
struct ParamFree { void operator()(OSSL_PARAM* p) const noexcept { OSSL_PARAM_free(p); } };

using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyFree>;

void append(std::vector<uint8_t>& out, const std::string_view s) { out.insert(out.end(), s.begin(), s.end()); }
void append(std::vector<uint8_t>& out, const Hash& h) { out.insert(out.end(), h.begin(), h.end()); }

bool isP256(const EVP_PKEY* key) noexcept {
    if (!key || EVP_PKEY_get_base_id(key) != EVP_PKEY_EC) return false;
    char group[64]{};
    std::size_t len = 0;
    if (EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof(group), &len) != 1) return false;
    return std::string_view(group, len) == kP256GroupName;
}

std::optional<std::vector<uint8_t>> spkiDerOf(const EVP_PKEY* key) noexcept {
    unsigned char* der = nullptr;
    const int len = i2d_PUBKEY(key, &der);
    if (len <= 0 || !der) return std::nullopt;
    std::vector<uint8_t> out(der, der + len);
    OPENSSL_free(der);
    return out;
}

int hexValue(const char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

}

std::string toHex(const std::span<const uint8_t> bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const auto b : bytes) {
        out.push_back(kDigits[b >> 4]);
        out.push_back(kDigits[b & 0x0f]);
    }
    return out;
}

std::optional<Hash> hashFromHex(const std::string_view hex) {
    if (hex.size() != 64) return std::nullopt;
    Hash out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        const int hi = hexValue(hex[2 * i]);
        const int lo = hexValue(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return out;
}

std::string toBase64(const std::span<const uint8_t> bytes) {
    if (bytes.empty()) return {};
    std::string out(4 * ((bytes.size() + 2) / 3), '\0');
    const int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), bytes.data(), static_cast<int>(bytes.size()));
    out.resize(static_cast<std::size_t>(std::max(n, 0)));
    return out;
}

std::optional<std::vector<uint8_t>> fromBase64(const std::string_view text) {
    if (text.empty()) return std::vector<uint8_t>{};
    if (text.size() % 4 != 0) return std::nullopt;
    std::size_t padding = 0;
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        const bool alnum = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
        if (alnum || c == '+' || c == '/') {
            if (padding) return std::nullopt;  // nothing after '='
            continue;
        }
        if (c != '=' || i + 2 < text.size()) return std::nullopt;  // '=' only in the last two positions
        ++padding;
    }
    std::vector<uint8_t> out(3 * (text.size() / 4));
    const int n = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(text.data()),
                                  static_cast<int>(text.size()));
    if (n < 0 || static_cast<std::size_t>(n) < padding) return std::nullopt;
    out.resize(static_cast<std::size_t>(n) - padding);
    return out;
}

Hash sha256(const std::span<const uint8_t> bytes) {
    Hash out{};
    unsigned int len = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), out.data(), &len, EVP_sha256(), nullptr) != 1 || len != out.size())
        throw std::runtime_error("SHA-256 failed");
    return out;
}

bool constantTimeEqual(const std::span<const uint8_t> a, const std::span<const uint8_t> b) noexcept {
    if (a.size() != b.size()) return false;
    return a.empty() || CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

bool constantTimeEqual(const std::string_view a, const std::string_view b) noexcept {
    return constantTimeEqual(std::span(reinterpret_cast<const uint8_t*>(a.data()), a.size()),
                             std::span(reinterpret_cast<const uint8_t*>(b.data()), b.size()));
}

Hash commitment(const Hash& deviceSpki, const Hash& nonceDevice) {
    std::vector<uint8_t> msg;
    msg.reserve(kCommitDomain.size() + 64);
    append(msg, kCommitDomain);
    append(msg, deviceSpki);
    append(msg, nonceDevice);
    return sha256(msg);
}

Hash sasDigest(const Hash& serverSpki, const Hash& deviceSpki, const Hash& nonceDevice, const Hash& nonceServer) {
    std::vector<uint8_t> msg;
    msg.reserve(kSasDomain.size() + 128);
    append(msg, kSasDomain);
    append(msg, serverSpki);
    append(msg, deviceSpki);
    append(msg, nonceDevice);
    append(msg, nonceServer);
    return sha256(msg);
}

std::string sasCode(const Hash& digest) {
    uint64_t value = 0;
    for (std::size_t i = 0; i < 8; ++i) value = (value << 8) | digest[i];
    auto code = std::to_string(value % 1'000'000);
    return std::string(6 - code.size(), '0') + code;
}

std::string displayCode(const std::string_view code) {
    if (code.size() != 6) return std::string(code);
    return std::string(code.substr(0, 3)) + " " + std::string(code.substr(3));
}

std::optional<std::string> normalizeCode(const std::string_view text) {
    std::string digits;
    for (const char c : text) {
        if (c >= '0' && c <= '9') digits.push_back(c);
        else if (c != ' ' && c != '-') return std::nullopt;
        if (digits.size() > 6) return std::nullopt;
    }
    if (digits.size() != 6) return std::nullopt;
    return digits;
}

Hash randomNonce() {
    Hash out{};
    if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) throw std::runtime_error("CSPRNG failure");
    return out;
}

std::string randomCode() {
    // Rejection sampling keeps the six digits uniform: 4 294 000 000 is the largest multiple of 10^6 below 2^32.
    for (;;) {
        uint32_t v = 0;
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&v), sizeof(v)) != 1) throw std::runtime_error("CSPRNG failure");
        if (v >= 4'294'000'000u) continue;
        auto code = std::to_string(v % 1'000'000);
        return std::string(6 - code.size(), '0') + code;
    }
}

std::string randomHex(const std::size_t n) {
    std::vector<uint8_t> bytes(n);
    if (n && RAND_bytes(bytes.data(), static_cast<int>(n)) != 1) throw std::runtime_error("CSPRNG failure");
    return toHex(bytes);
}

std::vector<uint8_t> rotationMessage(const Hash& newSpki, const Hash& serverSpki, const uint64_t timestamp) {
    std::vector<uint8_t> msg;
    msg.reserve(kRotateDomain.size() + 72);
    append(msg, kRotateDomain);
    append(msg, newSpki);
    append(msg, serverSpki);
    for (int shift = 56; shift >= 0; shift -= 8) msg.push_back(static_cast<uint8_t>(timestamp >> shift));
    return msg;
}

bool verifyEcdsaP256Sha256(const std::span<const uint8_t> spkiDer, const std::span<const uint8_t> message,
                           const std::span<const uint8_t> signature) {
    const unsigned char* p = spkiDer.data();
    PkeyPtr key(d2i_PUBKEY(nullptr, &p, static_cast<long>(spkiDer.size())));
    if (!key || p != spkiDer.data() + spkiDer.size() || !isP256(key.get())) return false;
    const std::unique_ptr<EVP_MD_CTX, MdCtxFree> ctx(EVP_MD_CTX_new());
    if (!ctx || EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key.get()) != 1) return false;
    return EVP_DigestVerify(ctx.get(), signature.data(), signature.size(), message.data(), message.size()) == 1;
}

std::optional<PublicKey> p256KeyOf(const X509* certificate) noexcept {
    if (!certificate) return std::nullopt;
    if (!isP256(X509_get0_pubkey(certificate))) return std::nullopt;
    // The SPKI exactly as the certificate encodes it (spec §1), not a re-encoding of the key.
    unsigned char* der = nullptr;
    const int len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(certificate), &der);
    if (len <= 0 || !der) return std::nullopt;
    PublicKey out;
    out.spkiDer.assign(der, der + len);
    OPENSSL_free(der);
    try {
        out.spkiSha256 = sha256(out.spkiDer);
    } catch (...) {
        return std::nullopt;
    }
    return out;
}

std::optional<PublicKey> p256KeyOfCertificate(const std::span<const uint8_t> der) noexcept {
    if (der.empty()) return std::nullopt;
    const unsigned char* p = der.data();
    const std::unique_ptr<X509, X509Free> cert(d2i_X509(nullptr, &p, static_cast<long>(der.size())));
    if (!cert || p != der.data() + der.size()) return std::nullopt;
    return p256KeyOf(cert.get());
}

std::optional<PublicKey> p256KeyFromPoint(const std::span<const uint8_t> point) {
    if (point.size() != 65 || point[0] != 0x04) return std::nullopt;
    const std::unique_ptr<OSSL_PARAM_BLD, ParamBldFree> bld(OSSL_PARAM_BLD_new());
    if (!bld ||
        OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, kP256GroupName.data(), 0) != 1 ||
        OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, point.data(), point.size()) != 1)
        return std::nullopt;
    const std::unique_ptr<OSSL_PARAM, ParamFree> params(OSSL_PARAM_BLD_to_param(bld.get()));
    const std::unique_ptr<EVP_PKEY_CTX, PkeyCtxFree> ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    EVP_PKEY* raw = nullptr;
    if (!params || !ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1 ||
        EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_PUBLIC_KEY, params.get()) != 1)
        return std::nullopt;
    const PkeyPtr key(raw);
    // fromdata does not prove the point is on the curve; the public-key check does.
    const std::unique_ptr<EVP_PKEY_CTX, PkeyCtxFree> check(EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr));
    if (!check || EVP_PKEY_public_check(check.get()) != 1) return std::nullopt;
    auto der = spkiDerOf(key.get());
    if (!der) return std::nullopt;
    PublicKey out{.spkiDer = std::move(*der)};
    out.spkiSha256 = sha256(out.spkiDer);
    return out;
}

}
