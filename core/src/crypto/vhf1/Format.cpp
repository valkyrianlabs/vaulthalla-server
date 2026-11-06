#include "crypto/vhf1/Format.hpp"

#include "crypto/util/Gcm.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <string>
#include <utility>

namespace vh::crypto::vhf1 {

namespace format_detail {

constexpr std::array<std::pair<ErrorCode, std::string_view>, 17> kErrorNames{{
    {ErrorCode::BadMagic, "bad_magic"},
    {ErrorCode::UnsupportedVersion, "unsupported_version"},
    {ErrorCode::BadHeaderLength, "bad_header_length"},
    {ErrorCode::UnsupportedSuite, "unsupported_suite"},
    {ErrorCode::BadChunkSize, "bad_chunk_size"},
    {ErrorCode::ReservedNonzero, "reserved_nonzero"},
    {ErrorCode::KindMismatch, "kind_mismatch"},
    {ErrorCode::VaultMismatch, "vault_mismatch"},
    {ErrorCode::ObjectMismatch, "object_mismatch"},
    {ErrorCode::GenerationMismatch, "generation_mismatch"},
    {ErrorCode::KeyUnavailable, "key_unavailable"},
    {ErrorCode::HeaderAuthFailed, "header_auth_failed"},
    {ErrorCode::SizeUnknown, "size_unknown"},
    {ErrorCode::SizeMismatch, "size_mismatch"},
    {ErrorCode::BadSize, "bad_size"},
    {ErrorCode::RangeOutOfBounds, "range_out_of_bounds"},
    {ErrorCode::ChunkAuthFailed, "chunk_auth_failed"},
}};

constexpr std::string_view kInfoHeader = "vh.f1.hdr";
constexpr std::string_view kInfoContent = "vh.f1.enc";

// Header field offsets (§3.2).
constexpr std::size_t kOffVersion = 8, kOffHeaderLen = 10, kOffSuite = 12, kOffChunkLog2 = 14, kOffKind = 15,
                      kOffKeyVersion = 16, kOffReserved = 20, kOffVaultUid = 24, kOffObjectUid = 40, kOffSalt = 56;

[[nodiscard]] uint16_t readBe16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

[[nodiscard]] uint32_t readBe32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

void writeBe16(uint8_t* p, const uint16_t v) {
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v);
}

void writeBe32(uint8_t* p, const uint32_t v) {
    for (int i = 0; i < 4; ++i) p[i] = static_cast<uint8_t>(v >> (24 - 8 * i));
}

void writeBe64(uint8_t* p, const uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = static_cast<uint8_t>(v >> (56 - 8 * i));
}

[[nodiscard]] bool equalCt(const uint8_t* a, const uint8_t* b, const std::size_t n) {
    return sodium_memcmp(a, b, n) == 0;
}

struct KdfDeleter {
    void operator()(EVP_KDF* kdf) const noexcept { EVP_KDF_free(kdf); }
};
struct KdfCtxDeleter {
    void operator()(EVP_KDF_CTX* ctx) const noexcept { EVP_KDF_CTX_free(ctx); }
};

// RFC 5869 through OpenSSL's HKDF provider, one mode at a time (the spec publishes PRK, K_hdr and K_enc separately).
void hkdfSha256(int mode, const std::span<const uint8_t> key, const std::span<const uint8_t> salt,
                const std::span<const uint8_t> info, const std::span<uint8_t> out) {
    const std::unique_ptr<EVP_KDF, KdfDeleter> kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    if (!kdf) throw std::runtime_error("OpenSSL HKDF is unavailable");
    const std::unique_ptr<EVP_KDF_CTX, KdfCtxDeleter> ctx(EVP_KDF_CTX_new(kdf.get()));
    if (!ctx) throw std::runtime_error("Failed to allocate an OpenSSL HKDF context");

    char digest[] = "SHA256";
    std::array<OSSL_PARAM, 6> params{};
    std::size_t n = 0;
    params[n++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
    params[n++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<uint8_t*>(key.data()),
                                                    key.size());
    if (!salt.empty())
        params[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<uint8_t*>(salt.data()),
                                                        salt.size());
    if (!info.empty())
        params[n++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<uint8_t*>(info.data()),
                                                        info.size());
    params[n] = OSSL_PARAM_construct_end();
    if (EVP_KDF_derive(ctx.get(), out.data(), out.size(), params.data()) != 1)
        throw std::runtime_error("HKDF-SHA-256 derivation failed");
}

[[nodiscard]] SecretKeyPtr expandKey(const SecretKey& prk, const std::string_view label, const HeaderHash& hh) {
    std::array<uint8_t, 9 + kHashSize> info{};
    std::memcpy(info.data(), label.data(), label.size());
    std::ranges::copy(hh, info.begin() + static_cast<std::ptrdiff_t>(label.size()));
    std::array<uint8_t, util::AES_KEY_SIZE> raw{};
    hkdfSha256(EVP_KDF_HKDF_MODE_EXPAND_ONLY, prk.bytes(), {}, {info.data(), label.size() + kHashSize}, raw);
    auto key = std::make_shared<const SecretKey>(raw);
    sodium_memzero(raw.data(), raw.size());
    return key;
}

[[nodiscard]] util::GcmKey gcmKeyOf(const SecretKey& key) { return key.bytes(); }

}

std::string_view errorCodeName(const ErrorCode code) {
    for (const auto& [c, name] : format_detail::kErrorNames)
        if (c == code) return name;
    return "unknown";
}

std::optional<ErrorCode> errorCodeFromName(const std::string_view name) {
    for (const auto& [c, n] : format_detail::kErrorNames)
        if (n == name) return c;
    return std::nullopt;
}

namespace format_detail {

[[nodiscard]] std::string errorMessage(const ErrorCode code, const std::optional<uint64_t> chunkIndex) {
    std::string out = "VHF1: ";
    out += errorCodeName(code);
    if (chunkIndex) out += " at chunk " + std::to_string(*chunkIndex);
    return out;
}

}

Error::Error(const ErrorCode code, const std::optional<uint64_t> chunkIndex)
    : std::runtime_error(format_detail::errorMessage(code, chunkIndex)), code_(code), chunkIndex_(chunkIndex) {}

Salt freshSalt() {
    Salt salt{};
    randombytes_buf(salt.data(), salt.size());
    return salt;
}

HeaderBody encodeHeaderBody(const HeaderParams& params) {
    using namespace format_detail;
    const auto kind = static_cast<uint8_t>(params.kind);
    if (kind < 1 || kind > 3) throw std::invalid_argument("VHF1: unknown object kind");
    if (params.keyVersion == 0) throw std::invalid_argument("VHF1: key versions start at 1");
    if (params.chunkLog2 < kMinChunkLog2 || params.chunkLog2 > kMaxChunkLog2)
        throw std::invalid_argument("VHF1: chunk size out of range");

    HeaderBody body{};
    std::ranges::copy(kMagic, body.begin());
    writeBe16(body.data() + kOffVersion, kFormatVersion);
    writeBe16(body.data() + kOffHeaderLen, static_cast<uint16_t>(kHeaderSize));
    writeBe16(body.data() + kOffSuite, kSuiteAes256GcmHkdfSha256);
    body[kOffChunkLog2] = params.chunkLog2;
    body[kOffKind] = kind;
    writeBe32(body.data() + kOffKeyVersion, params.keyVersion);
    // bytes 20..24 reserved, zero
    std::ranges::copy(params.vaultUid, body.begin() + kOffVaultUid);
    std::ranges::copy(params.objectUid, body.begin() + kOffObjectUid);
    std::ranges::copy(params.salt, body.begin() + kOffSalt);
    return body;
}

HeaderHash headerHash(const std::span<const uint8_t, kHeaderBodySize> body) {
    HeaderHash hh{};
    unsigned int len = 0;
    if (EVP_Digest(body.data(), body.size(), hh.data(), &len, EVP_sha256(), nullptr) != 1 || len != hh.size())
        throw std::runtime_error("SHA-256 failed");
    return hh;
}

KeySchedule deriveKeys(const SecretKey& vaultKey, const Salt& salt, const HeaderHash& hh) {
    std::array<uint8_t, kHashSize> prkRaw{};
    format_detail::hkdfSha256(EVP_KDF_HKDF_MODE_EXTRACT_ONLY, vaultKey.bytes(), salt, {}, prkRaw);
    auto prk = std::make_shared<const SecretKey>(prkRaw);
    sodium_memzero(prkRaw.data(), prkRaw.size());
    KeySchedule ks;
    ks.headerKey = format_detail::expandKey(*prk, format_detail::kInfoHeader, hh);
    ks.contentKey = format_detail::expandKey(*prk, format_detail::kInfoContent, hh);
    ks.prk = std::move(prk);
    return ks;
}

HeaderTag headerTag(const SecretKey& headerKey, const std::span<const uint8_t, kHeaderBodySize> body) {
    HeaderTag tag{};
    std::size_t len = 0;
    const auto key = headerKey.bytes();
    if (EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA256", nullptr, key.data(), key.size(), body.data(), body.size(),
                  tag.data(), tag.size(), &len) == nullptr || len != tag.size())
        throw std::runtime_error("HMAC-SHA-256 failed");
    return tag;
}

Nonce chunkNonce(const uint64_t index) {
    Nonce nonce{};
    format_detail::writeBe64(nonce.data() + 4, index);
    return nonce;
}

Aad chunkAad(const HeaderHash& hh, const uint64_t index, const bool final) {
    Aad aad{};
    std::ranges::copy(hh, aad.begin());
    format_detail::writeBe64(aad.data() + kHashSize, index);
    aad[kHashSize + 8] = final ? 1 : 0;
    return aad;
}

uint64_t chunkSizeOf(const uint8_t chunkLog2) {
    if (chunkLog2 < kMinChunkLog2 || chunkLog2 > kMaxChunkLog2)
        throw std::invalid_argument("VHF1: chunk size out of range");
    return uint64_t{1} << chunkLog2;
}

uint64_t objectSizeFor(const uint64_t plaintextSize, const uint8_t chunkLog2) {
    const auto c = chunkSizeOf(chunkLog2);
    const uint64_t n = plaintextSize == 0 ? 1 : plaintextSize / c + (plaintextSize % c != 0 ? 1 : 0);
    constexpr auto kMax = std::numeric_limits<uint64_t>::max();
    // n ≤ 2^54 here, so 16·n can't overflow on its own.
    const uint64_t overhead = kHeaderSize + kTagSize * n;
    if (plaintextSize > kMax - overhead) throw std::overflow_error("VHF1: object size exceeds 64 bits");
    return plaintextSize + overhead;
}

Layout layoutFor(const uint64_t objectSize, const uint8_t chunkLog2) {
    const auto c = chunkSizeOf(chunkLog2);
    if (objectSize < kHeaderSize + kTagSize) throw Error(ErrorCode::BadSize);
    const uint64_t rest = objectSize - kHeaderSize;
    const uint64_t q = rest / (c + kTagSize);
    const uint64_t r = rest % (c + kTagSize);
    if (r == 0) return {q, q * c};
    if (r == kTagSize && q == 0) return {1, 0};
    if (r > kTagSize) return {q + 1, q * c + r - kTagSize};
    throw Error(ErrorCode::BadSize);
}

ByteSpan chunkSpan(const uint64_t index, const Layout& layout, const uint8_t chunkLog2) {
    if (index >= layout.chunkCount) throw std::out_of_range("VHF1: chunk index past the last chunk");
    const auto c = chunkSizeOf(chunkLog2);
    const uint64_t begin = kHeaderSize + index * (c + kTagSize);
    const uint64_t plain = index + 1 < layout.chunkCount ? c : layout.plaintextSize - index * c;
    return {begin, begin + plain + kTagSize};
}

SecureBytes::SecureBytes(const std::size_t capacity)
    : data_(capacity ? std::make_unique<uint8_t[]>(capacity) : nullptr), capacity_(capacity) {}

SecureBytes::~SecureBytes() { wipe(); }

SecureBytes::SecureBytes(SecureBytes&& other) noexcept
    : data_(std::move(other.data_)), capacity_(std::exchange(other.capacity_, 0)), size_(std::exchange(other.size_, 0)) {}

SecureBytes& SecureBytes::operator=(SecureBytes&& other) noexcept {
    if (this != &other) {
        wipe();
        data_ = std::move(other.data_);
        capacity_ = std::exchange(other.capacity_, 0);
        size_ = std::exchange(other.size_, 0);
    }
    return *this;
}

void SecureBytes::append(const std::span<const uint8_t> bytes) {
    if (bytes.size() > capacity_ - size_) throw std::length_error("SecureBytes: capacity exceeded");
    if (!bytes.empty()) std::memcpy(data_.get() + size_, bytes.data(), bytes.size());
    size_ += bytes.size();
}

void SecureBytes::resize(const std::size_t size) {
    if (size > capacity_) throw std::length_error("SecureBytes: capacity exceeded");
    if (size > size_) std::memset(data_.get() + size_, 0, size - size_);
    else if (size < size_) sodium_memzero(data_.get() + size, size_ - size);
    size_ = size;
}

void SecureBytes::clear() {
    if (data_) sodium_memzero(data_.get(), size_);
    size_ = 0;
}

void SecureBytes::wipe() noexcept {
    if (data_) sodium_memzero(data_.get(), capacity_);
    size_ = 0;
}

OpenedHeader::OpenedHeader(const HeaderParams& params, const HeaderHash& hash, SecretKeyPtr contentKey)
    : params_(params), hash_(hash), contentKey_(std::move(contentKey)) {}

OpenedHeader openHeader(const std::span<const uint8_t> object, const Expectation& expect, const KeyLookup& keys) {
    using namespace format_detail;
    // 1. Structure.
    if (object.size() < kHeaderSize || !std::equal(kMagic.begin(), kMagic.end(), object.begin()))
        throw Error(ErrorCode::BadMagic);
    const uint8_t* h = object.data();
    if (readBe16(h + kOffVersion) != kFormatVersion) throw Error(ErrorCode::UnsupportedVersion);
    if (readBe16(h + kOffHeaderLen) != kHeaderSize) throw Error(ErrorCode::BadHeaderLength);
    if (readBe16(h + kOffSuite) != kSuiteAes256GcmHkdfSha256) throw Error(ErrorCode::UnsupportedSuite);
    const uint8_t chunkLog2 = h[kOffChunkLog2];
    if (chunkLog2 < kMinChunkLog2 || chunkLog2 > kMaxChunkLog2) throw Error(ErrorCode::BadChunkSize);
    if (readBe32(h + kOffReserved) != 0) throw Error(ErrorCode::ReservedNonzero);

    // 2. The caller's expectations.
    if (h[kOffKind] != static_cast<uint8_t>(expect.kind)) throw Error(ErrorCode::KindMismatch);
    if (!equalCt(h + kOffVaultUid, expect.vaultUid.data(), kUidSize)) throw Error(ErrorCode::VaultMismatch);
    if (!expect.objectUid && !expect.generation)
        throw std::invalid_argument("A VHF1 expectation names the object's uid, its generation or both");
    if (expect.objectUid && !equalCt(h + kOffObjectUid, expect.objectUid->data(), kUidSize))
        throw Error(ErrorCode::ObjectMismatch);
    if (expect.generation && !equalCt(h + kOffSalt, expect.generation->data(), kSaltSize))
        throw Error(ErrorCode::GenerationMismatch);
    const uint32_t keyVersion = readBe32(h + kOffKeyVersion);
    const SecretKeyPtr vaultKey = keyVersion == 0 || !keys ? nullptr : keys(keyVersion);
    if (!vaultKey) throw Error(ErrorCode::KeyUnavailable);

    // 3. The header tag.
    HeaderParams params;
    params.kind = expect.kind;
    params.keyVersion = keyVersion;
    params.chunkLog2 = chunkLog2;
    std::copy_n(h + kOffVaultUid, kUidSize, params.vaultUid.begin());
    std::copy_n(h + kOffObjectUid, kUidSize, params.objectUid.begin());
    std::copy_n(h + kOffSalt, kSaltSize, params.salt.begin());

    const std::span<const uint8_t, kHeaderBodySize> body(h, kHeaderBodySize);
    const auto hh = headerHash(body);
    auto ks = deriveKeys(*vaultKey, params.salt, hh);
    const auto tag = headerTag(*ks.headerKey, body);
    if (!equalCt(tag.data(), h + kHeaderBodySize, kHeaderTagSize)) throw Error(ErrorCode::HeaderAuthFailed);
    return {params, hh, std::move(ks.contentKey)};
}

void sealChunk(const SecretKey& contentKey, const HeaderHash& hh, const uint64_t index, const bool final,
               const std::span<const uint8_t> plaintext, const std::span<uint8_t> out) {
    if (out.size() != plaintext.size() + kTagSize) throw std::invalid_argument("VHF1: sealed chunk buffer size");
    const auto nonce = chunkNonce(index);
    const auto aad = chunkAad(hh, index, final);
    util::GcmStreamEncryptor enc(format_detail::gcmKeyOf(contentKey), util::GcmIv(nonce.data(), kNonceSize), aad);
    enc.update(plaintext, out.first(plaintext.size()));
    const auto tag = enc.finish();
    std::ranges::copy(tag, out.begin() + static_cast<std::ptrdiff_t>(plaintext.size()));
}

bool openChunk(const OpenedHeader& header, const uint64_t index, const bool final,
               const std::span<const uint8_t> sealed, const std::span<uint8_t> out) {
    if (sealed.size() < kTagSize || out.size() != sealed.size() - kTagSize)
        throw std::invalid_argument("VHF1: chunk buffer size");
    const auto bodySize = sealed.size() - kTagSize;
    const auto nonce = chunkNonce(index);
    const auto aad = chunkAad(header.hash(), index, final);
    return util::gcmDecrypt(format_detail::gcmKeyOf(header.contentKey()), util::GcmIv(nonce.data(), kNonceSize),
                            sealed.first(bodySize), std::span<const uint8_t, kTagSize>(sealed.data() + bodySize, kTagSize),
                            out, aad);
}

}
