#include "crypto/recovery/Kev1.hpp"

#include "crypto/id/ObjectUid.hpp"
#include "crypto/util/uuid.hpp"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <optional>
#include <utility>

namespace vh::crypto::kev1 {

namespace kev1_detail {

constexpr std::array<std::pair<ErrorCode, std::string_view>, 12> kErrorNames{{
    {ErrorCode::BadMagic, "bad_magic"},
    {ErrorCode::UnsupportedVersion, "unsupported_version"},
    {ErrorCode::UnsupportedSuite, "unsupported_suite"},
    {ErrorCode::BadPurpose, "bad_purpose"},
    {ErrorCode::UnsupportedRecipientClass, "unsupported_recipient_class"},
    {ErrorCode::ReservedNonzero, "reserved_nonzero"},
    {ErrorCode::VaultMismatch, "vault_mismatch"},
    {ErrorCode::RecipientMismatch, "recipient_mismatch"},
    {ErrorCode::BadLength, "bad_length"},
    {ErrorCode::BadEphemeral, "bad_ephemeral"},
    {ErrorCode::WrapAuthFailed, "wrap_auth_failed"},
    {ErrorCode::BadKeyVersion, "bad_key_version"},
}};

constexpr std::string_view kInfo = "vh.kev1.wrap";
constexpr std::size_t kOffVersion = 8, kOffSuite = 10, kOffPurpose = 12, kOffClass = 13, kOffReserved = 14,
                      kOffKeyVersion = 16, kOffVaultUid = 20, kOffRecipient = 36, kOffEpkLen = 68;
constexpr std::size_t kGcmTag = 16;

struct PkeyDeleter {
    void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); }
};
struct PkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); }
};
struct CipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* p) const noexcept { EVP_CIPHER_CTX_free(p); }
};
struct KdfDeleter {
    void operator()(EVP_KDF* p) const noexcept { EVP_KDF_free(p); }
};
struct KdfCtxDeleter {
    void operator()(EVP_KDF_CTX* p) const noexcept { EVP_KDF_CTX_free(p); }
};
struct BnDeleter {
    void operator()(BIGNUM* p) const noexcept { BN_clear_free(p); }
};
struct GroupDeleter {
    void operator()(EC_GROUP* p) const noexcept { EC_GROUP_free(p); }
};
struct PointDeleter {
    void operator()(EC_POINT* p) const noexcept { EC_POINT_free(p); }
};
struct ParamBldDeleter {
    void operator()(OSSL_PARAM_BLD* p) const noexcept { OSSL_PARAM_BLD_free(p); }
};
struct ParamDeleter {
    void operator()(OSSL_PARAM* p) const noexcept { OSSL_PARAM_free(p); }
};

using Pkey = std::unique_ptr<EVP_PKEY, PkeyDeleter>;

uint16_t be16(const uint8_t* p) { return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]); }
uint32_t be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}
void putBe16(std::vector<uint8_t>& out, const uint16_t v) {
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v));
}
void putBe32(std::vector<uint8_t>& out, const uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(v >> (24 - 8 * i)));
}

std::size_t epkSize(const Suite suite) { return suite == Suite::X25519 ? kX25519KeySize : kP256PointSize; }

bool knownSuite(const uint16_t suite) {
    return suite == static_cast<uint16_t>(Suite::X25519) || suite == static_cast<uint16_t>(Suite::P256);
}

// The P-256 point of a scalar (uncompressed SEC1, 65 bytes). Throws std::invalid_argument for a scalar out of range.
std::vector<uint8_t> p256Point(const std::span<const uint8_t> scalar) {
    if (scalar.size() != kP256ScalarSize) throw std::invalid_argument("a P-256 secret key is a 32-byte scalar");
    const std::unique_ptr<EC_GROUP, GroupDeleter> group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    const std::unique_ptr<BIGNUM, BnDeleter> k(BN_bin2bn(scalar.data(), static_cast<int>(scalar.size()), nullptr));
    if (!group || !k) throw std::runtime_error("OpenSSL P-256 setup failed");
    if (BN_is_zero(k.get()) || BN_cmp(k.get(), EC_GROUP_get0_order(group.get())) >= 0)
        throw std::invalid_argument("the P-256 secret key is out of range");
    const std::unique_ptr<EC_POINT, PointDeleter> point(EC_POINT_new(group.get()));
    if (!point || EC_POINT_mul(group.get(), point.get(), k.get(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("P-256 point multiplication failed");
    std::vector<uint8_t> out(kP256PointSize);
    if (EC_POINT_point2oct(group.get(), point.get(), POINT_CONVERSION_UNCOMPRESSED, out.data(), out.size(), nullptr) !=
        kP256PointSize)
        throw std::runtime_error("P-256 point encoding failed");
    return out;
}

// An EVP key from raw parts: X25519 (32-byte secret or public key) or P-256 (scalar and/or uncompressed point).
// nullptr when OpenSSL refuses the bytes (not a point on the curve, wrong size).
Pkey x25519Key(const std::span<const uint8_t> bytes, const bool secret) {
    if (bytes.size() != kX25519KeySize) return nullptr;
    return Pkey(secret ? EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, bytes.data(), bytes.size())
                       : EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, bytes.data(), bytes.size()));
}

Pkey p256Key(const std::span<const uint8_t> scalar, const std::span<const uint8_t> point) {
    if (point.size() != kP256PointSize || point[0] != 0x04) return nullptr;
    {
        // EVP_PKEY_fromdata doesn't check that the point is on the curve; this does.
        const std::unique_ptr<EC_GROUP, GroupDeleter> group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
        const std::unique_ptr<EC_POINT, PointDeleter> p(group ? EC_POINT_new(group.get()) : nullptr);
        if (!p || EC_POINT_oct2point(group.get(), p.get(), point.data(), point.size(), nullptr) != 1 ||
            EC_POINT_is_on_curve(group.get(), p.get(), nullptr) != 1)
            return nullptr;
    }
    const std::unique_ptr<OSSL_PARAM_BLD, ParamBldDeleter> bld(OSSL_PARAM_BLD_new());
    if (!bld) return nullptr;
    std::unique_ptr<BIGNUM, BnDeleter> k;
    if (OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) != 1 ||
        OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, point.data(), point.size()) != 1)
        return nullptr;
    if (!scalar.empty()) {
        k.reset(BN_bin2bn(scalar.data(), static_cast<int>(scalar.size()), nullptr));
        if (!k || OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_PRIV_KEY, k.get()) != 1) return nullptr;
    }
    const std::unique_ptr<OSSL_PARAM, ParamDeleter> params(OSSL_PARAM_BLD_to_param(bld.get()));
    const std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter> ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!params || !ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1) return nullptr;
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_fromdata(ctx.get(), &raw, scalar.empty() ? EVP_PKEY_PUBLIC_KEY : EVP_PKEY_KEYPAIR, params.get()) != 1)
        return nullptr;
    return Pkey(raw);
}

Pkey secretKey(const Suite suite, const std::span<const uint8_t> sk) {
    if (suite == Suite::X25519) return x25519Key(sk, true);
    return p256Key(sk, p256Point(sk));
}

Pkey publicKey(const Suite suite, const std::span<const uint8_t> pk) {
    return suite == Suite::X25519 ? x25519Key(pk, false) : p256Key({}, pk);
}

// Z: the X25519 output or the P-256 x-coordinate. Error(BadEphemeral) for a peer OpenSSL refuses or an all-zero Z.
std::vector<uint8_t> agree(EVP_PKEY* mine, EVP_PKEY* peer) {
    if (!mine || !peer) throw Error(ErrorCode::BadEphemeral);
    const std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter> ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, mine, nullptr));
    std::size_t len = 0;
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) != 1 || EVP_PKEY_derive_set_peer(ctx.get(), peer) != 1 ||
        EVP_PKEY_derive(ctx.get(), nullptr, &len) != 1)
        throw Error(ErrorCode::BadEphemeral);
    std::vector<uint8_t> z(len);
    if (EVP_PKEY_derive(ctx.get(), z.data(), &len) != 1) {
        sodium_memzero(z.data(), z.size());
        throw Error(ErrorCode::BadEphemeral);
    }
    z.resize(len);
    if (sodium_is_zero(z.data(), z.size())) throw Error(ErrorCode::BadEphemeral);
    return z;
}

// K_wrap = HKDF-SHA-256(salt = epk ‖ rpk, IKM = Z, info = "vh.kev1.wrap" ‖ prefix), 32 bytes.
std::array<uint8_t, 32> wrapKey(const std::span<const uint8_t> z, const std::span<const uint8_t> epk,
                                const std::span<const uint8_t> rpk, const std::span<const uint8_t> prefix) {
    std::vector<uint8_t> salt(epk.begin(), epk.end());
    salt.insert(salt.end(), rpk.begin(), rpk.end());
    std::vector<uint8_t> info(kInfo.begin(), kInfo.end());
    info.insert(info.end(), prefix.begin(), prefix.end());

    const std::unique_ptr<EVP_KDF, KdfDeleter> kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    if (!kdf) throw std::runtime_error("OpenSSL HKDF is unavailable");
    const std::unique_ptr<EVP_KDF_CTX, KdfCtxDeleter> ctx(EVP_KDF_CTX_new(kdf.get()));
    if (!ctx) throw std::runtime_error("Failed to allocate an OpenSSL HKDF context");
    char digest[] = "SHA256";
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;
    std::array<OSSL_PARAM, 6> params{
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<uint8_t*>(z.data()), z.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt.data(), salt.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info.data(), info.size()),
        OSSL_PARAM_construct_end()};
    std::array<uint8_t, 32> out{};
    if (EVP_KDF_derive(ctx.get(), out.data(), out.size(), params.data()) != 1)
        throw std::runtime_error("HKDF-SHA-256 derivation failed");
    return out;
}

// AES-256-GCM with the zero nonce (K_wrap is single-use). Returns ciphertext ‖ tag.
std::vector<uint8_t> seal(const std::array<uint8_t, 32>& key, const std::span<const uint8_t> plaintext,
                          const std::span<const uint8_t> aad) {
    const std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter> ctx(EVP_CIPHER_CTX_new());
    const std::array<uint8_t, 12> nonce{};
    std::vector<uint8_t> out(plaintext.size() + kGcmTag);
    int len = 0;
    if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, key.data(), nonce.data()) != 1 ||
        EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) != 1 ||
        EVP_EncryptUpdate(ctx.get(), out.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) != 1 ||
        EVP_EncryptFinal_ex(ctx.get(), out.data() + len, &len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(kGcmTag),
                            out.data() + plaintext.size()) != 1)
        throw std::runtime_error("AES-256-GCM key wrap failed");
    return out;
}

// Returns the 32-byte plaintext, or nullopt when the tag doesn't authenticate.
std::optional<std::array<uint8_t, 32>> open(const std::array<uint8_t, 32>& key, const std::span<const uint8_t> sealed,
                                            const std::span<const uint8_t> aad) {
    if (sealed.size() != kWrappedSize) return std::nullopt;
    const std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter> ctx(EVP_CIPHER_CTX_new());
    const std::array<uint8_t, 12> nonce{};
    std::array<uint8_t, 32> out{};
    std::array<uint8_t, kGcmTag> tag{};
    std::ranges::copy(sealed.subspan(32), tag.begin());
    int len = 0;
    const bool ok = ctx && EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, key.data(), nonce.data()) == 1 &&
                    EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), static_cast<int>(aad.size())) == 1 &&
                    EVP_DecryptUpdate(ctx.get(), out.data(), &len, sealed.data(), 32) == 1 &&
                    EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(kGcmTag), tag.data()) == 1 &&
                    EVP_DecryptFinal_ex(ctx.get(), out.data() + len, &len) == 1;
    if (!ok) {
        sodium_memzero(out.data(), out.size());
        return std::nullopt;
    }
    return out;
}

Digest sha256(const std::span<const uint8_t> bytes) {
    Digest d{};
    crypto_hash_sha256(d.data(), bytes.data(), bytes.size());
    return d;
}

// Structural checks shared by inspect() and unwrap(), in the reader's order up to reserved_nonzero.
void checkPrefix(const std::span<const uint8_t> env) {
    if (env.size() < kFixedPrefixSize || !std::equal(kMagic.begin(), kMagic.end(), env.begin()))
        throw Error(ErrorCode::BadMagic);
    if (be16(env.data() + kOffVersion) != kVersion) throw Error(ErrorCode::UnsupportedVersion);
}

}

std::string_view errorCodeName(const ErrorCode code) {
    for (const auto& [c, name] : kev1_detail::kErrorNames)
        if (c == code) return name;
    return "unknown";
}

Error::Error(const ErrorCode code)
    : std::runtime_error("KEV1 envelope rejected: " + std::string(errorCodeName(code))), code_(code) {}

bool skippedByRestore(const ErrorCode code) noexcept {
    return code == ErrorCode::BadPurpose || code == ErrorCode::UnsupportedRecipientClass ||
           code == ErrorCode::RecipientMismatch;
}

Digest recipientId(const std::span<const uint8_t> publicKey) { return kev1_detail::sha256(publicKey); }

std::vector<uint8_t> publicKeyOf(const Suite suite, const std::span<const uint8_t> secretKey) {
    if (suite == Suite::P256) return kev1_detail::p256Point(secretKey);
    if (secretKey.size() != kX25519KeySize) throw std::invalid_argument("an X25519 secret key is 32 bytes");
    std::vector<uint8_t> out(kX25519KeySize);
    if (crypto_scalarmult_base(out.data(), secretKey.data()) != 0)
        throw std::runtime_error("X25519 public key derivation failed");
    return out;
}

std::vector<uint8_t> wrap(const SecretKey& vaultKey, const Suite suite, const uint32_t keyVersion,
                          const VaultUid& vaultUid, const std::span<const uint8_t> recipientPublicKey,
                          const std::span<const uint8_t> ephemeralSecretForTesting) {
    using namespace kev1_detail;
    if (keyVersion == 0) throw std::invalid_argument("KEV1 key versions start at 1");
    util::ensure_sodium_init();
    const auto peer = publicKey(suite, recipientPublicKey);
    if (!peer) throw std::invalid_argument("the recipient public key is not a valid key for its suite");

    std::vector<uint8_t> esk;
    if (!ephemeralSecretForTesting.empty()) {
        esk.assign(ephemeralSecretForTesting.begin(), ephemeralSecretForTesting.end());
    } else {
        esk.resize(suite == Suite::X25519 ? kX25519KeySize : kP256ScalarSize);
        // A P-256 scalar must be below the group order; retrying a rejected draw keeps it uniform.
        for (int attempt = 0;; ++attempt) {
            randombytes_buf(esk.data(), esk.size());
            if (suite == Suite::X25519) break;
            try {
                (void)p256Point(esk);
                break;
            } catch (const std::invalid_argument&) {
                if (attempt > 16) throw;
            }
        }
    }
    struct Wipe {
        std::vector<uint8_t>& v;
        ~Wipe() { sodium_memzero(v.data(), v.size()); }
    } wipeEsk{esk};

    const auto mine = secretKey(suite, esk);
    if (!mine) throw std::invalid_argument("the ephemeral secret key is not valid for its suite");
    const auto epk = publicKeyOf(suite, esk);
    auto z = agree(mine.get(), peer.get());
    Wipe wipeZ{z};

    std::vector<uint8_t> env(kMagic.begin(), kMagic.end());
    putBe16(env, kVersion);
    putBe16(env, static_cast<uint16_t>(suite));
    env.push_back(kPurposeVaultKey);
    env.push_back(kClassCustomer);
    putBe16(env, 0);
    putBe32(env, keyVersion);
    env.insert(env.end(), vaultUid.begin(), vaultUid.end());
    const auto rid = recipientId(recipientPublicKey);
    env.insert(env.end(), rid.begin(), rid.end());
    putBe16(env, static_cast<uint16_t>(epk.size()));
    env.insert(env.end(), epk.begin(), epk.end());

    auto kWrap = wrapKey(z, epk, recipientPublicKey, env);
    const auto wrapped = seal(kWrap, vaultKey.bytes(), env);
    sodium_memzero(kWrap.data(), kWrap.size());
    env.insert(env.end(), wrapped.begin(), wrapped.end());
    return env;
}

Header inspect(const std::span<const uint8_t> env) {
    using namespace kev1_detail;
    checkPrefix(env);
    Header h;
    h.suite = be16(env.data() + kOffSuite);
    if (!knownSuite(h.suite)) throw Error(ErrorCode::UnsupportedSuite);
    h.purpose = env[kOffPurpose];
    if (h.purpose != kPurposeVaultKey) throw Error(ErrorCode::BadPurpose);
    h.recipient_class = env[kOffClass];
    if (h.recipient_class != kClassCustomer) throw Error(ErrorCode::UnsupportedRecipientClass);
    if (env[kOffReserved] != 0 || env[kOffReserved + 1] != 0) throw Error(ErrorCode::ReservedNonzero);
    h.key_version = be32(env.data() + kOffKeyVersion);
    std::copy_n(env.begin() + kOffVaultUid, h.vault_uid.size(), h.vault_uid.begin());
    std::copy_n(env.begin() + kOffRecipient, h.recipient_id.size(), h.recipient_id.begin());
    const auto epkLen = be16(env.data() + kOffEpkLen);
    if (epkLen != epkSize(static_cast<Suite>(h.suite)) || env.size() != kFixedPrefixSize + epkLen + kWrappedSize)
        throw Error(ErrorCode::BadLength);
    return h;
}

Unwrapped unwrap(const std::span<const uint8_t> env, const std::span<const uint8_t> recipientSecretKey,
                 const Suite expectedSuite, const VaultUid& vaultUid) {
    using namespace kev1_detail;
    checkPrefix(env);
    const auto suite = be16(env.data() + kOffSuite);
    if (suite != static_cast<uint16_t>(expectedSuite) || !knownSuite(suite)) throw Error(ErrorCode::UnsupportedSuite);
    if (env[kOffPurpose] != kPurposeVaultKey) throw Error(ErrorCode::BadPurpose);
    if (env[kOffClass] != kClassCustomer) throw Error(ErrorCode::UnsupportedRecipientClass);
    if (env[kOffReserved] != 0 || env[kOffReserved + 1] != 0) throw Error(ErrorCode::ReservedNonzero);
    const auto keyVersion = be32(env.data() + kOffKeyVersion);
    if (sodium_memcmp(env.data() + kOffVaultUid, vaultUid.data(), vaultUid.size()) != 0)
        throw Error(ErrorCode::VaultMismatch);

    std::vector<uint8_t> rpk;
    try {
        rpk = publicKeyOf(expectedSuite, recipientSecretKey);
    } catch (const std::invalid_argument&) {
        throw Error(ErrorCode::RecipientMismatch);  // not a key of this suite: it can't be the recipient
    }
    const auto rid = recipientId(rpk);
    if (sodium_memcmp(env.data() + kOffRecipient, rid.data(), rid.size()) != 0)
        throw Error(ErrorCode::RecipientMismatch);

    const auto epkLen = be16(env.data() + kOffEpkLen);
    if (epkLen != epkSize(expectedSuite) || env.size() != kFixedPrefixSize + epkLen + kWrappedSize)
        throw Error(ErrorCode::BadLength);
    const auto prefix = env.first(kFixedPrefixSize + epkLen);
    const auto epk = env.subspan(kFixedPrefixSize, epkLen);

    const auto mine = secretKey(expectedSuite, recipientSecretKey);
    const auto peer = publicKey(expectedSuite, epk);
    if (!peer) throw Error(ErrorCode::BadEphemeral);
    auto z = agree(mine.get(), peer.get());
    auto kWrap = wrapKey(z, epk, rpk, prefix);
    sodium_memzero(z.data(), z.size());
    auto key = open(kWrap, env.subspan(kFixedPrefixSize + epkLen), prefix);
    sodium_memzero(kWrap.data(), kWrap.size());
    if (!key) throw Error(ErrorCode::WrapAuthFailed);
    auto secret = std::make_shared<const SecretKey>(*key);
    sodium_memzero(key->data(), key->size());
    if (keyVersion == 0) throw Error(ErrorCode::BadKeyVersion);
    return {keyVersion, std::move(secret)};
}

std::string kid(const std::span<const uint8_t> envelope) {
    const auto digest = kev1_detail::sha256(envelope);
    id::ObjectUid head{};
    std::copy_n(digest.begin(), head.size(), head.begin());
    return id::toBase32(head);
}

std::string objectKey(const std::string_view kid) { return std::string(kObjectPrefix) + std::string(kid); }

}
