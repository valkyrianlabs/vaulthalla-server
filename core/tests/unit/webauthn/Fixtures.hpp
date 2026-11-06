#pragma once

// Test-only authenticator for the WebAuthn verifier tests (#355): fresh OpenSSL / libsodium keys, a minimal CBOR writer
// (able to write the malformed encodings the strict parser must refuse), and builders for clientDataJSON,
// authenticatorData and attestation objects. Signing happens only here, in tests; the verifier only verifies.

#include "auth/webauthn/Base64Url.hpp"
#include "auth/webauthn/Types.hpp"

#include <nlohmann/json.hpp>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <sodium.h>

#include <array>
#include <cstdint>
#include <deque>
#include <memory>
#include <optional>
#include <ostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace vh::auth::webauthn {
// Readable gtest messages: refusals print their name.
inline void PrintTo(const Failure f, std::ostream* os) { *os << toString(f); }
inline void PrintTo(const AttestationType t, std::ostream* os) { *os << toString(t); }
inline void PrintTo(const Algorithm a, std::ostream* os) { *os << toString(a); }
}

namespace vh::test_webauthn {

namespace wa = vh::auth::webauthn;
using wa::Bytes;
using wa::ByteView;

inline Bytes hex(const std::string_view h) {
    if (h.size() % 2) throw std::invalid_argument("odd hex");
    Bytes out(h.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = static_cast<std::uint8_t>(std::stoul(std::string(h.substr(2 * i, 2)), nullptr, 16));
    return out;
}

inline Bytes bytesOf(const std::string_view s) { return {s.begin(), s.end()}; }

inline Bytes concat(std::initializer_list<ByteView> parts) {
    Bytes out;
    for (const auto p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

inline Bytes sha256(const ByteView data) {
    Bytes out(crypto_hash_sha256_BYTES);
    crypto_hash_sha256(out.data(), data.data(), data.size());
    return out;
}

// A minimal CBOR writer. Integers and lengths use the shortest form unless written raw.
class CborWriter {
public:
    Bytes out;

    CborWriter& head(const std::uint8_t major, const std::uint64_t v) {
        const auto m = static_cast<std::uint8_t>(major << 5);
        if (v < 24) out.push_back(static_cast<std::uint8_t>(m | v));
        else if (v <= 0xFF) { out.push_back(m | 24); out.push_back(static_cast<std::uint8_t>(v)); }
        else if (v <= 0xFFFF) { out.push_back(m | 25); push(v, 2); }
        else if (v <= 0xFFFFFFFF) { out.push_back(m | 26); push(v, 4); }
        else { out.push_back(m | 27); push(v, 8); }
        return *this;
    }
    CborWriter& integer(const std::int64_t v) {
        return v >= 0 ? head(0, static_cast<std::uint64_t>(v)) : head(1, static_cast<std::uint64_t>(-1 - v));
    }
    CborWriter& bytes(const ByteView b) {
        head(2, b.size());
        out.insert(out.end(), b.begin(), b.end());
        return *this;
    }
    CborWriter& text(const std::string_view s) {
        head(3, s.size());
        out.insert(out.end(), s.begin(), s.end());
        return *this;
    }
    CborWriter& array(const std::uint64_t n) { return head(4, n); }
    CborWriter& map(const std::uint64_t n) { return head(5, n); }
    CborWriter& raw(const ByteView b) {
        out.insert(out.end(), b.begin(), b.end());
        return *this;
    }
    CborWriter& byte(const std::uint8_t b) {
        out.push_back(b);
        return *this;
    }

private:
    void push(const std::uint64_t v, const int n) {
        for (int i = n - 1; i >= 0; --i) out.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    }
};

struct PkeyFree {
    void operator()(EVP_PKEY* k) const { EVP_PKEY_free(k); }
};

inline Bytes bnParam(EVP_PKEY* key, const char* name, const int pad = 0) {
    BIGNUM* bn = nullptr;
    if (EVP_PKEY_get_bn_param(key, name, &bn) != 1) throw std::runtime_error("bn param");
    Bytes out(pad ? static_cast<std::size_t>(pad) : static_cast<std::size_t>(BN_num_bytes(bn)));
    if (pad) BN_bn2binpad(bn, out.data(), pad);
    else BN_bn2bin(bn, out.data());
    BN_free(bn);
    return out;
}

// A credential key pair of one of the three algorithms.
class TestKey {
public:
    explicit TestKey(const wa::Algorithm alg, const int rsaBits = 2048) : alg_(alg) {
        if (sodium_init() < 0) throw std::runtime_error("sodium");
        switch (alg) {
            case wa::Algorithm::ES256:
                pkey_.reset(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256"));
                x = bnParam(pkey_.get(), OSSL_PKEY_PARAM_EC_PUB_X, 32);
                y = bnParam(pkey_.get(), OSSL_PKEY_PARAM_EC_PUB_Y, 32);
                break;
            case wa::Algorithm::RS256:
                pkey_.reset(EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", static_cast<std::size_t>(rsaBits)));
                n = bnParam(pkey_.get(), OSSL_PKEY_PARAM_RSA_N);
                e = bnParam(pkey_.get(), OSSL_PKEY_PARAM_RSA_E);
                break;
            case wa::Algorithm::EdDSA:
                x.resize(crypto_sign_PUBLICKEYBYTES);
                crypto_sign_keypair(x.data(), edSecret_.data());
                break;
        }
        if (alg != wa::Algorithm::EdDSA && !pkey_) throw std::runtime_error("keygen");
    }

    [[nodiscard]] wa::Algorithm algorithm() const { return alg_; }

    // The COSE_Key, written the way authenticators do.
    [[nodiscard]] Bytes cose() const {
        CborWriter w;
        switch (alg_) {
            case wa::Algorithm::ES256:
                w.map(5).integer(1).integer(2).integer(3).integer(-7).integer(-1).integer(1)
                    .integer(-2).bytes(x).integer(-3).bytes(y);
                break;
            case wa::Algorithm::EdDSA:
                w.map(4).integer(1).integer(1).integer(3).integer(-8).integer(-1).integer(6).integer(-2).bytes(x);
                break;
            case wa::Algorithm::RS256:
                w.map(4).integer(1).integer(3).integer(3).integer(-257).integer(-1).bytes(n).integer(-2).bytes(e);
                break;
        }
        return w.out;
    }

    [[nodiscard]] Bytes sign(const ByteView message) const {
        if (alg_ == wa::Algorithm::EdDSA) {
            Bytes sig(crypto_sign_BYTES);
            crypto_sign_detached(sig.data(), nullptr, message.data(), message.size(), edSecret_.data());
            return sig;
        }
        const std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
        if (EVP_DigestSignInit_ex(md.get(), nullptr, "SHA256", nullptr, nullptr, pkey_.get(), nullptr) != 1)
            throw std::runtime_error("sign init");
        std::size_t len = 0;
        if (EVP_DigestSign(md.get(), nullptr, &len, message.data(), message.size()) != 1) throw std::runtime_error("sign");
        Bytes sig(len);
        if (EVP_DigestSign(md.get(), sig.data(), &len, message.data(), message.size()) != 1) throw std::runtime_error("sign");
        sig.resize(len);
        return sig;
    }

    Bytes x, y, n, e;

private:
    wa::Algorithm alg_;
    std::unique_ptr<EVP_PKEY, PkeyFree> pkey_;
    std::array<std::uint8_t, crypto_sign_SECRETKEYBYTES> edSecret_{};
};

inline constexpr std::string_view kRpId = "vault.example.test";
inline constexpr std::string_view kOrigin = "https://vault.example.test";

inline wa::RelyingParty relyingParty() { return {std::string(kRpId), {std::string(kOrigin)}, {}}; }

inline std::string clientDataJSON(const std::string_view type, const ByteView challenge,
                                  const std::string_view origin = kOrigin, const std::string_view extra = "") {
    std::string out = R"({"type":")" + std::string(type) + R"(","challenge":")" + wa::base64urlEncode(challenge) +
                      R"(","origin":")" + std::string(origin) + R"(")";
    if (extra.empty()) out += R"(,"crossOrigin":false)";
    else out += extra;
    return out + "}";
}

namespace flags {
inline constexpr std::uint8_t UP = 0x01, UV = 0x04, BE = 0x08, BS = 0x10, AT = 0x40, ED = 0x80;
}

struct Attested {
    std::array<std::uint8_t, 16> aaguid{};
    Bytes credentialId;
    Bytes cose;
};

inline Bytes authenticatorData(const std::uint8_t flagByte, const std::uint32_t signCount,
                               const std::optional<Attested>& attested = std::nullopt,
                               const std::string_view rpId = kRpId, const ByteView extensions = {}) {
    Bytes out = sha256(wa::view(rpId));
    out.push_back(flagByte);
    for (int i = 3; i >= 0; --i) out.push_back(static_cast<std::uint8_t>(signCount >> (8 * i)));
    if (attested) {
        out.insert(out.end(), attested->aaguid.begin(), attested->aaguid.end());
        out.push_back(static_cast<std::uint8_t>(attested->credentialId.size() >> 8));
        out.push_back(static_cast<std::uint8_t>(attested->credentialId.size() & 0xFF));
        out.insert(out.end(), attested->credentialId.begin(), attested->credentialId.end());
        out.insert(out.end(), attested->cose.begin(), attested->cose.end());
    }
    out.insert(out.end(), extensions.begin(), extensions.end());
    return out;
}

inline Bytes attestationNone(const ByteView authData) {
    CborWriter w;
    w.map(3).text("fmt").text("none").text("attStmt").map(0).text("authData").bytes(authData);
    return w.out;
}

inline Bytes attestationPackedSelf(const ByteView authData, const TestKey& key, const ByteView clientDataHash,
                                   const std::optional<std::int64_t> alg = std::nullopt) {
    const auto sig = key.sign(concat({authData, clientDataHash}));
    CborWriter w;
    w.map(3).text("fmt").text("packed").text("attStmt").map(2)
        .text("alg").integer(alg.value_or(static_cast<std::int64_t>(key.algorithm()))).text("sig").bytes(sig)
        .text("authData").bytes(authData);
    return w.out;
}

inline Bytes randomBytes(const std::size_t n) {
    Bytes out(n);
    randombytes_buf(out.data(), n);
    return out;
}

class MemoryCredentials final : public wa::CredentialLookup {
public:
    std::deque<wa::StoredCredential> rows;  // stable references across store()

    [[nodiscard]] std::optional<wa::StoredCredential> find(const ByteView id) const override {
        for (const auto& r : rows)
            if (r.id.size() == id.size() && std::equal(r.id.begin(), r.id.end(), id.begin())) return r;
        return std::nullopt;
    }

    wa::StoredCredential& store(const wa::NewCredential& c, const std::int64_t user, Bytes handle) {
        wa::StoredCredential s;
        s.id = c.id;
        s.userId = user;
        s.userHandle = std::move(handle);
        s.publicKeyCose = c.publicKeyCose;
        s.rpId = c.rpId;
        s.signCount = c.signCount;
        s.backupEligible = c.backupEligible;
        s.backupState = c.backupState;
        rows.push_back(std::move(s));
        return rows.back();
    }
};

// A software authenticator for the DB-backed MFA tests (ES256, none attestation).
struct Authenticator {
    TestKey key{wa::Algorithm::ES256};
    Bytes credentialId = randomBytes(32);
    std::uint32_t signCount = 0;
};

// navigator.credentials.get()'s answer to `publicKey` (the server's request options), as the ws client sends it.
inline nlohmann::json assertionJson(Authenticator& a, const nlohmann::json& publicKey,
                                    const std::uint8_t flagByte = flags::UP | flags::UV) {
    const auto cd = bytesOf(clientDataJSON("webauthn.get", *wa::base64urlDecode(publicKey.at("challenge").get<std::string>())));
    const auto ad = authenticatorData(flagByte, ++a.signCount);
    const auto sig = a.key.sign(concat({ad, sha256(cd)}));
    const auto id = wa::base64urlEncode(a.credentialId);
    return {{"id", id}, {"rawId", id}, {"type", "public-key"},
            {"response", {{"clientDataJSON", wa::base64urlEncode(cd)}, {"authenticatorData", wa::base64urlEncode(ad)},
                          {"signature", wa::base64urlEncode(sig)}}}};
}

}
