#include "auth/webauthn/Cose.hpp"

#include "auth/webauthn/Cbor.hpp"
#include "auth/webauthn/OpenSsl.hpp"

#include <sodium.h>

#include <algorithm>
#include <bit>
#include <initializer_list>

namespace vh::auth::webauthn::cose {

namespace {

// COSE key labels (RFC 9052 section 7, RFC 9053 section 7).
constexpr std::int64_t kLabelKty = 1, kLabelKid = 2, kLabelAlg = 3;
constexpr std::int64_t kLabelCrvOrN = -1, kLabelXOrE = -2, kLabelY = -3;
constexpr std::int64_t kKtyOkp = 1, kKtyEc2 = 2, kKtyRsa = 3;
constexpr std::int64_t kCrvP256 = 1, kCrvEd25519 = 6;

Parsed refuseKey(const Failure f) { return {std::nullopt, f}; }

bool coseOnlyLabels(const cbor_item_t* map, const std::initializer_list<std::int64_t> allowed) {
    for (std::size_t i = 0; i < cbor::size(map); ++i) {
        const auto label = cbor::asInt(cbor::mapKeyAt(map, i));
        if (!label || std::ranges::find(allowed, *label) == allowed.end()) return false;
    }
    return true;
}

std::optional<Bytes> coseBytesAt(const cbor_item_t* map, const std::int64_t label) {
    const auto b = cbor::asBytes(cbor::find(map, label));
    if (!b) return std::nullopt;
    return Bytes(b->begin(), b->end());
}

int coseBitLength(const Bytes& bigEndian) {
    if (bigEndian.empty() || bigEndian.front() == 0) return 0;
    return static_cast<int>(bigEndian.size() * 8) - std::countl_zero(bigEndian.front());
}

bool coseSodiumReady() {
    static const bool ready = sodium_init() >= 0;
    return ready;
}

}

Parsed parse(const ByteView encoded) {
    if (encoded.size() > kMaxKeyBytes) return refuseKey(Failure::CoseKeyMalformed);
    const auto root = cbor::decode(encoded);
    if (!root || !cbor::isMap(root.get())) return refuseKey(Failure::CoseKeyMalformed);
    const auto* map = root.get();

    const auto kty = cbor::asInt(cbor::find(map, kLabelKty));
    const auto alg = cbor::asInt(cbor::find(map, kLabelAlg));
    if (!kty || !alg) return refuseKey(Failure::CoseKeyMalformed);
    if (const auto* kid = cbor::find(map, kLabelKid); kid && !cbor::asBytes(kid))
        return refuseKey(Failure::CoseKeyMalformed);

    PublicKey key;
    switch (*alg) {
        case static_cast<std::int64_t>(Algorithm::EdDSA): {
            key.algorithm = Algorithm::EdDSA;
            if (*kty != kKtyOkp || cbor::asInt(cbor::find(map, kLabelCrvOrN)) != kCrvEd25519)
                return refuseKey(Failure::KeyParametersMismatch);
            if (!coseOnlyLabels(map, {kLabelKty, kLabelKid, kLabelAlg, kLabelCrvOrN, kLabelXOrE}))
                return refuseKey(Failure::CoseKeyMalformed);
            auto x = coseBytesAt(map, kLabelXOrE);
            if (!x || x->size() != crypto_sign_PUBLICKEYBYTES) return refuseKey(Failure::InvalidPublicKey);
            // Canonical encoding, on the curve, in the prime-order subgroup, not of small order.
            if (!coseSodiumReady() || crypto_core_ed25519_is_valid_point(x->data()) != 1)
                return refuseKey(Failure::InvalidPublicKey);
            key.x = std::move(*x);
            return {std::move(key), Failure::None};
        }
        case static_cast<std::int64_t>(Algorithm::ES256): {
            key.algorithm = Algorithm::ES256;
            if (*kty != kKtyEc2 || cbor::asInt(cbor::find(map, kLabelCrvOrN)) != kCrvP256)
                return refuseKey(Failure::KeyParametersMismatch);
            if (!coseOnlyLabels(map, {kLabelKty, kLabelKid, kLabelAlg, kLabelCrvOrN, kLabelXOrE, kLabelY}))
                return refuseKey(Failure::CoseKeyMalformed);
            auto x = coseBytesAt(map, kLabelXOrE);
            auto y = coseBytesAt(map, kLabelY);
            if (!x || !y || x->size() != 32 || y->size() != 32) return refuseKey(Failure::InvalidPublicKey);
            if (!openssl::p256(*x, *y)) return refuseKey(Failure::InvalidPublicKey);  // on the curve, not infinity
            key.x = std::move(*x);
            key.y = std::move(*y);
            return {std::move(key), Failure::None};
        }
        case static_cast<std::int64_t>(Algorithm::RS256): {
            key.algorithm = Algorithm::RS256;
            if (*kty != kKtyRsa) return refuseKey(Failure::KeyParametersMismatch);
            if (!coseOnlyLabels(map, {kLabelKty, kLabelKid, kLabelAlg, kLabelCrvOrN, kLabelXOrE}))
                return refuseKey(Failure::CoseKeyMalformed);
            auto n = coseBytesAt(map, kLabelCrvOrN);
            auto e = coseBytesAt(map, kLabelXOrE);
            if (!n || !e) return refuseKey(Failure::CoseKeyMalformed);
            const int bits = coseBitLength(*n);
            if (bits == 0) return refuseKey(Failure::InvalidPublicKey);
            if (bits < kMinRsaBits || bits > kMaxRsaBits) return refuseKey(Failure::RsaKeySize);
            // e: minimal big-endian, odd, 3 <= e < 2^32.
            if (e->empty() || e->size() > 4 || e->front() == 0 || (e->back() & 1) == 0
                || (e->size() == 1 && e->front() < 3))
                return refuseKey(Failure::InvalidPublicKey);
            const auto pk = openssl::rsa(*n, *e);
            if (!pk || openssl::rsaBits(pk) != bits) return refuseKey(Failure::InvalidPublicKey);
            key.n = std::move(*n);
            key.e = std::move(*e);
            return {std::move(key), Failure::None};
        }
        default:
            return refuseKey(Failure::UnsupportedAlgorithm);
    }
}

bool verify(const PublicKey& key, const ByteView message, const ByteView signature) {
    switch (key.algorithm) {
        case Algorithm::EdDSA:
            return coseSodiumReady() && signature.size() == crypto_sign_BYTES && key.x.size() == crypto_sign_PUBLICKEYBYTES
                && crypto_sign_verify_detached(signature.data(), message.data(), message.size(), key.x.data()) == 0;
        case Algorithm::ES256: {
            if (signature.size() < 8 || signature.size() > 72) return false;  // DER ECDSA-Sig-Value for P-256
            const auto pk = openssl::p256(key.x, key.y);
            return pk && openssl::verify(pk.get(), message, signature);
        }
        case Algorithm::RS256: {
            if (signature.size() != key.n.size()) return false;
            const auto pk = openssl::rsa(key.n, key.e);
            return pk && openssl::verify(pk.get(), message, signature);
        }
    }
    return false;
}

}
