#include "peer/Crypto.hpp"

#include "peer/Peer.hpp"

#include <openssl/evp.h>

#include <memory>
#include <stdexcept>

namespace vh::peer::crypto {

namespace {

struct DigestCtxFree { void operator()(EVP_MD_CTX* p) const noexcept { EVP_MD_CTX_free(p); } };

void put(std::vector<uint8_t>& out, const std::string_view s) { out.insert(out.end(), s.begin(), s.end()); }
void put(std::vector<uint8_t>& out, const std::span<const uint8_t> b) { out.insert(out.end(), b.begin(), b.end()); }

void putU32(std::vector<uint8_t>& out, const uint32_t v) {
    for (int shift = 24; shift >= 0; shift -= 8) out.push_back(static_cast<uint8_t>(v >> shift));
}

void putU64(std::vector<uint8_t>& out, const uint64_t v) {
    for (int shift = 56; shift >= 0; shift -= 8) out.push_back(static_cast<uint8_t>(v >> shift));
}

// Length-prefixed: UInt32BE(byte length) ‖ the bytes.
void putLp(std::vector<uint8_t>& out, const std::string_view s) {
    if (s.size() > 0xffffffffULL) throw std::invalid_argument("a peer card field is too long");
    putU32(out, static_cast<uint32_t>(s.size()));
    put(out, s);
}

}

std::vector<uint8_t> cardBytes(const Card& card) {
    std::vector<uint8_t> out;
    out.reserve(kCardDomain.size() + 64 + card.node_id.size() + card.name.size() + card.product_version.size() +
                kKeyBytes * (card.attest_public_keys.size() + 1));
    put(out, kCardDomain);
    putLp(out, card.node_id);
    putLp(out, card.name);
    putU32(out, static_cast<uint32_t>(card.attest_public_keys.size()));
    for (const auto& k : card.attest_public_keys) put(out, std::span<const uint8_t>(k));
    put(out, std::span<const uint8_t>(card.wrap_public_key));
    putU32(out, card.peer_protocol);
    putLp(out, card.product_version);
    return out;
}

Hash cardHash(const Card& card) { return vh::device::crypto::sha256(cardBytes(card)); }

Hash commitment(const Hash& spkiA, const Hash& nonceA) {
    std::vector<uint8_t> msg;
    msg.reserve(kCommitDomain.size() + 64);
    put(msg, kCommitDomain);
    put(msg, spkiA);
    put(msg, nonceA);
    return vh::device::crypto::sha256(msg);
}

Hash sasDigest(const Hash& spkiB, const Hash& spkiA, const Hash& nonceA, const Hash& nonceB, const Hash& cardHashA,
               const Hash& cardHashB) {
    std::vector<uint8_t> msg;
    msg.reserve(kSasDomain.size() + 6 * 32);
    put(msg, kSasDomain);
    put(msg, spkiB);
    put(msg, spkiA);
    put(msg, nonceA);
    put(msg, nonceB);
    put(msg, cardHashA);
    put(msg, cardHashB);
    return vh::device::crypto::sha256(msg);
}

std::string sasCode(const Hash& digest) { return vh::device::crypto::sasCode(digest); }

std::vector<uint8_t> rotationMessage(const Hash& nextSpki, const Hash& peerSpki, const std::string_view nodeId,
                                     const uint64_t counter) {
    std::vector<uint8_t> msg;
    msg.reserve(kRotateDomain.size() + 76 + nodeId.size());
    put(msg, kRotateDomain);
    put(msg, nextSpki);
    put(msg, peerSpki);
    putLp(msg, nodeId);
    putU64(msg, counter);
    return msg;
}

std::vector<uint8_t> signP256(EVP_PKEY* key, const std::span<const uint8_t> message) {
    if (!key) throw std::invalid_argument("no signing key");
    const std::unique_ptr<EVP_MD_CTX, DigestCtxFree> ctx(EVP_MD_CTX_new());
    std::size_t len = 0;
    if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key) != 1 ||
        EVP_DigestSign(ctx.get(), nullptr, &len, message.data(), message.size()) != 1)
        throw std::runtime_error("cannot sign with the identity key");
    std::vector<uint8_t> sig(len);
    if (EVP_DigestSign(ctx.get(), sig.data(), &len, message.data(), message.size()) != 1)
        throw std::runtime_error("cannot sign with the identity key");
    sig.resize(len);
    return sig;
}

}
