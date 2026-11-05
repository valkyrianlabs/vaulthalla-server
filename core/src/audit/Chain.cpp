#include "audit/Chain.hpp"

#include <sodium.h>

#include <stdexcept>

namespace vh::audit {

namespace {

void putU32(std::vector<uint8_t>& out, const uint32_t v) {
    for (int shift = 24; shift >= 0; shift -= 8) out.push_back(static_cast<uint8_t>(v >> shift));
}

void putU64(std::vector<uint8_t>& out, const uint64_t v) {
    for (int shift = 56; shift >= 0; shift -= 8) out.push_back(static_cast<uint8_t>(v >> shift));
}

void putStr(std::vector<uint8_t>& out, const std::string_view s) {
    if (s.size() > UINT32_MAX) throw std::length_error("audit field too long");
    putU32(out, static_cast<uint32_t>(s.size()));
    out.insert(out.end(), s.begin(), s.end());
}

void putOpt32(std::vector<uint8_t>& out, const std::optional<uint32_t> v) {
    out.push_back(v ? 1 : 0);
    if (v) putU32(out, *v);
}

void putOpt64(std::vector<uint8_t>& out, const std::optional<uint64_t> v) {
    out.push_back(v ? 1 : 0);
    if (v) putU64(out, *v);
}

int hexValue(const char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

}

Hash computeHash(const Record& r) {
    std::vector<uint8_t> msg(kChainDomain.begin(), kChainDomain.end());
    msg.reserve(msg.size() + 128 + r.message.size() + r.details.size());
    putU64(msg, r.seq);
    msg.insert(msg.end(), r.prev_hash.begin(), r.prev_hash.end());
    putU64(msg, r.occurred_us);
    putStr(msg, r.level);
    putStr(msg, r.action);
    putStr(msg, r.outcome);
    putOpt32(msg, r.actor_id);
    putStr(msg, r.actor);
    putStr(msg, r.origin);
    putOpt32(msg, r.vault_id);
    putOpt64(msg, r.entry_id);
    putStr(msg, r.message);
    putStr(msg, r.details);

    if (sodium_init() < 0) throw std::runtime_error("libsodium failed to initialize");
    Hash out{};
    crypto_hash_sha256(out.data(), msg.data(), msg.size());
    return out;
}

std::vector<uint8_t> headMessage(const std::string_view nodeId, const uint64_t seq, const Hash& hash,
                                 const uint64_t signedUs) {
    if (nodeId.empty()) throw std::invalid_argument("a signed audit head needs this node's id");
    std::vector<uint8_t> msg(kHeadDomain.begin(), kHeadDomain.end());
    putStr(msg, nodeId);
    putU64(msg, seq);
    msg.insert(msg.end(), hash.begin(), hash.end());
    putU64(msg, signedUs);
    return msg;
}

std::string toHex(const std::span<const uint8_t> bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const auto b : bytes) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0x0f]);
    }
    return out;
}

std::optional<Hash> hashFromHex(const std::string_view hex) {
    if (hex.size() != kHashSize * 2) return std::nullopt;
    Hash out{};
    for (std::size_t i = 0; i < kHashSize; ++i) {
        const int hi = hexValue(hex[2 * i]);
        const int lo = hexValue(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return out;
}

ChainVerifier::ChainVerifier(const std::optional<Checkpoint> anchor) {
    if (anchor) {
        check_.last_seq = anchor->seq;
        check_.last_hash = anchor->hash;
    }
}

bool ChainVerifier::feed(const Record& r) {
    if (check_.broken_at) return false;
    const auto fail = [&](std::string why) {
        check_.broken_at = r.seq;
        check_.problem = std::move(why);
        return false;
    };
    if (r.seq != check_.last_seq + 1)
        return fail("expected event " + std::to_string(check_.last_seq + 1) + ", found " + std::to_string(r.seq) +
                    (r.seq > check_.last_seq + 1 ? " (events are missing)" : " (events are out of order)"));
    if (r.prev_hash != check_.last_hash) return fail("its previous-hash does not match the event before it");
    if (computeHash(r) != r.hash) return fail("its contents do not match its hash (the event was altered)");
    ++check_.checked;
    check_.last_seq = r.seq;
    check_.last_hash = r.hash;
    return true;
}

}
