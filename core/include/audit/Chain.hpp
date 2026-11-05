#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// The audit trail's hash chain (#323, migration 117). Pure functions: no database, no keys.
//
//   hash = SHA-256( "vh-audit-v1"
//                   ‖ UInt64BE(seq) ‖ prev_hash[32] ‖ UInt64BE(occurred_us)
//                   ‖ Str(level) ‖ Str(action) ‖ Str(outcome)
//                   ‖ OptU32(actor_id) ‖ Str(actor) ‖ Str(origin)
//                   ‖ OptU32(vault_id) ‖ OptU64(entry_id)
//                   ‖ Str(message) ‖ Str(details) )
//
//   Str(s)    = UInt32BE(byte length) ‖ UTF-8 bytes
//   OptU32(v) = 0x00 when absent, else 0x01 ‖ UInt32BE(v);  OptU64 likewise with UInt64BE
//
// The first retained row's prev_hash is 32 zero bytes (genesis) or the hash recorded by the last retention purge
// (audit_checkpoint). A signed head is Ed25519, by this node's key (vault/KeyAttestation.hpp, key_attestation_keys),
// over
//
//   "vh-audit-head-v1" ‖ Str(node_id) ‖ UInt64BE(seq) ‖ hash[32] ‖ UInt64BE(signed_us)
//
// Test vector pinned by AuditChain.MatchesTheDocumentedVector (test_audit_trail.cpp) and docs/admin/audit-trail.md.
namespace vh::audit {

inline constexpr std::string_view kChainDomain = "vh-audit-v1";
inline constexpr std::string_view kHeadDomain = "vh-audit-head-v1";
inline constexpr std::size_t kHashSize = 32;

using Hash = std::array<uint8_t, kHashSize>;

struct Record {
    uint64_t seq{};
    uint64_t occurred_us{};
    std::string level{};
    std::string action{};
    std::string outcome{};
    std::optional<uint32_t> actor_id{};
    std::string actor{};
    std::string origin{};
    std::optional<uint32_t> vault_id{};
    std::optional<uint64_t> entry_id{};
    std::string message{};
    std::string details{"{}"};  // a JSON object, hashed and stored byte for byte
    Hash prev_hash{};
    Hash hash{};
};

struct SignedHead {
    uint64_t seq{};
    Hash hash{};
    uint64_t signed_us{};
    std::string node_id{};
    unsigned int key_id{};
    std::vector<uint8_t> signature{};
};

struct Checkpoint {
    uint64_t seq{};
    Hash hash{};
    uint64_t purged{};
};

[[nodiscard]] Hash computeHash(const Record& record);
[[nodiscard]] std::vector<uint8_t> headMessage(std::string_view nodeId, uint64_t seq, const Hash& hash,
                                               uint64_t signedUs);

[[nodiscard]] std::string toHex(std::span<const uint8_t> bytes);
// nullopt unless `hex` is exactly 64 hex digits.
[[nodiscard]] std::optional<Hash> hashFromHex(std::string_view hex);

// Chain verification over records in ascending seq order, starting after `anchor` (the checkpoint, or genesis).
struct ChainCheck {
    uint64_t checked{};
    uint64_t last_seq{};
    Hash last_hash{};
    std::optional<uint64_t> broken_at{};  // the first seq that fails
    std::string problem{};                // why, when broken
};

class ChainVerifier {
public:
    explicit ChainVerifier(std::optional<Checkpoint> anchor);
    // Feeds the next record; returns false once the chain is broken (later calls do nothing).
    bool feed(const Record& record);
    [[nodiscard]] const ChainCheck& result() const noexcept { return check_; }

private:
    ChainCheck check_;
};

}
