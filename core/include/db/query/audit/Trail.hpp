#pragma once

#include "audit/Chain.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// The audit trail's tables (migration 117): audit_event (append-only hash chain), audit_head (signed heads),
// audit_checkpoint (where the retained chain starts after a purge). Only audit::Trail appends; ops::audit reads.
namespace vh::db::query::audit {

struct Tail {
    uint64_t seq{};
    vh::audit::Hash hash{};
};

struct Filter {
    std::optional<uint64_t> before_seq{};  // paging: events with seq < before_seq (newest first)
    std::optional<uint64_t> since_us{};
    std::optional<uint64_t> until_us{};
    std::optional<std::string> action_prefix{};  // "auth." matches auth.login.success, ...
    std::optional<uint32_t> actor_id{};
    std::optional<uint32_t> vault_id{};
    std::optional<std::string> outcome{};
};

class Trail {
public:
    // The newest event, else the newest checkpoint, else nullopt (an empty chain starts from genesis).
    [[nodiscard]] static std::optional<Tail> tail();
    // Appends records whose seq/prev_hash/hash are already computed, in one transaction.
    static void append(const std::vector<vh::audit::Record>& records);
    static void appendHead(const vh::audit::SignedHead& head);

    [[nodiscard]] static std::optional<vh::audit::SignedHead> lastHead();
    [[nodiscard]] static std::vector<vh::audit::SignedHead> heads();  // ascending
    [[nodiscard]] static std::optional<vh::audit::Checkpoint> checkpoint();

    // Ascending, seq > afterSeq (verification and export).
    [[nodiscard]] static std::vector<vh::audit::Record> range(uint64_t afterSeq, std::size_t limit);
    // Newest first (the viewer).
    [[nodiscard]] static std::vector<vh::audit::Record> list(const Filter& filter, std::size_t limit);
    [[nodiscard]] static uint64_t count();

    // Retention: vh_audit_purge_before(cutoff); returns the number of events removed.
    static uint64_t purgeBefore(uint64_t cutoffUs);
};

}
