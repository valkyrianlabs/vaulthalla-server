#pragma once

#include "audit/Chain.hpp"
#include "db/query/audit/Trail.hpp"
#include "ops/Actor.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Reading the audit trail (#323): the viewer, chain verification and export, shared by ws audit.* and `vh audit`.
// Every call needs admin.audits.view, and is itself recorded (audit.view / audit.verify / audit.export).
namespace vh::ops::audit {

using Filter = db::query::audit::Filter;

struct Page {
    std::vector<vh::audit::Record> events;
    std::optional<uint64_t> next_before;  // pass as before_seq for the next (older) page
};

struct Verification {
    bool ok{false};
    uint64_t events_checked{};
    std::optional<uint64_t> first_seq{};
    std::optional<uint64_t> last_seq{};
    std::optional<uint64_t> anchor_seq{};  // the retention checkpoint the chain starts after
    std::optional<uint64_t> broken_at{};
    std::string problem{};
    uint64_t heads_valid{};
    uint64_t heads_invalid{};
    std::optional<uint64_t> last_signed_seq{};
    uint64_t unsigned_events{};  // events after the newest valid signed head
    std::vector<std::string> head_problems{};
};

[[nodiscard]] bool canView(const Actor& actor);

// Newest first; limit 1..1000.
[[nodiscard]] Page list(const Actor& actor, const Filter& filter, std::size_t limit);
[[nodiscard]] Verification verify(const Actor& actor);
// Writes NDJSON lines: one {"type":"export",...} header, then every event in [since, until) in seq order, then the
// signed heads that cover them. Each event carries prev_hash and hash, so the export verifies on its own
// (tools/audit/verify_export.py). Returns the number of events written.
uint64_t exportNdjson(const Actor& actor, std::optional<uint64_t> sinceUs, std::optional<uint64_t> untilUs,
                      const std::function<void(std::string_view line)>& write);

[[nodiscard]] nlohmann::json toJson(const vh::audit::Record& record);
[[nodiscard]] nlohmann::json toJson(const vh::audit::SignedHead& head);
[[nodiscard]] nlohmann::json toJson(const Verification& verification);

}
