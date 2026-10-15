#pragma once

#include "storage/upstream/model/WriteIntent.hpp"

#include <chrono>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>

// upstream_write_intent: Vaulthalla's own pending PUT/DELETEs, matched against the notifications they cause.
namespace vh::db::query::upstream {

class WriteIntent {
public:
    // Recorded before the request is sent; expires after ttl.
    static int64_t record(uint32_t vaultId, const std::string& key, storage::upstream::model::WriteOp op,
                          std::optional<uint64_t> expectedSize, std::chrono::seconds ttl = std::chrono::hours(1));
    // Consumes (deletes) exactly one unexpired intent for the key + op recorded no later than eventTime + 5 s
    // (clock slack). For puts, sizes must agree when both are known. True when one matched: the event is ours.
    [[nodiscard]] static bool consumeMatching(uint32_t vaultId, const std::string& key, storage::upstream::model::WriteOp op,
                                              std::optional<uint64_t> size, std::time_t eventTime);
    // Deletes expired intents; returns how many.
    static uint64_t sweepExpired();
};

}
