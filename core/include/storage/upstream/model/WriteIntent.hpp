#pragma once

#include "db/Fwd.hpp"

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>

// Vaulthalla's own pending PUT/DELETE of an object (upstream_write_intent), so the notification it causes is
// recognised as ours (origin self) instead of being synced back.
namespace vh::storage::upstream::model {

enum class WriteOp { Put, Delete };

[[nodiscard]] std::string to_string(WriteOp op);
[[nodiscard]] WriteOp writeOpFromString(const std::string& s);   // throws std::invalid_argument

struct WriteIntent {
    int64_t id{};
    uint32_t vault_id{};
    std::string object_key;
    WriteOp op{WriteOp::Put};
    std::optional<uint64_t> expected_size;
    std::time_t recorded_at{};
    std::time_t expires_at{};

    WriteIntent() = default;
    explicit WriteIntent(pqxx::row_ref row);
};

}
